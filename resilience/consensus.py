"""Signed PBFT phases and view-change simulation for the four-agent committee.

This is a deterministic protocol model: message signatures and quorum checks are
real, while transport between replicas is simulated in one process. Kubernetes
deployment work will replace this message bus with mTLS network transport.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json

from .crypto_keys import NodeKeyring


@dataclass(frozen=True)
class PBFTMessage:
    sender: str
    phase: str
    view: int
    sequence: int
    digest: str
    signature: str
    prepared_digest: str = ""

    def payload(self) -> bytes:
        return json.dumps({"sender": self.sender, "phase": self.phase,
                           "view": self.view, "sequence": self.sequence,
                           "digest": self.digest,
                           "prepared_digest": self.prepared_digest}, sort_keys=True,
                          separators=(",", ":")).encode()


@dataclass
class PBFTResult:
    committed: bool
    value: str
    view: int | None
    sequence: int
    quorum: int
    phases: list[dict] = field(default_factory=list)
    events: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


class PBFTConsensus:
    """PBFT pre-prepare/prepare/commit with primary rotation on view change."""

    def __init__(self, node_ids: list[str], keyring: NodeKeyring, max_faults: int):
        if len(node_ids) < 3 * max_faults + 1:
            raise ValueError("PBFT committee must have at least 3f+1 replicas")
        if max_faults < 0:
            raise ValueError("max_faults cannot be negative")
        self.node_ids = list(node_ids)
        self.keyring = keyring
        self.f = max_faults
        self.quorum = 2 * max_faults + 1
        self.sequence = 1

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def _message(self, sender: str, phase: str, view: int, digest: str) -> PBFTMessage:
        unsigned = PBFTMessage(sender, phase, view, self.sequence, digest, "")
        signature = self.keyring.sign(sender, unsigned.payload()).hex()
        return PBFTMessage(sender, phase, view, self.sequence, digest, signature)

    def verify_message(self, message: PBFTMessage) -> bool:
        try:
            signature = bytes.fromhex(message.signature)
        except ValueError:
            return False
        return (message.sender in self.node_ids
                and message.phase in {"PRE-PREPARE", "PREPARE", "COMMIT", "VIEW-CHANGE", "NEW-VIEW"}
                and message.view >= 0
                and len(message.digest) == 64
                and message.sequence == self.sequence
                and self.keyring.verify(message.sender, message.payload(), signature))

    def decide(self, value: str, *, byzantine: set[str] | None = None,
               silent: set[str] | None = None,
               block_primary: bool = False,
               primary_value: str | None = None) -> PBFTResult:
        result = self._decide(value, byzantine=byzantine, silent=silent,
                              block_primary=block_primary, primary_value=primary_value)
        self.sequence += 1
        return result

    def _decide(self, value: str, *, byzantine: set[str] | None = None,
               silent: set[str] | None = None,
               block_primary: bool = False,
               primary_value: str | None = None) -> PBFTResult:
        byzantine = set(byzantine or ())
        silent = set(silent or ())
        if (byzantine | silent) - set(self.node_ids):
            raise ValueError("faulty or silent node is not in the committee")
        digest = self.digest(value)
        honest_active = [n for n in self.node_ids if n not in byzantine | silent]
        phase_log: list[dict] = []
        events: list[str] = []

        # A primary that refuses or proposes an unauthorized value triggers a
        # signed 2f+1 view-change certificate before a new primary can lead.
        view = 0
        primary = self.node_ids[view % len(self.node_ids)]
        proposed = primary_value or value
        primary_faulty = primary in byzantine or primary in silent or block_primary
        invalid_proposal = proposed != value
        if primary_faulty or invalid_proposal:
            if invalid_proposal:
                events.append(f"view {view}: primary proposed an unauthorized digest; honest replicas rejected it")
            else:
                events.append(f"view {view}: primary {primary} failed to lead; replicas started view change")
            changes = []
            for node_id in honest_active:
                message = self._message(node_id, "VIEW-CHANGE", view + 1, digest)
                if self.verify_message(message):
                    changes.append(message.sender)
            phase_log.append({"phase": "VIEW-CHANGE", "from_view": view,
                              "to_view": view + 1, "valid_messages": changes,
                              "required": self.quorum})
            if len(set(changes)) < self.quorum:
                events.append("view-change quorum not reached; no value committed")
                return PBFTResult(False, "NOOP", None, self.sequence, self.quorum,
                                  phase_log, events)
            view += 1
            primary = self.node_ids[view % len(self.node_ids)]
            events.append(f"view change succeeded; new primary is {primary}")

        if len(honest_active) < self.quorum:
            events.append("fewer than 2f+1 honest active replicas; PBFT cannot commit")
            return PBFTResult(False, "NOOP", None, self.sequence, self.quorum,
                              phase_log, events)

        # PRE-PREPARE: new/current primary signs the exact value selected by
        # the evidence policy. Followers verify its signature and digest.
        pre_prepare = self._message(primary, "PRE-PREPARE", view, digest)
        if not self.verify_message(pre_prepare):
            events.append("pre-prepare signature invalid; request rejected")
            return PBFTResult(False, "NOOP", None, self.sequence, self.quorum,
                              phase_log, events)
        phase_log.append({"phase": "PRE-PREPARE", "view": view,
                          "primary": primary, "digest": digest,
                          "valid": True})

        # PREPARE: each correct active replica signs the same digest. A
        # Byzantine replica may withhold or equivocate; correct replicas only
        # count messages matching the signed pre-prepare.
        prepares = [self._message(node_id, "PREPARE", view, digest)
                    for node_id in honest_active]
        valid_prepares = [m for m in prepares if self.verify_message(m)
                          and m.digest == digest and m.view == view]
        phase_log.append({"phase": "PREPARE", "view": view,
                          "valid_messages": [m.sender for m in valid_prepares],
                          "required": self.quorum})
        if len({m.sender for m in valid_prepares}) < self.quorum:
            events.append("prepared certificate lacks a 2f+1 matching prepare quorum")
            return PBFTResult(False, "NOOP", None, self.sequence, self.quorum,
                              phase_log, events)

        # COMMIT: only after a prepared certificate do replicas emit commits.
        commits = [self._message(node_id, "COMMIT", view, digest)
                   for node_id in honest_active]
        valid_commits = [m for m in commits if self.verify_message(m)
                         and m.digest == digest and m.view == view]
        phase_log.append({"phase": "COMMIT", "view": view,
                          "valid_messages": [m.sender for m in valid_commits],
                          "required": self.quorum})
        committed = len({m.sender for m in valid_commits}) >= self.quorum
        events.append("2f+1 signed commits agree" if committed else "commit quorum not reached")
        return PBFTResult(committed, value if committed else "NOOP", view,
                          self.sequence, self.quorum, phase_log, events)
