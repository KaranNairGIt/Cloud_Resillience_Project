"""Per-process PBFT replica state machine used by the mTLS peer endpoint."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from threading import RLock
from functools import wraps

from .consensus import PBFTMessage
from .crypto_keys import NodeKeyring
from .engine import (EVIDENCE_TYPE_WEIGHTS, EVIDENCE_TYPES, MAX_BYZANTINE_FAULTS,
                     MIN_CORROBORATING_REPORTERS, MIN_DISTINCT_EVIDENCE_TYPES,
                     MIN_EVIDENCE_SCORE, SERVICES, Evidence)


class ProtocolError(ValueError):
    """A peer sent a signed but invalid or unauthorized protocol operation."""


def _replica_locked(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self.lock:
            if self.faulted:
                raise ProtocolError("replica stopped after a durable-state failure")
            return method(self, *args, **kwargs)
    return wrapped


@dataclass
class ReplicaRound:
    sequence: int
    view: int = 0
    proposal: dict | None = None
    digest: str | None = None
    prepares: dict[str, PBFTMessage] = field(default_factory=dict)
    commits: dict[str, PBFTMessage] = field(default_factory=dict)
    view_changes: dict[int, dict[str, PBFTMessage]] = field(default_factory=dict)
    view_change_proofs: dict[int, dict[str, list[PBFTMessage]]] = field(default_factory=dict)
    new_view_message: PBFTMessage | None = None
    new_view_certificate: list[dict] = field(default_factory=list)
    prepare_sent: bool = False
    commit_sent: bool = False
    committed: bool = False
    audit: list[dict] = field(default_factory=list)


class ReplicaStateStore:
    """Atomic snapshots backed by a node-signed, hash-chained transition journal."""

    GENESIS = "0" * 64

    def __init__(self, path: Path, node_id: str, keyring: NodeKeyring):
        self.path = Path(path)
        self.node_id = node_id
        self.keyring = keyring
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("CREATE TABLE IF NOT EXISTS rounds (sequence INTEGER PRIMARY KEY, state_json TEXT NOT NULL, journal_id INTEGER, entry_hash TEXT)")
            columns = {row[1] for row in db.execute("PRAGMA table_info(rounds)")}
            if "journal_id" not in columns:
                db.execute("ALTER TABLE rounds ADD COLUMN journal_id INTEGER")
            if "entry_hash" not in columns:
                db.execute("ALTER TABLE rounds ADD COLUMN entry_hash TEXT")
            db.execute("CREATE TABLE IF NOT EXISTS journal (id INTEGER PRIMARY KEY AUTOINCREMENT, sequence INTEGER NOT NULL, body TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL, signature TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS journal_head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), head_id INTEGER NOT NULL, head_hash TEXT NOT NULL)")
            db.execute("INSERT OR IGNORE INTO journal_head(singleton,head_id,head_hash) VALUES(1,0,?)", (self.GENESIS,))
            db.commit()
        finally:
            db.close()

    def load(self) -> list[tuple[int, str]]:
        db = sqlite3.connect(self.path)
        try:
            self._verify_journal(db)
            return list(db.execute("SELECT sequence, state_json FROM rounds ORDER BY sequence"))
        finally:
            db.close()

    @staticmethod
    def _entry_payload(entry_id: int, sequence: int, body: str, prev_hash: str) -> bytes:
        body_hash = hashlib.sha256(body.encode()).hexdigest()
        return json.dumps({"entry_id": entry_id, "sequence": sequence,
                           "body_hash": body_hash, "prev_hash": prev_hash},
                          sort_keys=True, separators=(",", ":")).encode()

    def _verify_journal(self, db: sqlite3.Connection) -> None:
        head_id, head_hash = db.execute(
            "SELECT head_id,head_hash FROM journal_head WHERE singleton=1").fetchone()
        previous = self.GENESIS
        expected_id = 1
        latest: dict[int, tuple[int, str]] = {}
        rows = db.execute("SELECT id,sequence,body,prev_hash,entry_hash,signature FROM journal ORDER BY id")
        for entry_id, sequence, body, prev_hash, entry_hash, signature in rows:
            if entry_id != expected_id or prev_hash != previous:
                raise ValueError("replica journal has a missing or reordered entry")
            calculated = hashlib.sha256(self._entry_payload(
                entry_id, sequence, body, prev_hash)).hexdigest()
            try:
                signature_bytes = bytes.fromhex(signature)
            except ValueError as exc:
                raise ValueError("replica journal signature is malformed") from exc
            if (calculated != entry_hash
                    or not self.keyring.verify(self.node_id,
                        bytes.fromhex(entry_hash), signature_bytes)):
                raise ValueError("replica journal signature or hash is invalid")
            previous = entry_hash
            expected_id += 1
            latest[sequence] = (entry_id, entry_hash)
        if head_id != expected_id - 1 or head_hash != previous:
            raise ValueError("replica journal head does not match its signed history")
        stored = {sequence: (journal_id, entry_hash) for sequence, journal_id, entry_hash
                  in db.execute("SELECT sequence,journal_id,entry_hash FROM rounds")}
        if stored != latest:
            raise ValueError("replica snapshots do not match the journal's latest entries")
        for sequence, encoded, journal_id, entry_hash in db.execute(
                "SELECT sequence,state_json,journal_id,entry_hash FROM rounds"):
            journal_body = db.execute("SELECT body FROM journal WHERE id=?", (journal_id,)).fetchone()
            if (journal_body is None or journal_body[0] != encoded
                    or entry_hash != latest[sequence][1]):
                raise ValueError("replica snapshot differs from its signed journal entry")

    def save(self, sequence: int, snapshot: dict) -> None:
        body = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        db = sqlite3.connect(self.path, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            head_id, previous = db.execute(
                "SELECT head_id,head_hash FROM journal_head WHERE singleton=1").fetchone()
            entry_id = head_id + 1
            digest = hashlib.sha256(self._entry_payload(
                entry_id, sequence, body, previous)).hexdigest()
            signature = self.keyring.sign(self.node_id, bytes.fromhex(digest)).hex()
            db.execute("INSERT INTO journal(id,sequence,body,prev_hash,entry_hash,signature) VALUES(?,?,?,?,?,?)",
                       (entry_id, sequence, body, previous, digest, signature))
            db.execute("UPDATE journal_head SET head_id=?,head_hash=? WHERE singleton=1",
                       (entry_id, digest))
            db.execute("INSERT INTO rounds(sequence,state_json,journal_id,entry_hash) VALUES(?,?,?,?) "
                       "ON CONFLICT(sequence) DO UPDATE SET state_json=excluded.state_json, "
                       "journal_id=excluded.journal_id,entry_hash=excluded.entry_hash",
                       (sequence, body, entry_id, digest))
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()


class PBFTReplica:
    """One node's independently signed PBFT state; private key is node-local."""

    def __init__(self, node_id: str, keyring: NodeKeyring,
                 node_ids: list[str] | None = None, max_faults: int = MAX_BYZANTINE_FAULTS,
                 state_db: Path | None = None):
        self.node_ids = list(node_ids or SERVICES)
        if node_id not in self.node_ids:
            raise ValueError(f"unknown replica: {node_id}")
        if self.node_ids != list(keyring.public):
            # Preserve canonical committee ordering, which defines the primary rotation.
            if set(self.node_ids) != set(keyring.public):
                raise ValueError("public signing keys must cover the whole committee")
        if len(self.node_ids) < 3 * max_faults + 1:
            raise ValueError("PBFT committee must have at least 3f+1 replicas")
        if node_id not in keyring.private:
            raise ValueError("this replica must hold its own private signing key")
        self.node_id = node_id
        self.keyring = keyring
        self.f = max_faults
        self.quorum = 2 * max_faults + 1
        self.lock = RLock()
        self.rounds: dict[int, ReplicaRound] = {}
        self.highest_committed_sequence = 0
        self.trust_scores = {member: 80.0 for member in self.node_ids}
        self.trust_audit: list[dict] = []
        self.store = ReplicaStateStore(state_db, node_id, keyring) if state_db else None
        self.faulted = False
        if self.store:
            self._restore()

    @staticmethod
    def _message_dict(message: PBFTMessage) -> dict:
        return asdict(message)

    def _snapshot(self, state: ReplicaRound) -> dict:
        return {
            "view": state.view, "proposal": state.proposal, "digest": state.digest,
            "prepares": {sender: self._message_dict(message)
                         for sender, message in state.prepares.items()},
            "commits": {sender: self._message_dict(message)
                        for sender, message in state.commits.items()},
            "view_changes": {str(view): {sender: self._message_dict(message)
                                          for sender, message in messages.items()}
                             for view, messages in state.view_changes.items()},
            "view_change_proofs": {str(view): {sender: [self._message_dict(message)
                                                          for message in proof]
                                               for sender, proof in messages.items()}
                                   for view, messages in state.view_change_proofs.items()},
            "new_view_message": (self._message_dict(state.new_view_message)
                                 if state.new_view_message else None),
            "new_view_certificate": state.new_view_certificate,
            "prepare_sent": state.prepare_sent, "commit_sent": state.commit_sent,
            "committed": state.committed, "audit": state.audit,
        }

    def _persist(self, state: ReplicaRound) -> None:
        if self.store:
            try:
                self.store.save(state.sequence, self._snapshot(state))
            except Exception:
                # Never acknowledge or sign further protocol traffic if durable
                # state cannot be committed before the response leaves this peer.
                self.faulted = True
                raise

    def _restore(self) -> None:
        assert self.store is not None
        for sequence, encoded in self.store.load():
            state = self._decode_round(sequence, encoded)
            self.rounds[sequence] = state
            if state.committed:
                self.highest_committed_sequence = max(
                    self.highest_committed_sequence, sequence)
                self._update_trust_from_committed_round(state)

    def _decode_round(self, sequence: int, encoded: str) -> ReplicaRound:
        try:
            raw = json.loads(encoded)
            state = ReplicaRound(
                sequence=sequence, view=int(raw["view"]), proposal=raw["proposal"],
                digest=raw["digest"],
                prepares={sender: PBFTMessage(**value)
                          for sender, value in raw["prepares"].items()},
                commits={sender: PBFTMessage(**value)
                         for sender, value in raw["commits"].items()},
                view_changes={int(view): {sender: PBFTMessage(**value)
                                          for sender, value in messages.items()}
                              for view, messages in raw["view_changes"].items()},
                view_change_proofs={int(view): {sender: [PBFTMessage(**value)
                                                          for value in proof]
                                               for sender, proof in messages.items()}
                                    for view, messages in raw.get("view_change_proofs", {}).items()},
                new_view_message=(PBFTMessage(**raw["new_view_message"])
                                  if raw["new_view_message"] else None),
                new_view_certificate=list(raw["new_view_certificate"]),
                prepare_sent=bool(raw["prepare_sent"]),
                commit_sent=bool(raw["commit_sent"]),
                committed=bool(raw["committed"]), audit=list(raw["audit"]),
            )
            if (state.sequence < 1 or state.view < 0
                    or not isinstance(state.proposal, dict)):
                raise ValueError("invalid persisted replica round metadata")
            if self.proposal_digest(state.proposal) != state.digest:
                raise ValueError("persisted proposal digest mismatch")
            self._validate_stored_messages(state)
            if state.committed and (len(state.prepares) < self.quorum
                                    or len(state.commits) < self.quorum):
                raise ValueError("persisted committed state lacks a 2f+1 certificate")
            if len(state.commits) >= self.quorum and not state.committed:
                raise ValueError("persisted commit certificate was not marked committed")
            if state.prepare_sent != (self.node_id in state.prepares):
                raise ValueError("persisted local prepare state is inconsistent")
            if state.commit_sent != (self.node_id in state.commits):
                raise ValueError("persisted local commit state is inconsistent")
            if state.commit_sent and len(state.prepares) < self.quorum:
                raise ValueError("persisted local COMMIT lacks a prepare certificate")
            if not state.view and state.new_view_message is not None:
                raise ValueError("persisted NEW-VIEW message has no entered view")
            if state.view:
                if (len(state.view_changes.get(state.view, {})) < self.quorum
                        or state.new_view_message is None
                        or not self._valid_message(state.new_view_message)
                        or state.new_view_message.phase != "NEW-VIEW"
                        or state.new_view_message.view != state.view
                        or state.new_view_message.sequence != state.sequence
                        or state.new_view_message.sender != self.node_ids[state.view % len(self.node_ids)]
                        or state.new_view_message.digest != self._certificate_digest(
                            state.new_view_certificate)
                        or len(state.new_view_certificate) < self.quorum
                        or {item["message"]["sender"] for item in state.new_view_certificate}
                        != set(state.view_changes.get(state.view, {}))):
                    raise ValueError("persisted view lacks a valid 2f+1 NEW-VIEW certificate")
            return state
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"replica state failed validation at sequence {sequence}: {exc}") from exc

    @_replica_locked
    def latest_checkpoint(self) -> dict | None:
        committed = [state for state in self.rounds.values() if state.committed]
        if not committed:
            return None
        state = max(committed, key=lambda item: item.sequence)
        snapshot = self._snapshot(state)
        # Local action flags are peer-specific; the commit certificate is portable.
        snapshot["prepare_sent"] = self.node_id in state.prepares
        snapshot["commit_sent"] = self.node_id in state.commits
        return {"sequence": state.sequence, "snapshot": snapshot}

    @_replica_locked
    def committed_checkpoints_after(self, sequence: int) -> list[dict]:
        """Return portable, certificate-bearing committed rounds after a watermark."""
        if not isinstance(sequence, int) or sequence < 0:
            raise ProtocolError("checkpoint watermark must be a non-negative integer")
        checkpoints = []
        for state in sorted(self.rounds.values(), key=lambda item: item.sequence):
            if state.committed and state.sequence > sequence:
                snapshot = self._snapshot(state)
                snapshot["prepare_sent"] = self.node_id in state.prepares
                snapshot["commit_sent"] = self.node_id in state.commits
                checkpoints.append({"sequence": state.sequence, "snapshot": snapshot})
        return checkpoints

    @_replica_locked
    def install_checkpoint(self, checkpoint: dict) -> dict:
        if set(checkpoint) != {"sequence", "snapshot"} or not isinstance(checkpoint["snapshot"], dict):
            raise ProtocolError("checkpoint must contain sequence and snapshot")
        sequence = checkpoint["sequence"]
        if not isinstance(sequence, int) or sequence < 1:
            raise ProtocolError("checkpoint sequence must be a positive integer")
        snapshot = dict(checkpoint["snapshot"])
        prepares = snapshot.get("prepares")
        commits = snapshot.get("commits")
        if not isinstance(prepares, dict) or not isinstance(commits, dict):
            raise ProtocolError("checkpoint is missing prepare/commit certificates")
        snapshot["prepare_sent"] = self.node_id in prepares
        snapshot["commit_sent"] = self.node_id in commits
        try:
            encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
            state = self._decode_round(sequence, encoded)
        except ValueError as exc:
            raise ProtocolError(f"checkpoint validation failed: {exc}") from exc
        if not state.committed:
            raise ProtocolError("checkpoint lacks a committed decision")
        existing = self.rounds.get(sequence)
        if existing and existing.committed:
            if existing.digest != state.digest or existing.proposal != state.proposal:
                raise ProtocolError("checkpoint conflicts with this replica's committed decision")
            return {"installed": False, "sequence": sequence, "reason": "already committed"}
        if existing and existing.proposal is not None and existing.digest != state.digest:
            raise ProtocolError("checkpoint conflicts with this replica's active proposal")
        if sequence < self.highest_committed_sequence:
            raise ProtocolError("checkpoint is older than this replica's committed high-water mark")
        state.audit.append({"phase": "CHECKPOINT-INSTALLED", "sequence": sequence,
                            "digest": state.digest, "commit_signers": sorted(state.commits)})
        self.rounds[sequence] = state
        self._persist(state)
        self._update_trust_from_committed_round(state)
        self.highest_committed_sequence = max(self.highest_committed_sequence, sequence)
        return {"installed": True, "sequence": sequence, "digest": state.digest,
                "commit_signers": sorted(state.commits)}

    def _validate_stored_messages(self, state: ReplicaRound) -> None:
        if state.proposal is None or state.digest is None:
            if state.prepares or state.commits or state.view_changes:
                raise ValueError("stored protocol messages have no cached proposal")
            return
        if state.proposal.get("value") == "CONTAIN" and not self._evidence_authorizes_containment(state.proposal):
            raise ValueError("persisted containment proposal no longer passes evidence policy")
        for phase, collection in (("PREPARE", state.prepares), ("COMMIT", state.commits)):
            for sender, message in collection.items():
                if (sender != message.sender or message.phase != phase
                        or message.sequence != state.sequence or message.view != state.view
                        or message.digest != state.digest or not self._valid_message(message)):
                    raise ValueError(f"invalid persisted {phase} message")
        for view, messages in state.view_changes.items():
            for sender, message in messages.items():
                if (sender != message.sender or message.phase != "VIEW-CHANGE"
                        or message.sequence != state.sequence or message.view != view
                        or message.digest != state.digest or not self._valid_message(message)):
                    raise ValueError("invalid persisted VIEW-CHANGE message")
                proof = state.view_change_proofs.get(view, {}).get(sender, [])
                expected_proof = (self._prepared_certificate_digest(
                    [self._message_dict(item) for item in proof]) if proof else "")
                if message.prepared_digest != expected_proof:
                    raise ValueError("invalid persisted VIEW-CHANGE prepared proof binding")
                if proof and not self._valid_prepare_certificate(proof, state.sequence,
                                                                  state.digest, view):
                    raise ValueError("invalid persisted prepared certificate in VIEW-CHANGE")
        if state.new_view_certificate:
            if not self._valid_view_change_certificate(state.new_view_certificate,
                                                       state.sequence, state.view,
                                                       state.digest)[0]:
                raise ValueError("invalid persisted NEW-VIEW certificate")

    def _record(self, state: ReplicaRound, event: dict) -> None:
        state.audit.append(event)

    def _round(self, sequence: int) -> ReplicaRound:
        if sequence < 1:
            raise ProtocolError("sequence must be positive")
        existing = self.rounds.get(sequence)
        if (sequence < self.highest_committed_sequence
                and (existing is None or not existing.committed)):
            raise ProtocolError("stale sequence is below this replica's committed high-water mark")
        return self.rounds.setdefault(sequence, ReplicaRound(sequence))

    @staticmethod
    def proposal_digest(proposal: dict) -> str:
        canonical = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    def _sign(self, phase: str, view: int, sequence: int, digest: str,
              prepared_digest: str = "") -> PBFTMessage:
        unsigned = PBFTMessage(self.node_id, phase, view, sequence, digest, "", prepared_digest)
        signature = self.keyring.sign(self.node_id, unsigned.payload()).hex()
        return PBFTMessage(self.node_id, phase, view, sequence, digest, signature,
                           prepared_digest)

    def _valid_message(self, message: PBFTMessage) -> bool:
        if (message.sender not in self.node_ids
                or message.phase not in {"PRE-PREPARE", "PREPARE", "COMMIT", "VIEW-CHANGE", "NEW-VIEW"}
                or message.view < 0 or message.sequence < 1 or len(message.digest) != 64
                or (message.prepared_digest and len(message.prepared_digest) != 64)):
            return False
        try:
            signature = bytes.fromhex(message.signature)
        except ValueError:
            return False
        return self.keyring.verify(message.sender, message.payload(), signature)

    def _evidence_authorizes_containment(self, proposal: dict) -> bool:
        evidence = proposal.get("evidence")
        target = proposal.get("target")
        if target not in self.node_ids or not isinstance(evidence, list):
            return False
        reporters: set[str] = set()
        by_type: dict[str, float] = {}
        for item in evidence:
            try:
                observation = Evidence(**item)
                if (observation.target != target or observation.observation not in EVIDENCE_TYPES
                        or not 0 <= observation.confidence <= 1
                        or observation.finding not in {None, "anomaly", "normal"}
                        or observation.finding == "normal"
                        or not self._verify_evidence(observation)):
                    continue
            except (TypeError, ValueError):
                continue
            reporters.add(observation.origin)
            adjusted = (observation.confidence
                        * self.trust_scores[observation.origin] / 100.0
                        * EVIDENCE_TYPE_WEIGHTS[observation.observation])
            by_type[observation.observation] = max(by_type.get(observation.observation, 0), adjusted)
        score = min(1.0, sum(by_type.values()))
        return (len(reporters) >= MIN_CORROBORATING_REPORTERS
                and len(by_type) >= MIN_DISTINCT_EVIDENCE_TYPES
                and score >= MIN_EVIDENCE_SCORE)

    def _verify_evidence(self, evidence: Evidence) -> bool:
        try:
            signature = bytes.fromhex(evidence.signature)
        except ValueError:
            return False
        return self.keyring.verify(evidence.origin, evidence.signed_body(), signature)

    def _update_trust_from_committed_round(self, state: ReplicaRound) -> None:
        """Derive identical member trust changes from a committed signed evidence set."""
        proposal = state.proposal or {}
        evidence = proposal.get("evidence", [])
        if not isinstance(evidence, list):
            return
        normal_reporters: set[str] = set()
        anomaly_reporters: set[str] = set()
        for item in evidence:
            try:
                observation = Evidence(**item)
                if (observation.origin not in self.trust_scores
                        or observation.target not in self.node_ids
                        or observation.observation not in EVIDENCE_TYPES
                        or observation.finding not in {None, "anomaly", "normal"}
                        or not 0 <= observation.confidence <= 1
                        or not self._verify_evidence(observation)):
                    continue
            except (TypeError, ValueError):
                continue
            if observation.finding == "normal":
                normal_reporters.add(observation.origin)
            else:
                anomaly_reporters.add(observation.origin)
        updates = []
        if len(normal_reporters) >= self.quorum:
            for reporter in sorted(anomaly_reporters - normal_reporters):
                self.trust_scores[reporter] = max(0.0, self.trust_scores[reporter] - 25.0)
                updates.append({"node": reporter, "change": -25.0,
                                "reason": "anomaly claim contradicted by normal quorum"})
        elif proposal.get("value") == "CONTAIN":
            target = proposal.get("target")
            if target in self.trust_scores:
                self.trust_scores[target] = max(0.0, self.trust_scores[target] - 25.0)
                updates.append({"node": target, "change": -25.0,
                                "reason": "target isolated after committed containment"})
        if proposal.get("value") == "NOOP" and len(normal_reporters) >= self.quorum:
            for reporter in sorted(normal_reporters):
                prior = self.trust_scores[reporter]
                self.trust_scores[reporter] = min(100.0, prior + 5.0)
                if self.trust_scores[reporter] != prior:
                    updates.append({"node": reporter, "change": 5.0,
                                    "reason": "committed clean observation window"})
        self.trust_audit.append({"sequence": state.sequence,
                                 "updates": updates,
                                 "normal_reporters": sorted(normal_reporters),
                                 "anomaly_reporters": sorted(anomaly_reporters),
                                 "trust_scores": dict(self.trust_scores)})

    @_replica_locked
    def cache_proposal(self, sequence: int, proposal: dict) -> dict:
        if set(proposal) != {"value", "target", "scenario", "evidence"}:
            raise ProtocolError("proposal fields are invalid")
        if proposal["value"] not in {"CONTAIN", "NOOP"}:
            raise ProtocolError("proposal value must be CONTAIN or NOOP")
        if proposal["value"] == "CONTAIN" and not self._evidence_authorizes_containment(proposal):
            raise ProtocolError("evidence policy does not authorize containment")
        state = self._round(sequence)
        digest = self.proposal_digest(proposal)
        if state.proposal is not None and state.digest != digest:
            raise ProtocolError("sequence already has a different proposal")
        if state.proposal is not None and state.digest == digest:
            if state.committed:
                raise ProtocolError("sequence is already committed")
            return {"cached": True, "sequence": sequence, "digest": digest,
                    "duplicate": True}
        if sequence <= self.highest_committed_sequence:
            raise ProtocolError("proposal sequence is stale")
        state.proposal = proposal
        state.digest = digest
        self._persist(state)
        return {"cached": True, "sequence": sequence, "digest": digest}

    @_replica_locked
    def create_pre_prepare(self, sequence: int, view: int | None = None) -> PBFTMessage:
        state = self._round(sequence)
        selected_view = state.view if view is None else view
        if selected_view != state.view:
            raise ProtocolError("replica is not in the requested view")
        primary = self.node_ids[selected_view % len(self.node_ids)]
        if primary != self.node_id:
            raise ProtocolError(f"{self.node_id} is not primary for view {selected_view}")
        if state.proposal is None or state.digest is None:
            raise ProtocolError("no validated proposal is cached for this sequence")
        message = self._sign("PRE-PREPARE", selected_view, sequence, state.digest)
        self._record(state, {"phase": "PRE-PREPARE-SENT", "sequence": sequence,
                             "view": selected_view, "digest": state.digest})
        self._persist(state)
        return message

    @_replica_locked
    def create_view_change(self, sequence: int, new_view: int) -> PBFTMessage:
        state = self._round(sequence)
        if state.digest is None:
            raise ProtocolError("cannot change view before caching the request proposal")
        if state.committed:
            raise ProtocolError("committed requests cannot enter a later view")
        if new_view <= state.view:
            raise ProtocolError("new view must be greater than current view")
        prepared = ([state.prepares[sender] for sender in sorted(state.prepares)[:self.quorum]]
                    if len(state.prepares) >= self.quorum else [])
        prepared_raw = [self._message_dict(item) for item in prepared]
        prepared_digest = self._prepared_certificate_digest(prepared_raw) if prepared else ""
        message = self._sign("VIEW-CHANGE", new_view, sequence, state.digest,
                             prepared_digest)
        state.view_changes.setdefault(new_view, {}).setdefault(self.node_id, message)
        state.view_change_proofs.setdefault(new_view, {})[self.node_id] = prepared
        self._persist(state)
        return message

    @_replica_locked
    def create_view_change_bundle(self, sequence: int, new_view: int) -> dict:
        message = self.create_view_change(sequence, new_view)
        state = self.rounds[sequence]
        prepared = state.view_change_proofs[new_view][self.node_id]
        return {"message": self._message_dict(message),
                "prepared_certificate": [self._message_dict(item) for item in prepared]}

    @staticmethod
    def _certificate_digest(certificate: list[dict]) -> str:
        canonical = json.dumps(certificate, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _prepared_certificate_digest(certificate: list[dict]) -> str:
        canonical = json.dumps(certificate, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    def _valid_prepare_certificate(self, certificate: list[PBFTMessage], sequence: int,
                                   digest: str, new_view: int) -> bool:
        if len(certificate) < self.quorum:
            return False
        senders = set()
        certificate_view = None
        for message in certificate:
            if (message.phase != "PREPARE" or message.sequence != sequence
                    or message.digest != digest or message.view >= new_view
                    or message.sender in senders or not self._valid_message(message)):
                return False
            if certificate_view is None:
                certificate_view = message.view
            elif message.view != certificate_view:
                return False
            senders.add(message.sender)
        return len(senders) >= self.quorum

    def _valid_view_change_certificate(self, certificate: list[dict], sequence: int,
                                       view: int, request_digest: str) -> tuple[bool, str]:
        if not isinstance(certificate, list) or len(certificate) < self.quorum:
            return False, request_digest
        senders = set()
        prepared_values: list[tuple[int, str]] = []
        for raw in certificate:
            try:
                message = PBFTMessage(**raw["message"])
                prepared = [PBFTMessage(**item) for item in raw["prepared_certificate"]]
            except (TypeError, ValueError):
                return False, request_digest
            if (message.sender in senders or message.phase != "VIEW-CHANGE"
                    or message.sequence != sequence or message.view != view
                    or message.digest != request_digest or not self._valid_message(message)):
                return False, request_digest
            expected = (self._prepared_certificate_digest(
                [self._message_dict(item) for item in prepared]) if prepared else "")
            if message.prepared_digest != expected:
                return False, request_digest
            if prepared:
                if not self._valid_prepare_certificate(prepared, sequence,
                                                       request_digest, view):
                    return False, request_digest
                prepared_values.append((prepared[0].view, prepared[0].digest))
            senders.add(message.sender)
        if len(senders) < self.quorum:
            return False, request_digest
        if prepared_values:
            highest_view = max(item[0] for item in prepared_values)
            highest = {digest for prepared_view, digest in prepared_values
                       if prepared_view == highest_view}
            if len(highest) != 1:
                return False, request_digest
            selected = next(iter(highest))
            if selected != request_digest:
                return False, selected
            return True, selected
        return True, request_digest

    @_replica_locked
    def create_new_view(self, sequence: int, new_view: int) -> dict:
        state = self._round(sequence)
        if new_view <= state.view or state.digest is None:
            raise ProtocolError("NEW-VIEW requires a cached proposal and a higher view")
        if self.node_ids[new_view % len(self.node_ids)] != self.node_id:
            raise ProtocolError("only the designated new primary may create NEW-VIEW")
        changes = state.view_changes.get(new_view, {})
        certificate = [{"message": self._message_dict(changes[sender]),
                        "prepared_certificate": [self._message_dict(item) for item in
                            state.view_change_proofs.get(new_view, {}).get(sender, [])]}
                       for sender in sorted(changes)[:self.quorum]]
        valid, selected_digest = self._valid_view_change_certificate(
            certificate, sequence, new_view, state.digest)
        if not valid or selected_digest != state.digest:
            raise ProtocolError("NEW-VIEW requires 2f+1 valid matching view-change messages")
        message = self._sign("NEW-VIEW", new_view, sequence,
                             self._certificate_digest(certificate))
        prepared_signers = sorted(item["message"]["sender"] for item in certificate
                                  if item["prepared_certificate"])
        return {"message": self._message_dict(message), "certificate": certificate,
                "selected_digest": selected_digest,
                "prepared_certificate_signers": prepared_signers}

    @_replica_locked
    def handle_message(self, message: PBFTMessage, proposal: dict | None = None,
                       certificate: list[dict] | None = None,
                       prepared_certificate: list[dict] | None = None) -> dict:
        if not self._valid_message(message):
            raise ProtocolError("invalid signature, sender, phase, or sequence")
        state = self._round(message.sequence)
        if state.committed and message.phase != "COMMIT":
            raise ProtocolError("committed requests cannot accept additional protocol phases")
        if message.phase == "VIEW-CHANGE":
            if (state.committed or state.digest is None or message.digest != state.digest
                    or message.view < state.view):
                raise ProtocolError("view-change message does not match the cached request")
            try:
                proof = [PBFTMessage(**item) for item in (prepared_certificate or [])]
            except (TypeError, ValueError) as exc:
                raise ProtocolError("malformed prepared certificate in view-change") from exc
            expected_proof = (self._prepared_certificate_digest(
                [self._message_dict(item) for item in proof]) if proof else "")
            if (message.prepared_digest != expected_proof
                    or (proof and not self._valid_prepare_certificate(
                        proof, message.sequence, state.digest, message.view))):
                raise ProtocolError("view-change prepared certificate is invalid")
            changes = state.view_changes.setdefault(message.view, {})
            changes.setdefault(message.sender, message)
            state.view_change_proofs.setdefault(message.view, {})[message.sender] = proof
            self._record(state, {"phase": "VIEW-CHANGE", "sequence": message.sequence,
                                 "view": message.view, "messages": sorted(changes),
                                 "required": self.quorum,
                                 "prepared_certificate": len(proof)})
            self._persist(state)
            return {"accepted": True, "phase": "VIEW-CHANGE", "view": state.view,
                    "messages": len(changes), "required": self.quorum}

        if message.phase == "NEW-VIEW":
            if message.sender != self.node_ids[message.view % len(self.node_ids)]:
                raise ProtocolError("NEW-VIEW sender is not the primary for its view")
            valid_certificate, selected_digest = self._valid_view_change_certificate(
                certificate if isinstance(certificate, list) else [],
                message.sequence, message.view, state.digest or "")
            if (message.view < state.view or state.digest is None
                    or not isinstance(certificate, list)
                    or message.digest != self._certificate_digest(certificate)
                    or not valid_certificate or selected_digest != state.digest):
                raise ProtocolError("NEW-VIEW signature does not carry a valid 2f+1 certificate")
            if message.view == state.view:
                if state.new_view_message != message:
                    raise ProtocolError("conflicting NEW-VIEW for an already entered view")
                return {"accepted": True, "phase": "NEW-VIEW", "view": state.view,
                        "certificate_messages": len(state.new_view_certificate)}
            state.view_changes[message.view] = {}
            state.view_change_proofs[message.view] = {}
            for raw in certificate:
                view_change = PBFTMessage(**raw["message"])
                proof = [PBFTMessage(**item) for item in raw["prepared_certificate"]]
                state.view_changes[message.view][view_change.sender] = view_change
                state.view_change_proofs[message.view][view_change.sender] = proof
            state.view = message.view
            state.prepares.clear()
            state.commits.clear()
            state.prepare_sent = False
            state.commit_sent = False
            state.new_view_message = message
            state.new_view_certificate = certificate
            self._record(state, {"phase": "NEW-VIEW", "sequence": message.sequence,
                                 "view": state.view, "primary": message.sender,
                                 "certificate_signers": sorted(state.view_changes[message.view])})
            self._persist(state)
            return {"accepted": True, "phase": "NEW-VIEW", "view": state.view,
                    "certificate_messages": len(state.new_view_certificate)}

        if message.phase == "PRE-PREPARE":
            if message.sender != self.node_ids[message.view % len(self.node_ids)]:
                raise ProtocolError("PRE-PREPARE sender is not the primary for this view")
            if message.view != state.view:
                raise ProtocolError("PRE-PREPARE is for a different view")
            if not isinstance(proposal, dict) or self.proposal_digest(proposal) != message.digest:
                raise ProtocolError("PRE-PREPARE digest does not match its proposal")
            allowed = "CONTAIN" if self._evidence_authorizes_containment(proposal) else "NOOP"
            if proposal.get("value") != allowed:
                raise ProtocolError("proposal conflicts with locally verified evidence policy")
            self.cache_proposal(message.sequence, proposal)
            if state.digest != message.digest:
                raise ProtocolError("sequence already prepared for a different digest")
            state.prepares.setdefault(self.node_id,
                                      self._sign("PREPARE", message.view, message.sequence, message.digest))
            state.prepare_sent = True
            self._record(state, {"phase": "PRE-PREPARE", "sequence": message.sequence,
                                 "view": message.view, "primary": message.sender,
                                 "digest": message.digest})
            self._persist(state)
            return {"accepted": True, "message": asdict(state.prepares[self.node_id])}

        if state.proposal is None or state.digest != message.digest or state.view != message.view:
            raise ProtocolError(f"{message.phase} does not match a prepared proposal")
        if message.phase == "PREPARE":
            state.prepares.setdefault(message.sender, message)
            prepared = len(state.prepares) >= self.quorum
            response = None
            if prepared:
                if not state.commit_sent:
                    response = self._sign("COMMIT", state.view, message.sequence, state.digest)
                    state.commits.setdefault(self.node_id, response)
                    state.commit_sent = True
                else:
                    response = state.commits.get(self.node_id)
            self._record(state, {"phase": "PREPARE", "sequence": message.sequence,
                                 "view": state.view, "messages": len(state.prepares),
                                 "required": self.quorum})
            self._persist(state)
            return {"accepted": True, "prepared": prepared,
                    "commit": asdict(response) if response else None}

        if message.phase == "COMMIT":
            if len(state.prepares) < self.quorum:
                raise ProtocolError("COMMIT received before a 2f+1 prepare certificate")
            was_committed = state.committed
            state.commits.setdefault(message.sender, message)
            state.committed = len(state.commits) >= self.quorum
            self._record(state, {"phase": "COMMIT", "sequence": message.sequence,
                                 "view": state.view, "messages": len(state.commits),
                                 "required": self.quorum, "committed": state.committed})
            self._persist(state)
            if state.committed:
                self.highest_committed_sequence = max(
                    self.highest_committed_sequence, message.sequence)
                if not was_committed:
                    self._update_trust_from_committed_round(state)
            return {"accepted": True, "committed": state.committed,
                    "messages": len(state.commits), "required": self.quorum,
                    "value": state.proposal["value"] if state.committed else None}
        raise ProtocolError("unsupported PBFT message phase")

    @_replica_locked
    def make_observation(self, scenario: str, target: str, tick: int) -> dict | None:
        if scenario == "healthy-window":
            from .engine import OBSERVATION_BY_ORIGIN
            category, confidence, finding = OBSERVATION_BY_ORIGIN[self.node_id], .95, "normal"
        elif scenario == "false-evidence":
            if self.node_id == "portal":
                category, confidence, finding = "network", .98, "anomaly"
            else:
                from .engine import OBSERVATION_BY_ORIGIN
                category, confidence, finding = OBSERVATION_BY_ORIGIN[self.node_id], .95, "normal"
        elif scenario == "silent-node" and self.node_id == "database":
            return None
        elif scenario == "block-vote" and self.node_id == "portal":
            return None
        elif scenario == "two-compromised" and self.node_id in {"portal", "identity"}:
            return None
        else:
            from .engine import OBSERVATION_BY_ORIGIN
            category, confidence, finding = OBSERVATION_BY_ORIGIN[self.node_id], .88, "anomaly"
        evidence = Evidence(target, category, confidence,
                            datetime.now(timezone.utc).isoformat(), self.node_id, "", finding)
        evidence.signature = self.keyring.sign(self.node_id, evidence.signed_body()).hex()
        return asdict(evidence)

    @_replica_locked
    def state_report(self, sequence: int = 1) -> dict:
        state = self.rounds.get(sequence)
        return {"node_id": self.node_id, "sequence": sequence,
                "highest_committed_sequence": self.highest_committed_sequence,
                "trust_scores": dict(self.trust_scores),
                "trust_audit": list(self.trust_audit),
                "view": state.view if state else 0,
                "prepared": bool(state and len(state.prepares) >= self.quorum),
                "prepare_messages": len(state.prepares) if state else 0,
                "commit_messages": len(state.commits) if state else 0,
                "committed": bool(state and state.committed),
                "value": state.proposal["value"] if state and state.committed else None,
                "audit": list(state.audit) if state else []}
