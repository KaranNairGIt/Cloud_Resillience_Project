"""Small mTLS coordinator used to exercise the networked PBFT replicas."""

from __future__ import annotations

from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .engine import (EVIDENCE_TYPE_WEIGHTS, MIN_CORROBORATING_REPORTERS,
                     MIN_DISTINCT_EVIDENCE_TYPES, MIN_EVIDENCE_SCORE, SERVICES,
                     MAX_BYZANTINE_FAULTS, EVIDENCE_TYPES, Evidence)
from .peer_transport import PeerRejectedError, PeerUnavailableError, send_peer_json
from .recovery import RecoveryWorkflow
from .k8s_recovery import KubernetesRecoveryAdapter


class NetworkPBFTCluster:
    """Drive a demo round by relaying signed messages among independent peers.

    The coordinator is an untrusted message relay: replicas independently verify
    signatures, proposal evidence and quorum counts. It holds only its mTLS
    client credential, never the peers' Ed25519 signing keys.
    """

    def __init__(self, pki_dir: Path, hosts: dict[str, str] | None = None,
                 ports: dict[str, int] | None = None,
                 public_key_dir: Path | None = None, timeout: float = 5,
                 apply_kubernetes_response: bool = False,
                 kubernetes_adapter: KubernetesRecoveryAdapter | None = None):
        self.pki_dir = Path(pki_dir)
        self.hosts = hosts or {node: "127.0.0.1" for node in SERVICES}
        self.ports = ports or {node: 8766 for node in SERVICES}
        if set(self.hosts) != set(SERVICES) or set(self.ports) != set(SERVICES):
            raise ValueError("host and port maps must contain every committee node")
        self.timeout = timeout
        self.max_request_attempts = 2
        self.apply_kubernetes_response = apply_kubernetes_response
        if kubernetes_adapter is not None and not apply_kubernetes_response:
            raise ValueError("an injected Kubernetes adapter requires apply_kubernetes_response")
        self.kubernetes_adapter = kubernetes_adapter
        self.unavailable: dict[str, str] = {}
        self.rejections: list[dict] = []
        public_key_dir = Path(public_key_dir) if public_key_dir else self.pki_dir.parent / "keys" / "public"
        self.public_keys = {
            node: serialization.load_pem_public_key(
                (public_key_dir / f"{node}.pub.pem").read_bytes())
            for node in SERVICES
        }
        self.ca = self.pki_dir / "ca.crt"
        self.client_cert = self.pki_dir / "portal.crt"
        self.client_key = self.pki_dir / "portal.key"

    def _request(self, node: str, path: str, body: dict | None = None) -> dict:
        return send_peer_json(self.hosts[node], self.ports[node], str(self.ca),
                              str(self.client_cert), str(self.client_key), path,
                              body, timeout=self.timeout)

    def _request_with_retry(self, node: str, path: str,
                            body: dict | None = None) -> dict:
        last_error = None
        for attempt in range(self.max_request_attempts):
            try:
                return self._request(node, path, body)
            except PeerRejectedError:
                raise
            except (OSError, PeerUnavailableError) as exc:
                last_error = exc
                if attempt + 1 == self.max_request_attempts:
                    raise
        raise last_error or PeerUnavailableError("peer request attempts exhausted")

    def _try_request(self, node: str, path: str, body: dict | None = None) -> dict | None:
        if node in self.unavailable:
            return None
        try:
            return self._request_with_retry(node, path, body)
        except (OSError, PeerUnavailableError, ValueError) as exc:
            self.unavailable[node] = str(exc)
            return None

    @staticmethod
    def _message(result: dict) -> dict:
        return result["message"]

    def _relay(self, nodes: list[str], message: dict,
               proposal: dict | None = None,
               certificate: list[dict] | None = None,
               prepared_certificate: list[dict] | None = None) -> dict[str, dict]:
        body = {"message": message}
        if proposal is not None:
            body["proposal"] = proposal
        if certificate is not None:
            body["certificate"] = certificate
        if prepared_certificate is not None:
            body["prepared_certificate"] = prepared_certificate
        results = {}
        for node in nodes:
            try:
                result = self._request_with_retry(node, "/v1/consensus", body)
            except PeerRejectedError as exc:
                self.rejections.append({"peer": node, "message_sender": message["sender"],
                                        "phase": message["phase"], "reason": str(exc)})
                continue
            except (OSError, PeerUnavailableError, ValueError) as exc:
                self.unavailable[node] = str(exc)
                continue
            if result is not None:
                results[node] = result
        return results

    def _replica_states(self, nodes: list[str], sequence: int) -> dict[str, dict]:
        states = {}
        for node in list(nodes):
            state = self._try_request(node, f"/v1/state?sequence={sequence}")
            if state is not None:
                states[node] = state
        return states

    @staticmethod
    def _stale_sequence_votes(sequence: int, watermarks: dict[str, dict]) -> dict[str, int]:
        """Require a quorum of stale reports so one Byzantine peer cannot veto a request."""
        return {node: int(state["highest_committed_sequence"])
                for node, state in watermarks.items()
                if sequence <= int(state["highest_committed_sequence"])}

    @staticmethod
    def _quorum_trust_scores(watermarks: dict[str, dict], required: int) -> dict[str, float]:
        """Use only trust values independently reported identically by a quorum."""
        scores = {}
        for member in SERVICES:
            votes: dict[float, int] = {}
            for state in watermarks.values():
                raw = state.get("trust_scores", {}).get(member)
                if isinstance(raw, (int, float)) and 0 <= raw <= 100:
                    value = float(raw)
                    votes[value] = votes.get(value, 0) + 1
            matching = [(count, value) for value, count in votes.items()
                        if count >= required]
            scores[member] = max(matching)[1] if matching else 0.0
        return scores

    def _synchronize_checkpoints(self, active: list[str],
                                 watermarks: dict[str, dict]) -> list[dict]:
        """Replay certificate-bearing committed rounds in sequence on lagging peers."""
        transfers = []
        sources = sorted(active,
                         key=lambda node: watermarks[node]["highest_committed_sequence"],
                         reverse=True)
        for source in sources:
            lagging = [node for node in active
                       if watermarks[node]["highest_committed_sequence"]
                       < watermarks[source]["highest_committed_sequence"]]
            if not lagging:
                continue
            after = min(int(watermarks[node]["highest_committed_sequence"])
                        for node in lagging)
            response = self._try_request(
                source, f"/v1/checkpoints?after={after}")
            checkpoints = response.get("checkpoints") if response else None
            if not isinstance(checkpoints, list):
                continue
            valid = [item for item in checkpoints
                     if isinstance(item, dict) and isinstance(item.get("sequence"), int)
                     and item["sequence"] > 0 and isinstance(item.get("snapshot"), dict)]
            valid.sort(key=lambda item: item["sequence"])
            source_high = int(watermarks[source]["highest_committed_sequence"])
            valid = [item for item in valid if item["sequence"] <= source_high]
            for target in lagging:
                last = int(watermarks[target]["highest_committed_sequence"])
                for checkpoint in valid:
                    if checkpoint["sequence"] <= last:
                        continue
                    try:
                        result = self._request_with_retry(target, "/v1/checkpoint", checkpoint)
                    except PeerRejectedError as exc:
                        self.rejections.append({"peer": target, "phase": "CHECKPOINT",
                                                "reason": str(exc)})
                        break
                    except (OSError, PeerUnavailableError, ValueError) as exc:
                        self.unavailable[target] = str(exc)
                        break
                    if result.get("installed"):
                        transfers.append({"sequence": checkpoint["sequence"],
                                          "source": source, "targets": [target],
                                          "commit_signers": sorted(checkpoint["snapshot"]["commits"])})
                        last = checkpoint["sequence"]
            if transfers:
                return transfers
        return transfers

    def _move_to_next_view(self, active: list[str], sequence: int,
                           current_view: int) -> tuple[list[str], int, int, list[dict], list[str]]:
        """Collect a signed view-change quorum and install the next view if it converges."""
        new_view = current_view + 1
        phases: list[dict] = []
        events: list[str] = []
        bundles = []
        for node in list(active):
            response = self._try_request(node, "/v1/view-change", {
                "sequence": sequence, "view": new_view
            })
            if response:
                bundles.append(response)
        for bundle in bundles:
            self._relay(active, bundle["message"],
                        prepared_certificate=bundle["prepared_certificate"])
        active = [node for node in active if node not in self.unavailable]
        senders = sorted(item["message"]["sender"] for item in bundles
                         if item["message"]["sender"] in active)
        quorum = 2 * MAX_BYZANTINE_FAULTS + 1
        phases.append({"phase": "VIEW-CHANGE", "senders": senders,
                       "required": quorum})
        primary = list(SERVICES)[new_view % len(SERVICES)]
        new_view_response = None
        if len(senders) >= quorum and len(active) >= quorum and primary in active:
            new_view_response = self._try_request(primary, "/v1/new-view", {
                "sequence": sequence, "view": new_view
            })
        if not new_view_response:
            events.append("view-change quorum failed to produce a valid NEW-VIEW")
            active = [node for node in active if node not in self.unavailable]
            return active, current_view, len(senders), phases, events
        new_view_message = new_view_response["message"]
        certificate = new_view_response["certificate"]
        self._relay(active, new_view_message, certificate=certificate)
        active = [node for node in active if node not in self.unavailable]
        view_states = self._replica_states(active, sequence)
        active = [node for node in active if node not in self.unavailable]
        converged = (len(view_states) >= quorum
                     and all(state.get("view") == new_view
                             for state in view_states.values()))
        if not converged:
            events.append("view-change quorum failed to converge; no value will be committed")
            return active, current_view, len(senders), phases, events
        phases.append({"phase": "NEW-VIEW", "sender": primary,
                       "certificate_signers": sorted(
                           item["message"]["sender"] for item in certificate),
                       "prepared_certificate_signers":
                           new_view_response["prepared_certificate_signers"],
                       "selected_prepared_digest": new_view_response["selected_digest"],
                       "required": quorum})
        events.append("primary signed NEW-VIEW with a verified 2f+1 certificate")
        return active, new_view, len(senders), phases, events

    def run(self, scenario: str, sequence: int = 1,
            validation: dict[str, bool] | None = None,
            trust_target: str | None = None) -> dict:
        self.unavailable = {}
        self.rejections = []
        if scenario not in {"genuine-compromise", "false-evidence", "silent-node", "block-vote", "two-compromised", "prepared-primary-failure", "healthy-window"}:
            raise ValueError("unsupported safe synthetic scenario")
        if sequence < 1:
            raise ValueError("sequence must be positive")
        if trust_target is not None and (scenario != "healthy-window" or trust_target not in SERVICES):
            raise ValueError("--trust-target is only available for healthy-window and must name a committee member")
        target = (trust_target or "identity") if scenario == "healthy-window" else (
            "identity" if scenario == "false-evidence" else "records")
        kubernetes_adapter = None
        if self.apply_kubernetes_response:
            if self.kubernetes_adapter is None:
                self.kubernetes_adapter = KubernetesRecoveryAdapter()
            kubernetes_adapter = self.kubernetes_adapter
        injected_attack = False
        omitted = set()
        if scenario == "silent-node":
            omitted.add("database")
        elif scenario == "block-vote":
            omitted.add("portal")
        elif scenario == "two-compromised":
            omitted.update({"portal", "identity"})
        active = [node for node in SERVICES if node not in omitted]
        watermarks = self._replica_states(active, 0)
        active = [node for node in active if node not in self.unavailable]
        checkpoint_transfers = self._synchronize_checkpoints(active, watermarks)
        active = [node for node in active if node not in self.unavailable]
        if checkpoint_transfers:
            watermarks = self._replica_states(active, 0)
            active = [node for node in active if node not in self.unavailable]
        trust_scores = self._quorum_trust_scores(
            watermarks, 2 * MAX_BYZANTINE_FAULTS + 1)
        stale_votes = self._stale_sequence_votes(sequence, watermarks)
        required_stale_votes = 2 * MAX_BYZANTINE_FAULTS + 1
        if len(stale_votes) >= required_stale_votes:
            raise ValueError(f"stale sequence {sequence}; {len(stale_votes)} active replicas report committed high-water marks that already include it (required {required_stale_votes}): {stale_votes}")
        if kubernetes_adapter and target == "records" and scenario != "healthy-window":
            kubernetes_adapter.inject_demo_attack()
            injected_attack = True

        evidence = []
        for node in active:
            result = self._try_request(node, "/v1/observe", {
                "scenario": scenario, "target": target, "sequence": sequence
            })
            item = result.get("observation") if result else None
            if item is not None:
                evidence.append(item)
        active = [node for node in active if node not in self.unavailable]

        verified_evidence = []
        by_type: dict[str, float] = {}
        for item in evidence:
            try:
                observation = Evidence(**item)
                if (observation.origin not in self.public_keys
                        or observation.target != target
                        or observation.observation not in EVIDENCE_TYPES
                        or observation.finding not in {None, "anomaly", "normal"}
                        or not 0 <= observation.confidence <= 1):
                    continue
                signature = bytes.fromhex(observation.signature)
                self.public_keys[observation.origin].verify(signature, observation.signed_body())
            except (InvalidSignature, KeyError, ValueError, TypeError):
                continue
            verified_evidence.append(item)
            if observation.finding == "normal":
                continue
            adjusted = (observation.confidence
                        * trust_scores.get(observation.origin, 0.0) / 100.0
                        * EVIDENCE_TYPE_WEIGHTS[observation.observation])
            by_type[item["observation"]] = max(by_type.get(item["observation"], 0), adjusted)
        reporters = {item["origin"] for item in verified_evidence
                     if item.get("finding") != "normal"}
        score = min(1.0, sum(by_type.values()))
        authorized = (len(reporters) >= MIN_CORROBORATING_REPORTERS
                      and len(by_type) >= MIN_DISTINCT_EVIDENCE_TYPES
                      and score >= MIN_EVIDENCE_SCORE)
        value = "CONTAIN" if authorized else "NOOP"
        proposal = {"value": value, "target": target, "scenario": scenario,
                    "evidence": evidence}
        events = (["synthetic workload entered an in-memory anomalous state"]
                  if injected_attack else [])
        for transfer in checkpoint_transfers:
            events.append(f"installed committed checkpoint {transfer['sequence']} from {transfer['source']} on {', '.join(transfer['targets'])}")

        # Demonstrate that a faulty primary cannot make replicas act on its
        # unsupported accusation: the same proposal gate is enforced locally.
        rejected_attack_proposal = False
        if scenario == "false-evidence":
            malicious = {**proposal, "value": "CONTAIN"}
            try:
                result = self._request("portal", "/v1/proposal",
                                       {"sequence": sequence, "proposal": malicious})
            except PeerRejectedError:
                result = None
            except (OSError, PeerUnavailableError) as exc:
                self.unavailable["portal"] = str(exc)
                result = None
            if result is None:
                rejected_attack_proposal = True
                events.append("portal's unsupported CONTAIN proposal was rejected by replica evidence policy")

        cache_results = {}
        for node in list(active):
            result = self._try_request(node, "/v1/proposal", {
                "sequence": sequence, "proposal": proposal
            })
            if result is not None:
                cache_results[node] = result
        active = [node for node in active if node not in self.unavailable]
        if len(active) < 3:
            events.append("fewer than 2f+1 reachable replicas; no proposal round can commit")
        digest = cache_results[active[0]]["digest"] if active else None

        view = 0
        view_change_count = 0
        protocol_phases = []
        prepared_failure = scenario == "prepared-primary-failure"
        if prepared_failure and len(active) >= 3 and "portal" in active:
            first_proposal = self._try_request("portal", "/v1/pre-prepare", {
                "sequence": sequence
            })
            if first_proposal:
                pre_prepare = self._message(first_proposal)
                prepare_messages = []
                for response in self._relay(active, pre_prepare, proposal).values():
                    if response.get("message"):
                        prepare_messages.append(response["message"])
                for prepare in prepare_messages:
                    self._relay(active, prepare)
                self.unavailable["portal"] = "synthetic primary failure after prepare quorum"
                active = [node for node in active if node != "portal"]
                events.append("primary stopped after a prepare quorum; replicas carry prepared proofs into the next view")
                protocol_phases.extend([
                    {"phase": "PRE-PREPARE", "sender": "portal",
                     "digest": pre_prepare["digest"]},
                    {"phase": "PREPARE", "senders": sorted(
                        {item["sender"] for item in prepare_messages}),
                     "required": 2 * MAX_BYZANTINE_FAULTS + 1},
                ])
        if len(active) >= 3 and (scenario in {"block-vote", "false-evidence", "prepared-primary-failure"} or "portal" not in active):
            active, view, view_change_count, phases, change_events = self._move_to_next_view(
                active, sequence, view)
            protocol_phases.extend(phases)
            events.extend(change_events)

        report = {"scenario": scenario, "target": target, "sequence": sequence,
                  "committee": list(SERVICES), "active_replicas": active,
                  "unavailable_replicas": dict(self.unavailable),
                  "checkpoint_transfers": checkpoint_transfers,
                  "rejected_messages": self.rejections,
                  "decision_parameters": {
                      "committee_size_n": len(SERVICES),
                      "byzantine_fault_limit_f": MAX_BYZANTINE_FAULTS,
                      "fault_limit_formula": "floor((n-1)/3)",
                      "reporter_quorum": MIN_CORROBORATING_REPORTERS,
                      "prepare_commit_quorum": 2 * MAX_BYZANTINE_FAULTS + 1,
                      "view_change_quorum": 2 * MAX_BYZANTINE_FAULTS + 1,
                      "max_transport_request_attempts": self.max_request_attempts,
                      "minimum_distinct_evidence_types": MIN_DISTINCT_EVIDENCE_TYPES,
                      "minimum_weighted_evidence_score": MIN_EVIDENCE_SCORE,
                      "reporter_trust_factor": "trust_score / 100; quorum-agreed per replica",
                      "reporter_trust_scores": trust_scores,
                      "evidence_type_weights": dict(EVIDENCE_TYPE_WEIGHTS),
                      "aggregation": "max adjusted confidence per type; sum distinct types; cap at 1.0",
                  },
                  "committee_size_n": len(SERVICES), "byzantine_fault_limit_f": 1,
                  "prepare_commit_quorum": 3, "view_change_messages": view_change_count,
                  "view": view, "proposal": proposal,
                  "kubernetes_attack_injected": injected_attack,
                  "evidence_score": round(score, 4),
                  "verified_evidence_count": len(verified_evidence),
                  "corroborating_reporters": sorted(reporters),
                  "distinct_evidence_types": sorted(by_type),
                  "evidence_authorized": authorized,
                  "rejected_unsupported_primary_proposal": rejected_attack_proposal,
                  "digest": digest, "events": events, "replicas": {},
                  "response": ({"executed": False, "status": "attack-active-no-quorum",
                                "reason": "the lab anomaly remains; consensus did not authorize recovery",
                                "actions": []} if injected_attack else
                               {"executed": False, "status": "unchanged",
                                "reason": "a committed CONTAIN decision is required", "actions": []}),
                  "consensus": {"committed": False, "value": None,
                                "phases": protocol_phases}}
        if len(active) < 3:
            if not any("fewer than 2f+1" in event for event in events):
                events.append("fewer than 2f+1 active replicas; round safely stopped without commit")
            report["replicas"] = {node: state for node in active
                                   if (state := self._try_request(node, f"/v1/state?sequence={sequence}"))}
            report["unavailable_replicas"] = dict(self.unavailable)
            return report

        primary = list(SERVICES)[view % len(SERVICES)]
        if primary not in active:
            events.append("selected primary is unavailable; no primary proposal was issued")
            report["unavailable_replicas"] = dict(self.unavailable)
            report["replicas"] = self._replica_states(active, sequence)
            return report
        response = self._try_request(primary, "/v1/pre-prepare", {"sequence": sequence})
        if response is None:
            active = [node for node in active if node not in self.unavailable]
            if len(active) >= 3:
                active, new_view, changed_messages, phases, change_events = self._move_to_next_view(
                    active, sequence, view)
                protocol_phases.extend(phases)
                events.extend(change_events)
                view_change_count = changed_messages
                if new_view > view:
                    view = new_view
                    primary = list(SERVICES)[view % len(SERVICES)]
                    events.append("primary request timed out; consensus continued in the verified next view")
                    response = self._try_request(primary, "/v1/pre-prepare", {
                        "sequence": sequence
                    })
            if response is None:
                events.append("no reachable primary issued PRE-PREPARE; this sequence did not commit")
                report["active_replicas"] = active
                report["unavailable_replicas"] = dict(self.unavailable)
                report["consensus"]["phases"] = protocol_phases
                report["consensus"]["view"] = view
                report["view_change_messages"] = view_change_count
                report["replicas"] = self._replica_states(active, sequence)
                return report
        pre_prepare = self._message(response)
        prepare_messages = []
        for result in self._relay(active, pre_prepare, proposal).values():
            if result.get("message"):
                prepare_messages.append(result["message"])
        active = [node for node in active if node not in self.unavailable]
        report["active_replicas"] = active
        report["unavailable_replicas"] = dict(self.unavailable)
        report["consensus"]["phases"].append({"phase": "PRE-PREPARE", "sender": primary,
                                                "digest": pre_prepare["digest"]})
        prepares_by_sender = {m["sender"]: m for m in prepare_messages}
        if len(active) < 3:
            events.append("fewer than 2f+1 replicas accepted PRE-PREPARE; round stopped")
            report["replicas"] = self._replica_states(active, sequence)
            return report
        commit_messages = []
        for message in prepares_by_sender.values():
            relay_results = self._relay(active, message)
            active = [node for node in active if node not in self.unavailable]
            for node, result in relay_results.items():
                commit = result.get("commit")
                if commit:
                    commit_messages.append(commit)
            if len(active) < 3:
                break
        report["consensus"]["phases"].append({"phase": "PREPARE",
                                                "senders": sorted(prepares_by_sender),
                                                "required": 3})
        commits_by_sender = {m["sender"]: m for m in commit_messages}
        for message in commits_by_sender.values():
            self._relay(active, message)
            active = [node for node in active if node not in self.unavailable]
        report["consensus"]["phases"].append({"phase": "COMMIT",
                                                "senders": sorted(commits_by_sender),
                                                "required": 3})
        report["replicas"] = self._replica_states(active, sequence)
        active = [node for node in active if node not in self.unavailable]
        report["active_replicas"] = active
        report["unavailable_replicas"] = dict(self.unavailable)
        committed = (len(commits_by_sender) >= 3
                     and sum(bool(state["committed"]) for state in report["replicas"].values()) >= 3)
        report["consensus"].update({"committed": committed,
                                     "value": value if committed else None,
                                     "view": view,
                                     "prepare_messages": len(prepares_by_sender),
                                     "commit_messages": len(commits_by_sender)})
        report["trust_scores_after_commit"] = self._quorum_trust_scores(
            report["replicas"], 2 * MAX_BYZANTINE_FAULTS + 1)
        report["trust_audit"] = {node: state.get("trust_audit", [])
                                 for node, state in report["replicas"].items()}
        clean_window_votes = sum(
            any(entry.get("sequence") == sequence
                and target in entry.get("normal_reporters", [])
                for entry in state.get("trust_audit", []))
            for state in report["replicas"].values())
        clean_window_committed = (scenario == "healthy-window" and committed
                                 and value == "NOOP"
                                 and clean_window_votes >= 2 * MAX_BYZANTINE_FAULTS + 1)
        report["trust_window_quorum"] = clean_window_votes
        if kubernetes_adapter:
            if scenario == "healthy-window" and target == "records":
                report["response"] = kubernetes_adapter.advance_trust_window(
                    consensus_committed=committed,
                    value=value if committed else "NOOP", target=target,
                    trust_score=report["trust_scores_after_commit"].get(target),
                    healthy_window_committed=clean_window_committed,
                    validation=validation)
            else:
                report["response"] = kubernetes_adapter.run(
                    consensus_committed=committed, value=value if committed else "NOOP",
                    target=target, validation=validation,
                    trust_score=report["trust_scores_after_commit"].get(target))
        else:
            report["response"] = RecoveryWorkflow().run(
                consensus_committed=committed, value=value if committed else "NOOP",
                target=target, validation=validation)
        if committed and value == "CONTAIN":
            events.append("replicas committed containment; configured response workflow ran")
        elif committed:
            events.append("replicas committed NOOP; no isolation action was authorized")
        else:
            events.append("replicas did not reach a consistent 2f+1 commit")
        return report
