"""Deterministic resilience-cycle simulator; all attack inputs are synthetic."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Iterable

from .consensus import PBFTConsensus
from .crypto_keys import NodeKeyring


SERVICES = {
    "portal": "patient-portal",
    "identity": "identity-service",
    "records": "records-api",
    "database": "records-database",
}
EVIDENCE_TYPES = {"network", "process", "file-integrity", "auth"}
OBSERVATION_BY_ORIGIN = {"portal": "network", "identity": "auth",
                         "records": "process", "database": "file-integrity"}
NODE_COUNT = len(SERVICES)
MAX_BYZANTINE_FAULTS = (NODE_COUNT - 1) // 3
MIN_CORROBORATING_REPORTERS = 2 * MAX_BYZANTINE_FAULTS + 1
MIN_DISTINCT_EVIDENCE_TYPES = 2
MIN_EVIDENCE_SCORE = 0.60
EVIDENCE_TYPE_WEIGHTS = {name: 1.0 for name in EVIDENCE_TYPES}
BENIGN_SCENARIOS = frozenset({"false-evidence", "healthy-window"})  # target is actually healthy
STAGES = ("quarantine", "restricted", "monitored", "peer-validated", "full")
STAGE_TRUST = {"quarantine": 0, "restricted": 45, "monitored": 60,
               "peer-validated": 75, "full": 90}
TRUST_RECOVERY_PER_HEALTHY_WINDOW = 10
SUSTAINED_HEALTHY_WINDOWS_PER_STAGE = 2
UNSUPPORTED_CLAIM_TRUST_PENALTY = 25
ISOLATION_TRUST_PENALTY = 25


@dataclass
class Node:
    node_id: str
    service: str
    trust: float = 80.0
    stage: str = "full"
    available: bool = True
    resilience_compromised: bool = False
    trust_since: int = 0
    healthy_window_streak: int = 0


@dataclass
class Evidence:
    target: str
    observation: str
    confidence: float
    timestamp: str
    origin: str
    signature: str
    finding: str | None = None

    def signed_body(self) -> bytes:
        body = {"target": self.target, "observation": self.observation,
                "confidence": self.confidence, "timestamp": self.timestamp,
                "origin": self.origin}
        if self.finding is not None:
            body["finding"] = self.finding
        return json.dumps(body, sort_keys=True,
                          separators=(",", ":")).encode()


@dataclass
class Incident:
    scenario: str
    target: str
    events: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    decision_score: float = 0.0
    decision: str = "pending"
    detect_seconds: int | None = None
    isolate_seconds: int | None = None
    recover_seconds: int | None = None
    false_isolation: bool = False
    consensus_result: dict | None = None
    trust_trajectory: list[dict] = field(default_factory=list)
    trust_updates: list[dict] = field(default_factory=list)
    recovery_success: bool | None = None
    false_reintegration: bool = False


class ResilienceSimulator:
    """A small single-process model of four mutually observing resilience nodes."""

    def __init__(self) -> None:
        self.nodes = {node_id: Node(node_id, service) for node_id, service in SERVICES.items()}
        self.keyring = NodeKeyring.generate(list(self.nodes))
        self.consensus = PBFTConsensus(list(self.nodes), self.keyring, MAX_BYZANTINE_FAULTS)
        self.tick = 0
        self.incidents: list[Incident] = []
        self.false_isolations = 0
        self.availability_samples = 0
        self.available_samples = 0

    def _emit(self, origin: str, target: str, observation: str,
              confidence: float, finding: str = "anomaly") -> Evidence:
        if observation not in EVIDENCE_TYPES:
            raise ValueError(f"unknown evidence type: {observation}")
        if not 0 <= confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if finding not in {"anomaly", "normal"}:
            raise ValueError("finding must be anomaly or normal")
        unsigned = Evidence(target, observation, confidence,
                            f"2026-01-01T00:00:{self.tick:02d}Z", origin, "", finding)
        signature = self.keyring.sign(origin, unsigned.signed_body()).hex()
        unsigned.signature = signature
        return unsigned

    def verify(self, evidence: Evidence) -> bool:
        try:
            signature = bytes.fromhex(evidence.signature)
        except ValueError:
            return False
        return self.keyring.verify(evidence.origin, evidence.signed_body(), signature)

    def _score(self, evidence: Iterable[Evidence]) -> float:
        # Each evidence category contributes once; same-type flooding adds no weight.
        best_by_type: dict[str, float] = {}
        for item in evidence:
            if not self.verify(item) or item.target not in self.nodes:
                continue
            if item.finding == "normal":
                continue
            reporter = self.nodes[item.origin]
            adjusted = (item.confidence * reporter.trust / 100.0
                        * EVIDENCE_TYPE_WEIGHTS[item.observation])
            best_by_type[item.observation] = max(best_by_type.get(item.observation, 0), adjusted)
        return min(1.0, sum(best_by_type.values()))

    @staticmethod
    def voting_parameters() -> dict:
        return {
            "committee_size_n": NODE_COUNT,
            "byzantine_fault_limit_f": MAX_BYZANTINE_FAULTS,
            "fault_limit_formula": "floor((n-1)/3)",
            "corroborating_reporter_quorum": MIN_CORROBORATING_REPORTERS,
            "quorum_formula": "2f+1",
            "minimum_distinct_evidence_types": MIN_DISTINCT_EVIDENCE_TYPES,
            "minimum_weighted_evidence_score": MIN_EVIDENCE_SCORE,
            "reporter_trust_factor": "trust_score / 100",
            "per_type_confidence_aggregation": "maximum adjusted confidence; duplicate types do not stack",
            "evidence_type_weights": dict(EVIDENCE_TYPE_WEIGHTS),
            "consensus_implementation": "signed PBFT-style pre-prepare/prepare/commit plus 2f+1 view-change/NEW-VIEW; independent network replicas available with cluster simulate",
        }

    def _record_availability(self) -> None:
        self.availability_samples += 1
        self.available_samples += sum(node.available for node in self.nodes.values())

    def _advance_trust_recovery(self, node: Node, incident: Incident,
                                healthy_windows: int) -> None:
        """Advance modeled clean monitoring windows before each trust-stage promotion."""
        if healthy_windows < 0 or healthy_windows > 24:
            raise ValueError("healthy_windows must be between 0 and 24")
        for _ in range(healthy_windows):
            self._record_trust_window(node, incident, healthy=True)

    def _record_trust_window(self, node: Node, incident: Incident,
                             healthy: bool) -> None:
        """Record one monitoring window; any unhealthy window breaks the streak."""
        stage_order = ("restricted", "monitored", "peer-validated", "full")
        self.tick += 1
        if healthy:
            node.trust = min(100, node.trust + TRUST_RECOVERY_PER_HEALTHY_WINDOW)
            node.healthy_window_streak += 1
        else:
            node.trust = max(0, node.trust - TRUST_RECOVERY_PER_HEALTHY_WINDOW)
            node.healthy_window_streak = 0
        while (node.stage in stage_order and node.stage != "restricted"
               and node.trust < STAGE_TRUST[node.stage]):
            node.stage = stage_order[stage_order.index(node.stage) - 1]
            node.trust_since = self.tick
            node.healthy_window_streak = 0
        promoted = False
        next_stage_index = stage_order.index(node.stage) + 1
        if (healthy and next_stage_index < len(stage_order)
                and node.healthy_window_streak >= SUSTAINED_HEALTHY_WINDOWS_PER_STAGE
                and node.trust >= STAGE_TRUST[stage_order[next_stage_index]]):
            node.stage = stage_order[next_stage_index]
            node.trust_since = self.tick
            node.healthy_window_streak = 0
            promoted = True
        incident.trust_trajectory.append({
            "window": len(incident.trust_trajectory) + 1,
            "tick": self.tick,
            "healthy": healthy,
            "trust": round(node.trust, 1),
            "stage": node.stage,
            "promotion": promoted,
        })

    def _collect(self, incident: Incident, origins: Iterable[str], confidence: float = .88) -> None:
        for origin in origins:
            node = self.nodes[origin]
            if incident.scenario == "silent-node" and origin == "database":
                incident.events.append("database agent went silent; its vote was unavailable")
                continue
            if incident.scenario == "healthy-window":
                e = self._emit(origin, incident.target,
                               OBSERVATION_BY_ORIGIN[origin], .95, "normal")
                incident.evidence.append(e)
                continue
            if incident.scenario == "false-evidence" and origin == "portal":
                # Deliberately unsupported accusation against a healthy target.
                e = self._emit(origin, incident.target, "network", .98)
                incident.evidence.append(e)
                incident.events.append("portal agent emitted unsupported synthetic accusation")
                continue
            if incident.scenario == "false-evidence":
                # Signed normal observations provide independent contradiction evidence.
                e = self._emit(origin, incident.target,
                               OBSERVATION_BY_ORIGIN[origin], .95, "normal")
                incident.evidence.append(e)
                continue
            if incident.scenario == "block-vote" and origin == "portal":
                # The synthetic Byzantine portal refuses to send its vote/evidence.
                continue
            if node.resilience_compromised and incident.scenario == "two-compromised":
                continue
            incident.evidence.append(self._emit(origin, incident.target,
                                                OBSERVATION_BY_ORIGIN[origin], confidence))

    def run(self, scenario: str = "genuine-compromise", tainted_restore: bool = False) -> dict:
        allowed = {"genuine-compromise", "false-evidence", "silent-node", "block-vote",
                   "two-compromised", "healthy-window"}
        if scenario not in allowed:
            raise ValueError(f"scenario must be one of: {', '.join(sorted(allowed))}")
        self.tick += 1
        target = "identity" if scenario in {"false-evidence", "silent-node", "block-vote",
                                             "healthy-window"} else "records"
        incident = Incident(scenario, target)
        self.incidents.append(incident)

        if scenario in {"genuine-compromise", "two-compromised", "block-vote", "silent-node"}:
            incident.events.append(f"synthetic anomalous workload behavior at {target}")
        if scenario == "two-compromised":
            self.nodes["portal"].resilience_compromised = True
            self.nodes["identity"].resilience_compromised = True
            incident.events.append("two resilience agents marked compromised for boundary experiment")
        if scenario in {"false-evidence", "silent-node", "block-vote"}:
            self.nodes["portal"].resilience_compromised = True
            incident.events.append("portal resilience agent marked compromised for simulation")

        incident.detect_seconds = 1
        origins = list(self.nodes)
        self._collect(incident, origins)
        if scenario == "block-vote":
            incident.events.append("compromised portal attempted to block a legitimate decision")
            # An attempted block cannot veto other independent signed evidence.
        incident.decision_score = self._score(incident.evidence)

        anomaly_evidence = [e for e in incident.evidence
                            if self.verify(e) and e.finding != "normal"]
        valid_reporters = {e.origin for e in anomaly_evidence}
        evidence_diversity = len({e.observation for e in anomaly_evidence})
        required = MIN_CORROBORATING_REPORTERS
        evidence_authorizes_containment = (
            len(valid_reporters) >= required
            and evidence_diversity >= MIN_DISTINCT_EVIDENCE_TYPES
            and incident.decision_score >= MIN_EVIDENCE_SCORE
        )
        expected_value = "CONTAIN" if evidence_authorizes_containment else "NOOP"
        byzantine = set()
        if scenario in {"false-evidence", "block-vote"}:
            byzantine.add("portal")
        elif scenario == "two-compromised":
            byzantine.update(("portal", "identity"))
        silent = {"database"} if scenario == "silent-node" else set()
        protocol = self.consensus.decide(
            expected_value,
            byzantine=byzantine,
            silent=silent,
            block_primary=scenario == "block-vote",
            primary_value="CONTAIN" if scenario == "false-evidence" else None,
        )
        incident.consensus_result = protocol.as_dict()
        approved = (evidence_authorizes_containment and protocol.committed
                    and protocol.value == "CONTAIN")
        incident.decision = "contain" if approved else "withhold"
        # Ground truth: containing a target that is actually healthy is a false isolation.
        incident.false_isolation = approved and scenario in BENIGN_SCENARIOS
        if incident.false_isolation:
            self.false_isolations += 1
        sampled_availability = False
        if approved:
            incident.isolate_seconds = 2
            self.nodes[target].available = False
            self.nodes[target].stage = "quarantine"
            prior_trust = self.nodes[target].trust
            self.nodes[target].trust = max(
                0, prior_trust - ISOLATION_TRUST_PENALTY)
            incident.trust_updates.append({"node": target,
                                           "change": self.nodes[target].trust - prior_trust,
                                           "reason": "committed containment"})
            incident.events.append(f"{target} quarantined after independent evidence quorum")
            self._record_availability()
            sampled_availability = True
        else:
            normal_reporters = {item.origin for item in incident.evidence
                                if self.verify(item) and item.finding == "normal"}
            anomaly_reporters = {item.origin for item in incident.evidence
                                 if self.verify(item) and item.finding != "normal"}
            if len(normal_reporters) >= MIN_CORROBORATING_REPORTERS:
                for reporter in anomaly_reporters - normal_reporters:
                    prior_trust = self.nodes[reporter].trust
                    self.nodes[reporter].trust = max(
                        0, self.nodes[reporter].trust - UNSUPPORTED_CLAIM_TRUST_PENALTY)
                    incident.events.append(f"{reporter} trust reduced after contradicted accusation")
                    incident.trust_updates.append({"node": reporter,
                                                   "change": self.nodes[reporter].trust - prior_trust,
                                                   "reason": "anomaly finding contradicted by normal quorum"})
                for reporter in normal_reporters:
                    prior_trust = self.nodes[reporter].trust
                    self.nodes[reporter].trust = min(100, self.nodes[reporter].trust + 5)
                    if self.nodes[reporter].trust != prior_trust:
                        incident.trust_updates.append({"node": reporter,
                                                       "change": self.nodes[reporter].trust - prior_trust,
                                                       "reason": "committed clean observation window"})
            if scenario == "false-evidence":
                incident.events.append("insufficient independent corroboration; no containment action taken")
                incident.events.append("portal trust reduced after unsupported accusation")
            else:
                incident.events.append("containment withheld: quorum or evidence score was insufficient")

        if approved:
            # Deterministic restore from the simulated known-good snapshot.
            self.tick += 2
            node = self.nodes[target]
            if tainted_restore:
                # Post-restore validation catches a still-compromised workload:
                # it stays quarantined and is never reintegrated.
                incident.recovery_success = False
                node.available = False
                node.stage = "quarantine"
                self._record_availability()
                incident.events.append("restored workload failed post-restore integrity validation")
                incident.events.append(f"{target} kept in quarantine; reintegration refused")
            else:
                node.available = True
                self._record_availability()
                incident.recover_seconds = 4
                incident.recovery_success = True
                incident.events.append("restored simulated known-good workload snapshot")
                incident.events.append("post-restore integrity and behavior validation passed")
                node.stage = "restricted"
                node.trust = max(node.trust, 50)
                node.trust_since = self.tick
                # Six clean monitoring windows demonstrate that promotion requires
                # repeated evidence at every stage, not just a single health check.
                self._advance_trust_recovery(node, incident, healthy_windows=6)
                incident.events.append(f"reintegrated at {node.stage} stage (trust {node.trust:.0f})")
        if scenario == "two-compromised" and not approved:
            incident.events.append("expected boundary: two compromised agents exceed this 4-node model's f=1 tolerance")
        incident.events.extend(protocol.events)

        if not sampled_availability:
            self._record_availability()
        return self.report(incident)

    def report(self, incident: Incident | None = None) -> dict:
        chosen = incident or (self.incidents[-1] if self.incidents else None)
        payload = {
            "scenario": chosen.scenario if chosen else None,
            "target": chosen.target if chosen else None,
            "decision": chosen.decision if chosen else None,
            "evidence_score": round(chosen.decision_score, 3) if chosen else 0,
            "evidence_types": sorted({e.observation for e in chosen.evidence
                                      if self.verify(e) and e.finding != "normal"}) if chosen else [],
            "decision_parameters": self.voting_parameters(),
            "corroboration": {
                "verified_reporters": len({e.origin for e in chosen.evidence
                                            if self.verify(e) and e.finding != "normal"}) if chosen else 0,
                "required_reporters": MIN_CORROBORATING_REPORTERS,
                "distinct_evidence_types": len({e.observation for e in chosen.evidence
                                                 if self.verify(e) and e.finding != "normal"}) if chosen else 0,
                "minimum_distinct_evidence_types": MIN_DISTINCT_EVIDENCE_TYPES,
                "evidence_score_threshold": MIN_EVIDENCE_SCORE,
                "passed": bool(chosen and chosen.decision == "contain"),
            },
            "pbft_consensus": chosen.consensus_result if chosen else None,
            "verified_reporters": sorted({e.origin for e in chosen.evidence
                                          if self.verify(e) and e.finding != "normal"}) if chosen else [],
            "normal_reporters": sorted({e.origin for e in chosen.evidence
                                        if self.verify(e) and e.finding == "normal"}) if chosen else [],
            "trust_updates": list(chosen.trust_updates) if chosen else [],
            "metrics": {
                "time_to_detect_seconds": chosen.detect_seconds if chosen else None,
                "time_to_isolate_seconds": chosen.isolate_seconds if chosen else None,
                "recovery_time_seconds": chosen.recover_seconds if chosen else None,
                "false_isolations": sum(i.false_isolation for i in self.incidents),
                "false_isolation": bool(chosen and chosen.false_isolation),
                "recovery_success": chosen.recovery_success if chosen else None,
                "false_reintegration": bool(chosen and chosen.false_reintegration),
                "missed_containment": bool(chosen and chosen.scenario not in BENIGN_SCENARIOS
                                           and chosen.decision != "contain"),
                "availability_percent": round(100 * self.available_samples / max(1, self.availability_samples * len(self.nodes)), 1),
                "target_trust": round(self.nodes[chosen.target].trust, 1) if chosen else None,
                "target_stage": self.nodes[chosen.target].stage if chosen else None,
                "trust_scores": {node_id: round(node.trust, 1) for node_id, node in self.nodes.items()},
                "trust_recovery_windows": len(chosen.trust_trajectory) if chosen else 0,
                "trust_recovery_time_ticks": (chosen.trust_trajectory[-1]["tick"] -
                                               chosen.trust_trajectory[0]["tick"] + 1)
                                              if chosen and chosen.trust_trajectory else 0,
                "trust_trajectory": list(chosen.trust_trajectory) if chosen else [],
            },
            "events": list(chosen.events) if chosen else [],
            "security_note": "local synthetic simulator; its Ed25519 keys are ephemeral; use cluster simulate for separate mTLS replicas; Kubernetes response actions are not wired to this peer protocol",
        }
        return payload
