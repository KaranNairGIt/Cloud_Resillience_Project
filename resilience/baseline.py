"""A real, deliberately minimal centralized controller for the PDF's Section 9 baseline.

One controller ingests the same signed sensor evidence as the distributed
committee and does detect -> isolate -> recover alone. It has no quorum, no
type-diversity rule, no trust model and no independent re-validation. The
controller itself can be compromised, which is the point of the comparison.
Timing values are the same modeled ticks the distributed simulator uses.
"""

from __future__ import annotations

from .crypto_keys import NodeKeyring
from .engine import (BENIGN_SCENARIOS, EVIDENCE_TYPES, MIN_EVIDENCE_SCORE,
                     OBSERVATION_BY_ORIGIN, SERVICES)

CONTROLLER_MODES = ("none", "block", "silent", "false-accuse", "rubber-stamp")
DETECT_TICKS, ISOLATE_TICKS, RECOVER_TICKS = 1, 2, 4  # same modeled ticks as the distributed run


class CentralizedController:
    def __init__(self, mode: str = "none") -> None:
        if mode not in CONTROLLER_MODES:
            raise ValueError(f"controller mode must be one of: {', '.join(CONTROLLER_MODES)}")
        self.mode = mode
        self.sensors = list(SERVICES)
        self.keyring = NodeKeyring.generate(self.sensors)

    def _sense(self, origin: str, target: str, anomaly: bool, confidence: float) -> dict:
        body = f"{origin}|{target}|{OBSERVATION_BY_ORIGIN[origin]}|{confidence}|{anomaly}".encode()
        return {"origin": origin, "target": target, "observation": OBSERVATION_BY_ORIGIN[origin],
                "confidence": confidence, "anomaly": anomaly, "body": body,
                "signature": self.keyring.sign(origin, body)}

    def _verified(self, item: dict) -> bool:
        return (item["observation"] in EVIDENCE_TYPES
                and self.keyring.verify(item["origin"], item["body"], item["signature"]))

    def _evidence(self, scenario: str, target: str) -> list[dict]:
        items = []
        for origin in self.sensors:
            if scenario == "silent-node" and origin == "database":
                continue  # this sensor produces nothing
            if scenario == "two-compromised" and origin in {"portal", "identity"}:
                continue  # two sensors withheld
            if scenario == "false-evidence":
                items.append(self._sense(origin, target, origin == "portal",
                                         .98 if origin == "portal" else .95))
            elif scenario == "healthy-window":
                items.append(self._sense(origin, target, False, .95))
            else:
                items.append(self._sense(origin, target, True, .88))
        return items

    def run(self, scenario: str, tainted_restore: bool = False) -> dict:
        target = ("identity" if scenario in {"false-evidence", "silent-node", "block-vote",
                                             "healthy-window"} else "records")
        mode = "block" if scenario == "block-vote" and self.mode == "none" else self.mode
        evidence = self._evidence(scenario, target)
        # Minimal policy: any single verified, sufficiently confident anomaly triggers containment.
        triggered = any(self._verified(i) and i["anomaly"] and i["confidence"] >= MIN_EVIDENCE_SCORE
                        for i in evidence)
        if mode == "false-accuse":
            triggered = True   # compromised controller isolates regardless of evidence
        if mode in {"block", "silent"}:
            triggered = False  # compromised/dead controller never acts
        contained = triggered
        events = []
        samples = []
        recover = None
        recovery_success = None
        false_reintegration = False
        if contained:
            events.append(f"{target} isolated on single-controller decision")
            samples.append(3)
            if tainted_restore and mode != "rubber-stamp":
                recovery_success = False
                samples.append(3)
                events.append("restore failed validation; target stays quarantined")
            else:
                samples.append(4)
                recover = RECOVER_TICKS
                recovery_success = not tainted_restore
                false_reintegration = tainted_restore
                events.append("compromised controller skipped validation; tainted workload reintegrated"
                              if tainted_restore else "restored known-good workload")
        else:
            samples.append(4)
            events.append(f"controller is {mode}; no containment action taken" if mode != "none"
                          else "evidence below threshold; no containment")
        benign = scenario in BENIGN_SCENARIOS
        return {
            "architecture": "centralized",
            "scenario": scenario,
            "controller_mode": mode,
            "target": target,
            "decision": "contain" if contained else "withhold",
            "metrics": {
                "time_to_detect_seconds": DETECT_TICKS,
                "time_to_isolate_seconds": ISOLATE_TICKS if contained else None,
                "recovery_time_seconds": recover,
                "false_isolations": int(contained and benign),
                "false_isolation": contained and benign,
                "missed_containment": (not contained) and not benign,
                "recovery_success": recovery_success,
                "false_reintegration": false_reintegration,
                "availability_percent": round(100 * sum(samples) / (4 * len(samples)), 1),
            },
            "events": events,
            "measurement_note": "modeled ticks from an executed controller; not wall-clock measurements",
        }
