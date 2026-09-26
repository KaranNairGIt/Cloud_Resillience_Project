"""Non-destructive recovery workflow used by the capstone simulations."""

from __future__ import annotations


class RecoveryWorkflow:
    """Model quarantine, restoration, validation and trust-gated reintegration.

    This module is deliberately a simulator: it changes no process, pod, file,
    network rule, database row or cloud resource.
    """

    CHECKS = ("integrity", "health", "behavior")
    STAGES = (("restricted", 45), ("monitored", 60),
              ("peer-validated", 75), ("full", 90))

    def run(self, *, consensus_committed: bool, value: str, target: str,
            validation: dict[str, bool] | None = None) -> dict:
        if not consensus_committed or value != "CONTAIN":
            return {"executed": False, "target": target,
                    "status": "unchanged",
                    "reason": "a committed CONTAIN decision is required",
                    "actions": []}
        validation = validation or {name: True for name in self.CHECKS}
        if set(validation) != set(self.CHECKS) or not all(isinstance(v, bool) for v in validation.values()):
            raise ValueError("validation must provide boolean integrity, health, and behavior results")
        actions = ["simulated quarantine applied", "restored simulated known-good workload snapshot"]
        failed = sorted(name for name in self.CHECKS if not validation[name])
        if failed:
            actions.append("validation failed; target remains quarantined and reintegration is blocked")
            return {"executed": True, "target": target,
                    "status": "quarantined", "available": False,
                    "known_good_restore": True,
                    "validation": validation, "failed_checks": failed,
                    "trust": 50, "reintegration_stages": ["quarantine"],
                    "actions": actions}

        actions.append("integrity, health and behavior checks passed")
        stages = ["quarantine"]
        trust = 50
        for stage, threshold in self.STAGES:
            trust = max(trust, threshold)
            stages.append(stage)
            actions.append(f"trust {trust}: promoted to {stage}")
        return {"executed": True, "target": target,
                "status": "fully-reintegrated", "available": True,
                "known_good_restore": True, "validation": validation,
                "failed_checks": [], "trust": trust,
                "reintegration_stages": stages, "actions": actions}
