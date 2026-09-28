"""Repeatable synthetic runs and a deliberately simple centralized baseline."""

from __future__ import annotations

from statistics import mean

from .baseline import CentralizedController
from .engine import ResilienceSimulator


SCENARIOS = ("genuine-compromise", "false-evidence", "silent-node", "block-vote",
            "two-compromised")


def centralized_baseline(scenario: str, controller_mode: str = "none",
                         tainted_restore: bool = False) -> dict:
    """Run the executable single-controller baseline (see baseline.py)."""
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    return CentralizedController(controller_mode).run(scenario, tainted_restore)


def _average(reports: list[dict], key: str) -> float | None:
    values = [r["metrics"].get(key) for r in reports if r["metrics"].get(key) is not None]
    return round(mean(values), 2) if values else None


def run_experiment(repeats: int = 3, scenarios: tuple[str, ...] = SCENARIOS) -> dict:
    if repeats < 1 or repeats > 100:
        raise ValueError("repeats must be between 1 and 100")
    unknown = set(scenarios) - set(SCENARIOS)
    if unknown:
        raise ValueError(f"unknown scenarios: {', '.join(sorted(unknown))}")

    results = []
    for scenario in scenarios:
        distributed_runs = [ResilienceSimulator().run(scenario) for _ in range(repeats)]
        central_runs = [centralized_baseline(scenario) for _ in range(repeats)]
        def summary(runs: list[dict]) -> dict:
            return {
                "runs": repeats,
                "containment_rate_percent": round(100 * sum(r["decision"] == "contain" for r in runs) / repeats, 1),
                "mean_time_to_detect_seconds": _average(runs, "time_to_detect_seconds"),
                "mean_time_to_isolate_seconds": _average(runs, "time_to_isolate_seconds"),
                "mean_recovery_time_seconds": _average(runs, "recovery_time_seconds"),
                "false_isolations": sum(r["metrics"]["false_isolations"] for r in runs),
                "mean_availability_percent": _average(runs, "availability_percent"),
                "false_isolation_rate_percent": round(100 * sum(bool(r["metrics"]["false_isolation"]) for r in runs) / repeats, 1),
                "missed_containment_rate_percent": round(100 * sum(bool(r["metrics"]["missed_containment"]) for r in runs) / repeats, 1),
                "mean_trust_recovery_time_ticks": _average(runs, "trust_recovery_time_ticks"),
            }
        results.append({
            "scenario": scenario,
            "distributed": summary(distributed_runs),
            "centralized": summary(central_runs),
            "sample": {"distributed": distributed_runs[0], "centralized": central_runs[0]},
        })
    return {
        "experiment": "distributed-vs-centralized-synthetic-scenarios",
        "repeats": repeats,
        "results": results,
        "limitations": [
            "All inputs and timing values are synthetic model ticks, not measurements on a deployed system.",
            "The centralized baseline is an executed but deliberately minimal single controller, not a production controller.",
            "Scenarios attack one sensor agent (or the controller itself for block-vote); use the `boundary` command to compromise the controller under every failure mode.",
        ],
    }
