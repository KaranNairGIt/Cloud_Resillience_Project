"""Repeatable synthetic runs and a deliberately simple centralized baseline."""

from __future__ import annotations

from statistics import mean

from .engine import ResilienceSimulator


SCENARIOS = ("genuine-compromise", "false-evidence", "silent-node", "block-vote",
            "two-compromised")


def centralized_baseline(scenario: str) -> dict:
    """Model one controller; scenarios are abstractions, not real measurements."""
    outcomes = {
        "genuine-compromise": ("contain", 0, 1, 2, 4, 75.0,
                               "controller detects and restores the synthetic workload"),
        "false-evidence": ("contain", 1, 1, 2, None, 50.0,
                           "single high-confidence accusation causes false isolation"),
        "silent-node": ("contain", 0, 2, 3, 5, 75.0,
                        "controller uses remaining synthetic observations"),
        "block-vote": ("withhold", 0, 1, None, None, 100.0,
                       "compromised central controller blocks the legitimate response"),
        "two-compromised": ("contain", 0, 1, 2, 4, 75.0,
                            "central baseline has no peer-agent quorum to compromise"),
    }
    if scenario not in outcomes:
        raise ValueError(f"unknown scenario: {scenario}")
    decision, false_isolations, detect, isolate, recover, availability, note = outcomes[scenario]
    return {
        "architecture": "centralized",
        "scenario": scenario,
        "decision": decision,
        "metrics": {
            "time_to_detect_seconds": detect,
            "time_to_isolate_seconds": isolate,
            "recovery_time_seconds": recover,
            "false_isolations": false_isolations,
            "availability_percent": availability,
        },
        "events": [note],
        "measurement_note": "illustrative model values; not wall-clock measurements",
    }


def _average(reports: list[dict], key: str) -> float | None:
    values = [r["metrics"][key] for r in reports if r["metrics"][key] is not None]
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
            "All inputs and timing values are synthetic model values, not measurements on a deployed system.",
            "The centralized baseline is a simplified illustrative comparator, not an implementation of a production controller.",
            "The two-compromised case exceeds the distributed model's one-fault tolerance; its centralized comparator has no peer-agent attack surface.",
        ],
    }
