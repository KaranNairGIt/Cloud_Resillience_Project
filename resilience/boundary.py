"""Fault-tolerance boundary sweep (PDF Sections 7 step 5, 9 and 10).

Sweeps the number of compromised resilience nodes k against committees of size
n, for three attacker behaviours, using the same evidence-policy constants and
the same signed PBFT model as the simulator. Reports where safety (no false
isolation) and liveness (genuine attack still contained) actually break and
compares that with the theoretical f = floor((n-1)/3). Also runs the same
attacks against a compromised centralized controller.

Modeling assumption (stated in every report): Byzantine replicas in the PBFT
model withhold or refuse; once k >= 2f+1 they are assumed able to form a commit
quorum on their own, because PBFT gives no guarantee beyond f faults.
"""

from __future__ import annotations

from .baseline import CentralizedController
from .consensus import PBFTConsensus
from .crypto_keys import NodeKeyring
from .engine import (EVIDENCE_TYPE_WEIGHTS, MIN_DISTINCT_EVIDENCE_TYPES, MIN_EVIDENCE_SCORE,
                     UNSUPPORTED_CLAIM_TRUST_PENALTY)

TYPES = ("network", "auth", "process", "file-integrity")
DEFAULT_SIZES = (4, 7, 10)
INITIAL_TRUST = 80.0
ATTACKS = {
    "false-accuse": {"truth": "benign", "goal": "isolate a healthy service"},
    "silent": {"truth": "genuine", "goal": "withhold votes so a real attack is not contained"},
    "block": {"truth": "genuine", "goal": "mask the attack and refuse to lead the isolation vote"},
}


def _gate(keyring: NodeKeyring, evidence: list[dict], f: int, trust: dict[str, float]) -> bool:
    """Same policy as the simulator: 2f+1 reporters, >=2 types, weighted score >= threshold."""
    best: dict[str, float] = {}
    reporters = set()
    for item in evidence:
        if item["finding"] != "anomaly":
            continue
        if not keyring.verify(item["origin"], item["body"], item["signature"]):
            continue
        reporters.add(item["origin"])
        adjusted = (item["confidence"] * trust[item["origin"]] / 100.0
                    * EVIDENCE_TYPE_WEIGHTS[item["observation"]])
        best[item["observation"]] = max(best.get(item["observation"], 0.0), adjusted)
    return (len(reporters) >= 2 * f + 1 and len(best) >= MIN_DISTINCT_EVIDENCE_TYPES
            and min(1.0, sum(best.values())) >= MIN_EVIDENCE_SCORE)


def _evidence(keyring: NodeKeyring, origin: str, index: int, finding: str, confidence: float) -> dict:
    observation = TYPES[index % len(TYPES)]
    body = f"{origin}|{observation}|{finding}|{confidence}".encode()
    return {"origin": origin, "observation": observation, "finding": finding,
            "confidence": confidence, "body": body, "signature": keyring.sign(origin, body)}


def run_cell(n: int, k: int, attack: str) -> dict:
    if attack not in ATTACKS:
        raise ValueError(f"attack must be one of: {', '.join(ATTACKS)}")
    if n < 4 or not 0 <= k <= n:
        raise ValueError("need n >= 4 and 0 <= k <= n")
    f = (n - 1) // 3
    quorum = 2 * f + 1
    nodes = [f"n{i}" for i in range(n)]
    bad = nodes[:k]                      # worst case: compromised set includes the initial primary
    honest = nodes[k:]
    keyring = NodeKeyring.generate(nodes)
    truth = ATTACKS[attack]["truth"]
    trust = {node: INITIAL_TRUST for node in nodes}

    evidence = []
    for i, node in enumerate(honest):
        evidence.append(_evidence(keyring, node, i, "anomaly" if truth == "genuine" else "normal",
                                  .88 if truth == "genuine" else .95))
    for i, node in enumerate(bad):
        if attack == "false-accuse":
            evidence.append(_evidence(keyring, node, i, "anomaly", .98))
        elif attack == "block":
            evidence.append(_evidence(keyring, node, i, "normal", .99))
        # silent: nothing emitted

    policy_value = "CONTAIN" if _gate(keyring, evidence, f, trust) else "NOOP"
    if k >= quorum and attack == "false-accuse":
        committed, value, note = True, "CONTAIN", "attackers alone form a 2f+1 quorum; PBFT assumption violated"
    else:
        consensus = PBFTConsensus(nodes, keyring, f)
        result = consensus.decide(
            policy_value,
            byzantine=set(bad) if attack != "silent" else set(),
            silent=set(bad) if attack == "silent" else set(),
            block_primary=(attack == "block" and k > 0))
        committed, value = result.committed, result.value
        note = "; ".join(result.events[-1:])
    contained = committed and value == "CONTAIN"
    genuine = truth == "genuine"
    outcome = {
        "n": n, "f": f, "k": k, "attack": attack, "truth": truth,
        "within_theoretical_tolerance": k <= f,
        "decision": "contain" if contained else "withhold",
        "false_isolation": contained and not genuine,
        "missed_containment": (not contained) and genuine,
        "correct": contained == genuine,
        "note": note,
    }
    if attack == "false-accuse" and k > 0:
        normal_quorum = len(honest) >= quorum
        rounds_to_downweight = None
        if normal_quorum:
            level, rounds = INITIAL_TRUST, 0
            while .98 * level / 100.0 >= MIN_EVIDENCE_SCORE and level > 0:
                level = max(0, level - UNSUPPORTED_CLAIM_TRUST_PENALTY)
                rounds += 1
            rounds_to_downweight = rounds
        outcome["accuser_detected_by_trust_decay"] = normal_quorum
        outcome["rounds_until_accuser_evidence_cannot_alone_meet_threshold"] = rounds_to_downweight
    return outcome


def _boundaries(cells: list[dict], f: int) -> dict:
    failing = [c["k"] for c in cells if not c["correct"]]
    first = min(failing) if failing else None
    return {"theoretical_f": f,
            "first_failing_k": first,
            "largest_correct_k": (first - 1) if first else max(c["k"] for c in cells),
            "matches_theory": first == f + 1 if first is not None else None,
            "exceeds_theory": first is not None and first > f + 1}


def run_boundary_sweep(sizes: tuple[int, ...] = DEFAULT_SIZES) -> dict:
    for n in sizes:
        if n < 4 or n > 16:
            raise ValueError("committee sizes must be between 4 and 16")
    sweeps = []
    for n in sizes:
        f = (n - 1) // 3
        by_attack = {}
        for attack in ATTACKS:
            cells = [run_cell(n, k, attack) for k in range(0, 2 * f + 2)]
            by_attack[attack] = {"cells": cells, **_boundaries(cells, f)}
        sweeps.append({"n": n, "f": f, "attacks": by_attack})

    centralized = []
    for attack, mode, scenario in (("false-accuse", "false-accuse", "healthy-window"),
                                   ("silent", "silent", "genuine-compromise"),
                                   ("block", "block", "genuine-compromise")):
        report = CentralizedController(mode).run(scenario)
        centralized.append({"attack": attack, "controller_compromised": True,
                            "decision": report["decision"],
                            "false_isolation": report["metrics"]["false_isolation"],
                            "missed_containment": report["metrics"]["missed_containment"],
                            "correct": not (report["metrics"]["false_isolation"]
                                            or report["metrics"]["missed_containment"])})
    return {
        "experiment": "fault-tolerance-boundary-sweep",
        "sweeps": sweeps,
        "centralized_controller_compromised": centralized,
        "reintegration_integrity": _reintegration_integrity(),
        "limitations": [
            "Synthetic evidence and modeled PBFT; nothing here exercises real exploits or wall-clock timing.",
            "Compromised nodes always include the initial primary (worst case for liveness).",
            "Byzantine replicas withhold or refuse; equivocation is not modeled beyond the k >= 2f+1 assumption stated in the module docs.",
            "Failures at k <= f would indicate a defect; failures at k > f are expected and reported, not hidden.",
        ],
    }


def _reintegration_integrity() -> dict:
    from .engine import ResilienceSimulator
    distributed = ResilienceSimulator().run("genuine-compromise", tainted_restore=True)["metrics"]
    central = CentralizedController("rubber-stamp").run("genuine-compromise", tainted_restore=True)["metrics"]
    return {
        "case": "restored workload is still compromised (tainted)",
        "distributed": {"false_reintegration": distributed["false_reintegration"],
                        "recovery_success": distributed["recovery_success"]},
        "centralized_compromised_controller": {"false_reintegration": central["false_reintegration"],
                                               "recovery_success": central["recovery_success"]},
    }
