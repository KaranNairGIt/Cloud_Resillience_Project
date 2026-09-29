"""Live Kubernetes validation: real wall-clock measurements from a running Minikube cluster.

Run *after* the deployment in docs/KUBERNETES.md is up. It drives the portal pod with
`kubectl exec`, polls the lab NetworkPolicy's stage annotation while each incident runs
(which is what makes time-to-isolate and time-to-restore measurable), then repeats clean
windows to time the full trust-recovery climb. Nothing here is a model: every number is
wall-clock time on the cluster, including `kubectl exec` overhead (about +/- 0.5 s with the
default 0.25 s poll). Detection itself is not timed separately, because the scenario injects
its synthetic evidence in-process.

The command runner, clock and sleep are injectable so the orchestration is unit-tested
without a cluster.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Callable

from .k8s_recovery import ACCESS_POLICY_NAME, LAB_NAMESPACE, STAGE_ORDER

PEERS = ("portal", "identity", "records", "database")
PORTAL = "deployment/resilience-peer-portal"
PKI_ARGS = ("--pki-dir", "/var/run/resilience-pki", "--key-dir", "/var/run/resilience-keys")
STAGE_ANNOTATION = "resilience.demo/stage"

# Expected outcome per scenario for n = 4, f = 1 (see docs/EXPERIMENTS.md).
EXPECTATIONS = {
    "genuine-compromise": ("CONTAIN", True),
    "false-evidence": ("NOOP", True),
    "silent-node": ("CONTAIN", True),   # one silent peer is within f = 1
    "block-vote": ("CONTAIN", True),    # one blocking primary is within f = 1
    "two-compromised": (None, False),   # beyond f: must NOT commit anything
}


class Proc:
    """Handle for a running command (subprocess-backed by default)."""

    def __init__(self, popen: subprocess.Popen):
        self._popen = popen

    def done(self) -> bool:
        return self._popen.poll() is not None

    def output(self) -> tuple[int, str, str]:
        out, err = self._popen.communicate()
        return self._popen.returncode, out, err


class SubprocessRunner:
    def run(self, argv: list[str], timeout: float = 60) -> tuple[int, str, str]:
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return 127, "", f"{argv[0]}: command not found"
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {timeout}s"
        return done.returncode, done.stdout, done.stderr

    def start(self, argv: list[str]) -> Proc:
        return Proc(subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))

    def available(self, name: str) -> bool:
        return shutil.which(name) is not None


def parse_json_output(text: str) -> dict | None:
    """The CLI prints one JSON document; tolerate leading noise such as kubectl warnings."""
    start = text.find("{")
    if start < 0:
        return None
    try:
        value, _ = json.JSONDecoder().raw_decode(text[start:])
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


class LiveValidator:
    def __init__(self, runner=None, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 poll_interval: float = .25, min_window_seconds: float = 30,
                 max_trust_attempts: int = 24, incident_timeout: float = 180):
        self.runner = runner or SubprocessRunner()
        self.clock, self.sleep, self.now = clock, sleep, now
        self.poll_interval = poll_interval
        self.min_window_seconds = min_window_seconds
        self.max_trust_attempts = max_trust_attempts
        self.incident_timeout = incident_timeout

    # ---- kubectl helpers -------------------------------------------------
    def _kubectl_json(self, *args: str) -> dict | None:
        code, out, _ = self.runner.run(["kubectl", *args, "-o", "json"], timeout=30)
        return parse_json_output(out) if code == 0 else None

    def _policy_stage(self) -> str | None:
        policy = self._kubectl_json("get", "networkpolicy", ACCESS_POLICY_NAME, "-n", LAB_NAMESPACE)
        if policy is None:
            return None
        return policy.get("metadata", {}).get("annotations", {}).get(STAGE_ANNOTATION, "unset")

    @staticmethod
    def _simulate_argv(scenario: str, *extra: str) -> list[str]:
        return ["kubectl", "exec", PORTAL, "-n", "resilience", "--", "python", "-m", "resilience.cli",
                "cluster", "simulate", scenario, *PKI_ARGS, "--kubernetes", *extra]

    # ---- preflight ---------------------------------------------------------
    def preflight(self) -> dict:
        checks: dict[str, dict] = {}

        def record(name: str, ok: bool, detail: str, blocking: bool = True) -> None:
            checks[name] = {"ok": ok, "detail": detail, "blocking": blocking}

        for tool in ("kubectl", "minikube"):
            present = self.runner.available(tool)
            record(f"{tool}_installed", present, "found" if present else f"{tool} is not on PATH",
                   blocking=(tool == "kubectl"))
        if checks["kubectl_installed"]["ok"]:
            code, _, err = self.runner.run(["kubectl", "get", "nodes"], timeout=30)
            record("cluster_reachable", code == 0, "reachable" if code == 0 else (err.strip()[:200] or "unreachable"))
            deployments = self._kubectl_json("get", "deployments", "-n", "resilience") if code == 0 else None
            ready = {}
            for item in (deployments or {}).get("items", []):
                status = item.get("status", {})
                ready[item["metadata"]["name"]] = (
                    status.get("readyReplicas", 0) >= item.get("spec", {}).get("replicas", 1) >= 1)
            missing = [n for n in PEERS if not ready.get(f"resilience-peer-{n}")]
            record("peers_ready", not missing, "all four peers ready" if not missing else f"not ready: {missing}")
            demo = self._kubectl_json("get", "deployment", "resilience-demo-records", "-n", LAB_NAMESPACE) if code == 0 else None
            demo_ready = bool(demo and demo.get("status", {}).get("readyReplicas", 0) >= 1)
            record("demo_workload_ready", demo_ready, "ready" if demo_ready else "resilience-demo-records is not ready")
            stage = self._policy_stage() if code == 0 else None
            record("access_policy_present", stage is not None,
                   f"stage annotation: {stage}" if stage is not None else f"{ACCESS_POLICY_NAME} not found")
            _, pods, _ = self.runner.run(["kubectl", "get", "pods", "-n", "kube-system", "-o", "name"], timeout=30)
            enforcing = any(word in pods for word in ("calico", "cilium", "weave"))
            record("networkpolicy_cni", enforcing,
                   "policy-enforcing CNI detected" if enforcing else
                   "no Calico/Cilium/Weave pods found; NetworkPolicy may not be enforced (start with --cni=calico)",
                   blocking=False)
        return {"ok": all(c["ok"] or not c["blocking"] for c in checks.values()), "checks": checks}

    # ---- measurements --------------------------------------------------------
    def run_scenario(self, scenario: str) -> dict:
        """Consensus-only run (no Kubernetes action) timed end to end."""
        start = self.clock()
        code, out, err = self.runner.run(self._simulate_argv(scenario), timeout=120)
        seconds = round(self.clock() - start, 2)
        report = parse_json_output(out)
        expected_value, expected_commit = EXPECTATIONS[scenario]
        if report is None:
            return {"scenario": scenario, "ok": False, "error": (err or out).strip()[:300],
                    "wall_seconds": seconds}
        consensus = report.get("consensus", {})
        committed, value = bool(consensus.get("committed")), consensus.get("value")
        matches = committed == expected_commit and (value == expected_value if expected_commit else not committed)
        return {"scenario": scenario, "ok": True, "wall_seconds": seconds, "committed": committed,
                "value": value, "expected_value": expected_value, "expected_commit": expected_commit,
                "matches_expectation": matches,
                "false_isolation": bool(committed and value == "CONTAIN" and scenario in ("false-evidence",)),
                "missed_containment": bool(scenario in ("genuine-compromise", "silent-node", "block-vote")
                                           and not (committed and value == "CONTAIN"))}

    def measure_incident(self, *extra: str) -> dict:
        """Genuine compromise with the Kubernetes response applied; polls the policy stage."""
        initial = self._policy_stage()
        start = self.clock()
        proc = self.runner.start(self._simulate_argv("genuine-compromise", "--apply-kubernetes-response", *extra))
        isolated_at = restored_at = None
        while True:
            elapsed = self.clock() - start
            stage = self._policy_stage()
            if stage == "quarantined" and initial != "quarantined" and isolated_at is None:
                isolated_at = elapsed
            if isolated_at is not None and restored_at is None and stage in STAGE_ORDER[1:]:
                restored_at = elapsed
            if proc.done() or elapsed > self.incident_timeout:
                break
            self.sleep(self.poll_interval)
        total = round(self.clock() - start, 2)
        code, out, err = proc.output()
        report = parse_json_output(out) or {}
        response = report.get("response", {})
        final = self._policy_stage()
        return {
            "initial_stage": initial, "final_stage": final,
            "end_to_end_seconds": total,
            "time_to_isolate_seconds": None if isolated_at is None else round(isolated_at, 2),
            "time_to_restore_seconds": None if restored_at is None else round(restored_at, 2),
            "isolation_timing_note": (None if isolated_at is not None else
                                      "not observed (workload already quarantined before the run, or poll missed it)"),
            "committed": bool(report.get("consensus", {}).get("committed")),
            "value": report.get("consensus", {}).get("value"),
            "response_status": response.get("status"),
            "recovery_success": response.get("status") in ("reintegration-pending", "fully-reintegrated"),
            "exit_code": code, "error": None if code == 0 else (err or out).strip()[:300],
        }

    def measure_trust_recovery(self) -> dict:
        """Repeat clean windows (honoring the spacing rule) until full access; time the climb."""
        start = self.clock()
        promotions: list[dict] = []
        attempts = counted = 0
        last_stage = self._policy_stage()
        final_status = None
        while attempts < self.max_trust_attempts:
            attempts += 1
            code, out, err = self.runner.run(
                self._simulate_argv("healthy-window", "--trust-target", "records", "--apply-kubernetes-response"),
                timeout=120)
            response = (parse_json_output(out) or {}).get("response", {})
            final_status = response.get("status")
            if final_status == "window-not-elapsed":
                self.sleep(float(response.get("seconds_remaining", self.min_window_seconds)) + 1)
                continue
            if code != 0 or final_status in (None, "quarantined", "conflict", "unchanged"):
                return self._trust_result(start, promotions, attempts, counted, final_status,
                                          error=(err or out).strip()[:300] or f"stopped on status {final_status}")
            counted += 1
            stage = response.get("current_stage")
            if stage and stage != last_stage:
                promotions.append({"stage": stage, "seconds_from_start": round(self.clock() - start, 2),
                                   "window": counted})
                last_stage = stage
            if final_status == "fully-reintegrated" or stage == "full":
                break
            self.sleep(self.min_window_seconds + 1)
        return self._trust_result(start, promotions, attempts, counted, final_status)

    def _trust_result(self, start: float, promotions: list, attempts: int, counted: int,
                      status: str | None, error: str | None = None) -> dict:
        reached_full = bool(promotions and promotions[-1]["stage"] == "full")
        return {"reached_full": reached_full, "counted_windows": counted, "attempts": attempts,
                "trust_recovery_seconds": round(self.clock() - start, 2) if reached_full else None,
                "promotions": promotions, "final_status": status, "error": error}

    def measure_tainted_restore(self) -> dict:
        """Post-restore health check forced to fail: workload must NOT reach full access."""
        result = self.measure_incident("--fail-check", "health")
        result["false_reintegration"] = result["final_stage"] == "full"
        result["kept_from_full_access"] = not result["false_reintegration"]
        return result

    # ---- driver ----------------------------------------------------------------
    def run_all(self, *, skip_trust_recovery: bool = False) -> dict:
        report: dict = {"experiment": "live-kubernetes-validation",
                        "started_at": self.now().isoformat(),
                        "measurement_source": "wall-clock on a running cluster (includes kubectl exec overhead)",
                        "poll_interval_seconds": self.poll_interval,
                        "min_window_seconds": self.min_window_seconds}
        report["preflight"] = self.preflight()
        if not report["preflight"]["ok"]:
            report["status"] = "preflight-failed"
            report["finished_at"] = self.now().isoformat()
            return report
        report["scenarios"] = [self.run_scenario(s) for s in EXPECTATIONS]
        report["baseline_incident"] = self.measure_incident()
        if skip_trust_recovery:
            report["trust_recovery"] = {"skipped": True}
        else:
            report["trust_recovery"] = self.measure_trust_recovery()
        report["tainted_restore"] = self.measure_tainted_restore()
        scenarios_ok = all(s.get("matches_expectation") for s in report["scenarios"])
        report["summary"] = {
            "all_scenarios_match_bft_expectation": scenarios_ok,
            "false_isolations": sum(bool(s.get("false_isolation")) for s in report["scenarios"]),
            "missed_containments": sum(bool(s.get("missed_containment")) for s in report["scenarios"]),
            "recovery_success": report["baseline_incident"]["recovery_success"],
            "false_reintegration": report["tainted_restore"]["false_reintegration"],
            "time_to_isolate_seconds": report["baseline_incident"]["time_to_isolate_seconds"],
            "time_to_restore_seconds": report["baseline_incident"]["time_to_restore_seconds"],
            "trust_recovery_seconds": report["trust_recovery"].get("trust_recovery_seconds"),
        }
        report["status"] = "passed" if (scenarios_ok and report["summary"]["recovery_success"]
                                        and not report["summary"]["false_reintegration"]) else "completed-with-findings"
        report["finished_at"] = self.now().isoformat()
        return report


def write_report(report: dict, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = directory / f"live-validation-{stamp}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path
