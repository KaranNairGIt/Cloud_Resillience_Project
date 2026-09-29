"""Live-validation orchestration tested against a scripted fake cluster on a virtual clock."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from resilience.live_validation import EXPECTATIONS, LiveValidator, parse_json_output  # noqa: E402

STAGES = ["restricted", "monitored", "peer-validated", "full"]


class VirtualClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


class FakeProc:
    def __init__(self, cluster, finish_at, payload, finish_stage):
        self.cluster, self.finish_at, self.payload, self.finish_stage = cluster, finish_at, payload, finish_stage

    def done(self):
        return self.cluster.clock.t >= self.finish_at

    def output(self):
        self.cluster.stage, self.cluster.incident = self.finish_stage, None
        return 0, "warning: noise\n" + json.dumps(self.payload), ""


class FakeCluster:
    """Answers kubectl calls; models isolate -> restore timing and the 30 s window rule."""

    def __init__(self, clock, *, tools=("kubectl", "minikube"), ready=True, cni=True,
                 wrong_scenarios=(), leak_to_full=False):
        self.clock, self.tools, self.ready, self.cni = clock, set(tools), ready, cni
        self.wrong, self.leak = set(wrong_scenarios), leak_to_full
        self.stage, self.incident = "unset", None
        self.windows, self.last_window = 0, None
        self.calls = []

    def available(self, name):
        return name in self.tools

    def _tick(self):
        self.clock.t += .05

    def _current_stage(self):
        if self.incident:
            start = self.incident
            if self.clock.t >= start + 8:
                return "restricted"
            if self.clock.t >= start + 2:
                return "quarantined"
        return self.stage

    def run(self, argv, timeout=60):
        self._tick()
        self.calls.append(argv)
        text = " ".join(argv)
        if argv[:3] == ["kubectl", "get", "nodes"]:
            return 0, "node ok", ""
        if "deployments" in text and "-n resilience -o" in text:
            status = {"readyReplicas": 1 if self.ready else 0}
            items = [{"metadata": {"name": f"resilience-peer-{n}"}, "spec": {"replicas": 1}, "status": status}
                     for n in ("portal", "identity", "records", "database")]
            return 0, json.dumps({"items": items}), ""
        if "deployment resilience-demo-records" in text:
            return 0, json.dumps({"status": {"readyReplicas": 1}}), ""
        if "networkpolicy" in text:
            return 0, json.dumps({"metadata": {"annotations": {"resilience.demo/stage": self._current_stage()}}}), ""
        if "kube-system" in text:
            return 0, "pod/calico-node-abc\n" if self.cni else "pod/kindnet-x\n", ""
        if "healthy-window" in text:
            return 0, json.dumps({"response": self._window()}), ""
        for scenario in EXPECTATIONS:
            if f"simulate {scenario}" in text:
                return 0, json.dumps(self._consensus(scenario)), ""
        return 1, "", "unexpected command: " + text

    def _consensus(self, scenario):
        value, committed = EXPECTATIONS[scenario]
        if scenario in self.wrong:
            value, committed = ("CONTAIN", True) if scenario == "false-evidence" else (None, False)
        return {"scenario": scenario, "consensus": {"committed": committed, "value": value}}

    def _window(self):
        now = self.clock.t
        if self.last_window is not None and now - self.last_window < 30:
            return {"status": "window-not-elapsed", "seconds_remaining": round(30 - (now - self.last_window), 1)}
        self.last_window, self.windows = now, self.windows + 1
        index = min(self.windows // 2, 3)
        self.stage = STAGES[index]
        return {"status": "fully-reintegrated" if self.stage == "full" else "reintegration-pending",
                "current_stage": self.stage}

    def start(self, argv):
        self._tick()
        text = " ".join(argv)
        self.incident = self.clock.t
        tainted = "--fail-check" in text
        if tainted:
            payload = {"consensus": {"committed": True, "value": "CONTAIN"},
                       "response": {"status": "restricted-validation-failed"}}
            final = "full" if self.leak else "restricted"
        else:
            payload = {"consensus": {"committed": True, "value": "CONTAIN"},
                       "response": {"status": "reintegration-pending"}}
            final = "restricted"
            self.windows, self.last_window = 0, None
        return FakeProc(self, self.clock.t + 10, payload, final)


def make(**kwargs):
    clock = VirtualClock()
    cluster = FakeCluster(clock, **kwargs)
    validator = LiveValidator(runner=cluster, clock=clock, sleep=clock.sleep, poll_interval=.25,
                              min_window_seconds=30)
    return validator, cluster, clock


class LiveValidationTests(unittest.TestCase):
    def test_full_run_measures_isolation_restore_and_trust_recovery(self):
        validator, cluster, _ = make()
        report = validator.run_all()
        self.assertEqual(report["status"], "passed", report["summary"])
        incident = report["baseline_incident"]
        self.assertAlmostEqual(incident["time_to_isolate_seconds"], 2.0, delta=.6)
        self.assertAlmostEqual(incident["time_to_restore_seconds"], 8.0, delta=.6)
        self.assertGreater(incident["end_to_end_seconds"], 9.9)
        self.assertTrue(incident["recovery_success"])
        trust = report["trust_recovery"]
        self.assertTrue(trust["reached_full"])
        self.assertEqual([p["stage"] for p in trust["promotions"]], ["monitored", "peer-validated", "full"])
        self.assertEqual(trust["counted_windows"], 6)
        self.assertGreaterEqual(trust["trust_recovery_seconds"], 5 * 30)  # spacing is really waited out
        self.assertTrue(report["summary"]["all_scenarios_match_bft_expectation"])
        self.assertFalse(report["summary"]["false_reintegration"])
        self.assertEqual(len(report["scenarios"]), 5)

    def test_early_windows_are_retried_not_counted(self):
        validator, _, _ = make()
        validator.min_window_seconds = 5  # too eager: the cluster enforces 30 s and says so
        report = validator.run_all()
        trust = report["trust_recovery"]
        self.assertTrue(trust["reached_full"])
        self.assertEqual(trust["counted_windows"], 6)
        self.assertGreater(trust["attempts"], 6)

    def test_false_reintegration_and_scenario_mismatches_are_flagged(self):
        validator, _, _ = make(leak_to_full=True, wrong_scenarios=("false-evidence", "silent-node"))
        report = validator.run_all(skip_trust_recovery=True)
        self.assertEqual(report["status"], "completed-with-findings")
        self.assertTrue(report["summary"]["false_reintegration"])
        self.assertEqual(report["summary"]["false_isolations"], 1)
        self.assertEqual(report["summary"]["missed_containments"], 1)
        self.assertFalse(report["summary"]["all_scenarios_match_bft_expectation"])
        self.assertEqual(report["trust_recovery"], {"skipped": True})

    def test_preflight_stops_before_touching_the_workload(self):
        for kwargs, failing in (({"tools": ("minikube",)}, "kubectl_installed"),
                                ({"ready": False}, "peers_ready")):
            validator, cluster, _ = make(**kwargs)
            report = validator.run_all()
            self.assertEqual(report["status"], "preflight-failed")
            self.assertFalse(report["preflight"]["checks"][failing]["ok"])
            self.assertNotIn("scenarios", report)
            self.assertFalse(any("simulate" in " ".join(c) for c in cluster.calls))

    def test_missing_networkpolicy_cni_warns_without_blocking(self):
        validator, _, _ = make(cni=False)
        preflight = validator.preflight()
        self.assertTrue(preflight["ok"])
        self.assertFalse(preflight["checks"]["networkpolicy_cni"]["ok"])
        self.assertFalse(preflight["checks"]["networkpolicy_cni"]["blocking"])

    def test_json_parsing_tolerates_kubectl_noise(self):
        self.assertEqual(parse_json_output('Defaulted container "peer"\n{"a": 1} trailing'), {"a": 1})
        self.assertIsNone(parse_json_output("no json here"))
        self.assertIsNone(parse_json_output("{broken"))


if __name__ == "__main__":
    unittest.main()
