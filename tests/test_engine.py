import unittest
from http.server import ThreadingHTTPServer
from threading import Thread
import http.client
import json
from unittest import mock
import os
from contextlib import closing
import sqlite3
from pathlib import Path
import ssl
import tempfile

from resilience.engine import ResilienceSimulator
from resilience.experiments import run_experiment
from resilience.dashboard import make_handler
from resilience.health_records import database_path, health_summary
from resilience.consensus import PBFTConsensus, PBFTMessage
from resilience.crypto_keys import NodeKeyring
from resilience.peer_transport import (PeerRejectedError, PeerUnavailableError,
                                       create_mtls_server, send_mtls_message,
                                       send_peer_json)
from resilience.pki_tools import generate_dev_pki
from resilience.replica import PBFTReplica, ProtocolError
from resilience.cluster import NetworkPBFTCluster
from resilience.recovery import RecoveryWorkflow
from resilience.k8s_recovery import KubernetesAPIError, KubernetesRecoveryAdapter, WORKLOAD_NAME, ACCESS_POLICY_NAME
from resilience import demo_workload


class FakeKubernetesAPI:
    def __init__(self, fail_ready=False):
        self.fail_ready = fail_ready
        self.policy_stages = []
        self.paths = []
        self.policy = {"metadata": {"annotations": {}}, "spec": {}}
        self.deployment = {
            "metadata": {"name": WORKLOAD_NAME, "namespace": "resilience-lab",
                         "generation": 1},
            "spec": {"template": {"spec": {"containers": [{"name": "untrusted",
                                                                       "image": "bad:tag"}]}}},
            "status": {"observedGeneration": 1, "updatedReplicas": 1,
                       "readyReplicas": 1, "availableReplicas": 1},
        }

    def request(self, method, path, payload=None):
        self.paths.append((method, path))
        if path.endswith("/networkpolicies/" + ACCESS_POLICY_NAME):
            self.assert_safe_path(path)
            if method == "GET":
                return self.policy
            annotations = payload.get("metadata", {}).get("annotations", {})
            self.policy["metadata"]["annotations"].update(annotations)
            if "spec" in payload:
                self.policy["spec"] = payload["spec"]
                self.policy_stages.append(annotations.get("resilience.demo/stage"))
            return self.policy
        if path.endswith("/deployments/" + WORKLOAD_NAME) and method == "PATCH":
            self.assert_safe_path(path)
            self.deployment["spec"]["replicas"] = payload["spec"]["replicas"]
            self.deployment["spec"]["template"]["metadata"] = payload["spec"]["template"]["metadata"]
            self.deployment["spec"]["template"]["spec"]["containers"] = payload["spec"]["template"]["spec"]["containers"]
            self.deployment["metadata"]["generation"] += 1
            self.deployment["status"]["observedGeneration"] = self.deployment["metadata"]["generation"]
            return self.deployment
        if path.endswith("/deployments/" + WORKLOAD_NAME) and method == "GET":
            self.assert_safe_path(path)
            if self.fail_ready:
                raise RuntimeError("synthetic rollout failure")
            return self.deployment
        raise AssertionError(f"unexpected Kubernetes API request: {method} {path}")

    @staticmethod
    def assert_safe_path(path):
        assert path.startswith("/apis/") and "/namespaces/resilience-lab/" in path
        assert (path.endswith("/deployments/" + WORKLOAD_NAME)
                or path.endswith("/networkpolicies/" + ACCESS_POLICY_NAME))


class SimulatorTests(unittest.TestCase):
    def test_new_primary_requires_and_presents_a_signed_view_change_certificate(self):
        nodes = ["portal", "identity", "records", "database"]
        ring = NodeKeyring.generate(nodes)
        replicas = {node: PBFTReplica(node, ring, nodes, max_faults=1) for node in nodes}
        proposal = {"value": "NOOP", "target": "records",
                    "scenario": "false-evidence", "evidence": []}
        for replica in replicas.values():
            replica.cache_proposal(55, proposal)
        changes = [replicas[node].create_view_change_bundle(55, 1) for node in nodes[:3]]
        for bundle in changes:
            replicas["identity"].handle_message(
                PBFTMessage(**bundle["message"]),
                prepared_certificate=bundle["prepared_certificate"])
        new_view = replicas["identity"].create_new_view(55, 1)
        message = PBFTMessage(**new_view["message"])
        with self.assertRaises(ProtocolError):
            replicas["records"].handle_message(message, certificate=new_view["certificate"][:2])
        accepted = replicas["records"].handle_message(message,
                                                       certificate=new_view["certificate"])
        self.assertEqual(accepted["phase"], "NEW-VIEW")
        self.assertEqual(replicas["records"].state_report(55)["view"], 1)

    def test_new_view_preserves_highest_prepared_value_with_signed_certificate(self):
        nodes = ["portal", "identity", "records", "database"]
        ring = NodeKeyring.generate(nodes)
        replicas = {node: PBFTReplica(node, ring, nodes, max_faults=1) for node in nodes}
        proposal = {"value": "NOOP", "target": "records",
                    "scenario": "false-evidence", "evidence": []}
        digest = PBFTReplica.proposal_digest(proposal)
        for replica in replicas.values():
            replica.cache_proposal(56, proposal)
        prepares = []
        for node in nodes[:3]:
            unsigned = PBFTMessage(node, "PREPARE", 0, 56, digest, "")
            prepares.append(PBFTMessage(node, "PREPARE", 0, 56, digest,
                                        ring.sign(node, unsigned.payload()).hex()))
        for replica in replicas.values():
            replica.rounds[56].prepares = {item.sender: item for item in prepares}
        changes = [replicas[node].create_view_change_bundle(56, 1) for node in nodes[:3]]
        self.assertTrue(all(len(bundle["prepared_certificate"]) == 3
                            for bundle in changes))
        tampered = {**changes[0], "prepared_certificate": changes[0]["prepared_certificate"][:2]}
        with self.assertRaises(ProtocolError):
            replicas["identity"].handle_message(
                PBFTMessage(**tampered["message"]),
                prepared_certificate=tampered["prepared_certificate"])
        for bundle in changes:
            replicas["identity"].handle_message(
                PBFTMessage(**bundle["message"]),
                prepared_certificate=bundle["prepared_certificate"])
        new_view = replicas["identity"].create_new_view(56, 1)
        self.assertEqual(len(new_view["certificate"]), 3)
        self.assertEqual(new_view["prepared_certificate_signers"], sorted(nodes[:3]))
        self.assertEqual(new_view["selected_digest"], digest)
        self.assertTrue(all(len(item["prepared_certificate"]) == 3
                            for item in new_view["certificate"]))
        accepted = replicas["records"].handle_message(
            PBFTMessage(**new_view["message"]), certificate=new_view["certificate"])
        self.assertEqual(accepted["phase"], "NEW-VIEW")
        self.assertEqual(replicas["records"].rounds[56].digest, digest)

    def test_duplicate_prepare_returns_the_same_commit_after_response_loss(self):
        nodes = ["portal", "identity", "records", "database"]
        ring = NodeKeyring.generate(nodes)
        replica = PBFTReplica("portal", ring, nodes, max_faults=1)
        proposal = {"value": "NOOP", "target": "records",
                    "scenario": "false-evidence", "evidence": []}
        replica.cache_proposal(57, proposal)
        digest = replica.proposal_digest(proposal)
        primary = replica._sign("PRE-PREPARE", 0, 57, digest)
        replica.handle_message(primary, proposal)
        external = []
        for node in nodes[1:3]:
            unsigned = PBFTMessage(node, "PREPARE", 0, 57, digest, "")
            external.append(PBFTMessage(node, "PREPARE", 0, 57, digest,
                                        ring.sign(node, unsigned.payload()).hex()))
        for message in external:
            first_response = replica.handle_message(message)
        self.assertIsNotNone(first_response["commit"])
        retried_response = replica.handle_message(external[-1])
        self.assertEqual(retried_response["commit"], first_response["commit"])

    def test_uncommitted_proposal_does_not_advance_committed_sequence_watermark(self):
        nodes = ["portal", "identity", "records", "database"]
        ring = NodeKeyring.generate(nodes)
        replica = PBFTReplica("portal", ring, nodes, max_faults=1)
        proposal = {"value": "NOOP", "target": "records",
                    "scenario": "false-evidence", "evidence": []}
        replica.cache_proposal(999, proposal)
        self.assertEqual(replica.highest_committed_sequence, 0)
        lower_proposal = {**proposal, "scenario": "genuine-compromise"}
        replica.cache_proposal(1, lower_proposal)
        self.assertEqual(replica.highest_committed_sequence, 0)

    def test_only_authenticated_current_primary_can_pre_cache_proposal(self):
        root = Path(__file__).resolve().parent.parent
        certs = Path(generate_dev_pki(root / "work" / "proposal-auth-test", force=True)["directory"])
        nodes = ["portal", "identity", "records", "database"]
        ring = NodeKeyring.generate(nodes)
        replica = PBFTReplica("portal", ring, nodes, max_faults=1)
        server = create_mtls_server("127.0.0.1", 0, str(certs / "portal.crt"),
                                    str(certs / "portal.key"), str(certs / "ca.crt"),
                                    replica=replica)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        proposal = {"value": "NOOP", "target": "records",
                    "scenario": "false-evidence", "evidence": []}
        try:
            with self.assertRaises(PeerRejectedError):
                send_peer_json("127.0.0.1", server.server_port,
                               str(certs / "ca.crt"), str(certs / "identity.crt"),
                               str(certs / "identity.key"), "/v1/proposal",
                               {"sequence": 999, "proposal": proposal})
            send_peer_json("127.0.0.1", server.server_port,
                           str(certs / "ca.crt"), str(certs / "portal.crt"),
                           str(certs / "portal.key"), "/v1/proposal",
                           {"sequence": 999, "proposal": proposal})
            self.assertEqual(replica.highest_committed_sequence, 0)
            send_peer_json("127.0.0.1", server.server_port,
                           str(certs / "ca.crt"), str(certs / "portal.crt"),
                           str(certs / "portal.key"), "/v1/proposal",
                           {"sequence": 1, "proposal": {**proposal,
                                                           "scenario": "genuine-compromise"}})
            self.assertEqual(replica.highest_committed_sequence, 0)
        finally:
            server.shutdown()
            server.server_close()

    def test_coordinator_retries_transient_transport_failure_with_a_bound(self):
        cluster = NetworkPBFTCluster.__new__(NetworkPBFTCluster)
        cluster.max_request_attempts = 2
        cluster.unavailable = {}
        calls = []

        def flaky_request(node, path, body=None):
            calls.append(node)
            if len(calls) == 1:
                raise PeerUnavailableError("temporary 503")
            return {"ready": True}

        cluster._request = flaky_request
        self.assertEqual(cluster._try_request("identity", "/healthz"), {"ready": True})
        self.assertEqual(calls, ["identity", "identity"])
        self.assertEqual(cluster.unavailable, {})

        bounded = NetworkPBFTCluster.__new__(NetworkPBFTCluster)
        bounded.max_request_attempts = 2
        bounded.unavailable = {}
        failures = []

        def down_request(node, path, body=None):
            failures.append(node)
            raise PeerUnavailableError("still unavailable")

        bounded._request = down_request
        self.assertIsNone(bounded._try_request("database", "/healthz"))
        self.assertEqual(failures, ["database", "database"])
        self.assertIn("database", bounded.unavailable)

    def test_one_byzantine_high_sequence_report_cannot_veto_coordinator(self):
        reports = {"portal": {"highest_committed_sequence": 44},
                   "identity": {"highest_committed_sequence": 44},
                   "records": {"highest_committed_sequence": 44},
                   "database": {"highest_committed_sequence": 9000000}}
        votes = NetworkPBFTCluster._stale_sequence_votes(100, reports)
        self.assertEqual(votes, {"database": 9000000})
        self.assertLess(len(votes), 3)
        stale_votes = NetworkPBFTCluster._stale_sequence_votes(44, reports)
        self.assertEqual(len(stale_votes), 4)

    def test_trust_score_uses_quorum_agreement_and_ignores_one_false_report(self):
        states = {
            "portal": {"trust_scores": {"portal": 55}},
            "identity": {"trust_scores": {"portal": 55}},
            "records": {"trust_scores": {"portal": 55}},
            "database": {"trust_scores": {"portal": 100}},
        }
        scores = NetworkPBFTCluster._quorum_trust_scores(states, required=3)
        self.assertEqual(scores["portal"], 55)

        states["records"]["trust_scores"]["portal"] = 54
        scores = NetworkPBFTCluster._quorum_trust_scores(states, required=3)
        self.assertEqual(scores["portal"], 0)

    def test_checkpoint_transfer_requires_commit_certificate_and_survives_restart(self):
        root = Path(__file__).resolve().parent.parent
        (root / "work").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root / "work", prefix="checkpoint-test-") as temp_dir:
            nodes = ["portal", "identity", "records", "database"]
            ring = NodeKeyring.generate(nodes)
            source = PBFTReplica("portal", ring, nodes, max_faults=1)
            proposal = {"value": "NOOP", "target": "records",
                        "scenario": "false-evidence", "evidence": []}
            sequence = 89
            source.cache_proposal(sequence, proposal)
            digest = source.proposal_digest(proposal)
            source.handle_message(source._sign("PRE-PREPARE", 0, sequence, digest), proposal)
            prepares = []
            commits = []
            for node in nodes[1:3]:
                unsigned_prepare = PBFTMessage(node, "PREPARE", 0, sequence, digest, "")
                prepares.append(PBFTMessage(
                    node, "PREPARE", 0, sequence, digest,
                    ring.sign(node, unsigned_prepare.payload()).hex()))
                unsigned_commit = PBFTMessage(node, "COMMIT", 0, sequence, digest, "")
                commits.append(PBFTMessage(
                    node, "COMMIT", 0, sequence, digest,
                    ring.sign(node, unsigned_commit.payload()).hex()))
            for message in prepares:
                source.handle_message(message)
            for message in commits:
                source.handle_message(message)
            self.assertTrue(source.state_report(sequence)["committed"])

            target = PBFTReplica("database", ring, nodes, max_faults=1,
                                 state_db=Path(temp_dir) / "database.sqlite3")
            checkpoint = source.latest_checkpoint()
            self.assertEqual(checkpoint["sequence"], sequence)
            with self.assertRaisesRegex(ProtocolError, "checkpoint validation failed"):
                target.install_checkpoint({"sequence": sequence,
                    "snapshot": {**checkpoint["snapshot"], "committed": True,
                                 "commits": {}}})
            self.assertEqual(target.highest_committed_sequence, 0)
            installed = target.install_checkpoint(checkpoint)
            self.assertTrue(installed["installed"])
            self.assertEqual(target.highest_committed_sequence, sequence)
            restarted = PBFTReplica("database", ring, nodes, max_faults=1,
                                    state_db=Path(temp_dir) / "database.sqlite3")
            self.assertTrue(restarted.state_report(sequence)["committed"])
            self.assertEqual(restarted.highest_committed_sequence, sequence)

    def test_replica_state_survives_restart_and_rejects_tampered_disk_snapshot(self):
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=root / "work", prefix="persist-test-") as temp_dir:
            db_path = Path(temp_dir) / "portal.sqlite3"
            ring = NodeKeyring.generate(["portal", "identity", "records", "database"])
            replica = PBFTReplica("portal", ring, state_db=db_path)
            proposal = {"value": "NOOP", "target": "records",
                        "scenario": "false-evidence", "evidence": []}
            replica.cache_proposal(77, proposal)
            digest = replica.proposal_digest(proposal)
            replica.handle_message(replica._sign("PRE-PREPARE", 0, 77, digest), proposal)
            prepares = []
            commits = []
            for node in ("identity", "records"):
                prepare = PBFTMessage(node, "PREPARE", 0, 77, digest, "")
                prepares.append(PBFTMessage(
                    node, "PREPARE", 0, 77, digest,
                    ring.sign(node, prepare.payload()).hex()))
                commit = PBFTMessage(node, "COMMIT", 0, 77, digest, "")
                commits.append(PBFTMessage(
                    node, "COMMIT", 0, 77, digest,
                    ring.sign(node, commit.payload()).hex()))
            for prepare in prepares:
                replica.handle_message(prepare)
            for commit in commits:
                replica.handle_message(commit)
            self.assertTrue(replica.state_report(77)["committed"])
            restarted = PBFTReplica("portal", ring, state_db=db_path)
            self.assertEqual(restarted.rounds[77].proposal, proposal)
            self.assertEqual(restarted.highest_committed_sequence, 77)
            with self.assertRaisesRegex(ProtocolError, "stale sequence"):
                restarted.cache_proposal(76, proposal)
            db = sqlite3.connect(db_path)
            try:
                encoded = db.execute("SELECT state_json FROM rounds WHERE sequence=77").fetchone()[0]
                snapshot = json.loads(encoded)
                snapshot["digest"] = "0" * 64
                db.execute("UPDATE rounds SET state_json=? WHERE sequence=77",
                           (json.dumps(snapshot),))
                db.commit()
            finally:
                db.close()
            with self.assertRaisesRegex(ValueError, "signed journal entry"):
                PBFTReplica("portal", ring, state_db=db_path)

    def test_replica_state_journal_rejects_tampered_transition(self):
        root = Path(__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory(dir=root / "work", prefix="journal-test-") as temp_dir:
            db_path = Path(temp_dir) / "portal.sqlite3"
            ring = NodeKeyring.generate(["portal", "identity", "records", "database"])
            replica = PBFTReplica("portal", ring, state_db=db_path)
            proposal = {"value": "NOOP", "target": "records",
                        "scenario": "false-evidence", "evidence": []}
            replica.cache_proposal(78, proposal)
            db = sqlite3.connect(db_path)
            try:
                encoded = db.execute("SELECT body FROM journal WHERE id=1").fetchone()[0]
                tampered = json.loads(encoded)
                tampered["committed"] = True
                db.execute("UPDATE journal SET body=? WHERE id=1",
                           (json.dumps(tampered, sort_keys=True, separators=(",", ":")),))
                db.commit()
            finally:
                db.close()
            with self.assertRaisesRegex(ValueError, "signature or hash is invalid"):
                PBFTReplica("portal", ring, state_db=db_path)

    def test_demo_attack_endpoint_only_flips_and_reports_synthetic_state(self):
        demo_workload.ATTACK_STATE["active"] = False
        server = ThreadingHTTPServer(("127.0.0.1", 0), demo_workload.DemoHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request("GET", "/behavior")
            normal = json.loads(connection.getresponse().read())
            self.assertEqual(normal["status"], "normal")
            connection.request("POST", "/simulate/attack", body="{}",
                               headers={"Content-Type": "application/json"})
            injected = json.loads(connection.getresponse().read())
            self.assertEqual(injected["effect"], "in-memory demo flag only")
            connection.request("GET", "/behavior")
            anomaly = json.loads(connection.getresponse().read())
            self.assertEqual(anomaly["status"], "anomalous")
            self.assertEqual(anomaly["records"], "synthetic-only")
        finally:
            demo_workload.ATTACK_STATE["active"] = False
            connection.close()
            server.shutdown()
            server.server_close()

    def test_recovery_requires_committed_containment_and_validates_before_reintegration(self):
        workflow = RecoveryWorkflow()
        denied = workflow.run(consensus_committed=True, value="NOOP", target="records")
        self.assertFalse(denied["executed"])
        failed = workflow.run(consensus_committed=True, value="CONTAIN", target="records",
                              validation={"integrity": True, "health": False, "behavior": True})
        self.assertEqual(failed["status"], "quarantined")
        self.assertEqual(failed["failed_checks"], ["health"])
        self.assertFalse(failed["available"])
        recovered = workflow.run(consensus_committed=True, value="CONTAIN", target="records")
        self.assertEqual(recovered["status"], "fully-reintegrated")
        self.assertEqual(recovered["reintegration_stages"],
                         ["quarantine", "restricted", "monitored", "peer-validated", "full"])

    def test_kubernetes_recovery_is_confined_to_demo_and_gates_reintegration(self):
        api = FakeKubernetesAPI()
        adapter = KubernetesRecoveryAdapter(
            api=api,
            probe=lambda path: ({"status": "healthy"} if path == "/healthz"
                                else {"status": "normal", "records": "synthetic-only"}),
            rollout_timeout=1, poll_interval=0, min_window_interval=0)
        denied = adapter.run(consensus_committed=True, value="CONTAIN", target="identity")
        self.assertFalse(denied["executed"])
        self.assertEqual(api.policy_stages, [])
        recovered = adapter.run(consensus_committed=True, value="CONTAIN", target="records",
                                 trust_score=55)
        self.assertEqual(recovered["namespace"], "resilience-lab")
        self.assertEqual(recovered["status"], "reintegration-pending")
        self.assertEqual(api.policy_stages, ["quarantined", "restricted"])
        for window, score in enumerate((60, 65, 70, 75, 80, 85, 90, 95), start=1):
            advanced = adapter.advance_trust_window(
                consensus_committed=True, value="NOOP", target="records",
                trust_score=score, healthy_window_committed=True)
            expected_stage = ("monitored" if window >= 2 else "restricted")
            if window >= 5:
                expected_stage = "peer-validated"
            if window == 8:
                expected_stage = "full"
            self.assertEqual(advanced["current_stage"], expected_stage)
        self.assertEqual(advanced["status"], "fully-reintegrated")
        self.assertEqual(api.policy["metadata"]["annotations"]["resilience.demo/stage"], "full")

    @staticmethod
    def _healthy_probe(path):
        return ({"status": "healthy"} if path == "/healthz"
                else {"status": "normal", "records": "synthetic-only"})

    def test_kubernetes_clean_windows_must_be_separated_in_time(self):
        api = FakeKubernetesAPI()
        now = [1000.0]
        adapter = KubernetesRecoveryAdapter(
            api=api, probe=SimulatorTests._healthy_probe, rollout_timeout=1, poll_interval=0,
            min_window_interval=30, clock=lambda: now[0])
        adapter.run(consensus_committed=True, value="CONTAIN", target="records", trust_score=70)
        annotations = api.policy["metadata"]["annotations"]
        self.assertIsNone(annotations["resilience.demo/last-window-at"])

        def advance():
            return adapter.advance_trust_window(
                consensus_committed=True, value="NOOP", target="records",
                trust_score=70, healthy_window_committed=True)

        first = advance()
        self.assertEqual(first["clean_windows"], 1)
        # A burst of triggers must not count: nothing changes and nothing is locked down.
        for _ in range(5):
            burst = advance()
            self.assertEqual(burst["status"], "window-not-elapsed")
            self.assertFalse(burst["executed"])
        self.assertEqual(api.policy["metadata"]["annotations"]["resilience.demo/stage"], "restricted")
        self.assertEqual(api.policy["metadata"]["annotations"]["resilience.demo/clean-windows"], "1")
        now[0] += 10
        self.assertEqual(advance()["seconds_remaining"], 20.0)
        now[0] += 21
        promoted = advance()
        self.assertEqual(promoted["current_stage"], "monitored")
        # Re-containment wipes the timing state as well as the streak.
        adapter.run(consensus_committed=True, value="CONTAIN", target="records", trust_score=70)
        self.assertIsNone(api.policy["metadata"]["annotations"]["resilience.demo/last-window-at"])

    def test_kubernetes_future_window_timestamp_fails_closed(self):
        api = FakeKubernetesAPI()
        adapter = KubernetesRecoveryAdapter(
            api=api, probe=SimulatorTests._healthy_probe, rollout_timeout=1, poll_interval=0,
            min_window_interval=30, clock=lambda: 1000.0)
        adapter.run(consensus_committed=True, value="CONTAIN", target="records", trust_score=70)
        api.policy["metadata"]["annotations"]["resilience.demo/last-window-at"] = "999999.0"
        result = adapter.advance_trust_window(
            consensus_committed=True, value="NOOP", target="records",
            trust_score=70, healthy_window_committed=True)
        self.assertEqual(result["status"], "quarantined")
        self.assertFalse(result["available"])

    def test_kubernetes_concurrent_update_is_rejected_without_lockdown(self):
        class RacingAPI(FakeKubernetesAPI):
            """Another writer bumps resourceVersion between the adapter's GET and PATCH."""
            def __init__(self):
                super().__init__()
                self.version = 1
                self.race = False

            def request(self, method, path, payload=None):
                if path.endswith("/networkpolicies/" + ACCESS_POLICY_NAME):
                    if method == "GET":
                        self.policy["metadata"]["resourceVersion"] = str(self.version)
                        reply = json.loads(json.dumps(self.policy))
                        if self.race:
                            self.version += 1  # concurrent writer wins
                        return reply
                    sent = payload.get("metadata", {}).get("resourceVersion")
                    if sent is not None and sent != str(self.version):
                        raise KubernetesAPIError(409, "Operation cannot be fulfilled: conflict")
                    self.version += 1
                return super().request(method, path, payload)

        api = RacingAPI()
        adapter = KubernetesRecoveryAdapter(
            api=api, probe=SimulatorTests._healthy_probe, rollout_timeout=1, poll_interval=0,
            min_window_interval=0)
        adapter.run(consensus_committed=True, value="CONTAIN", target="records", trust_score=70)
        stages_before = list(api.policy_stages)
        api.race = True
        result = adapter.advance_trust_window(
            consensus_committed=True, value="NOOP", target="records",
            trust_score=70, healthy_window_committed=True)
        self.assertEqual(result["status"], "conflict")
        self.assertFalse(result["executed"])
        self.assertEqual(api.policy_stages, stages_before)  # no write, and no quarantine lockdown
        api.race = False
        self.assertEqual(adapter.advance_trust_window(
            consensus_committed=True, value="NOOP", target="records",
            trust_score=70, healthy_window_committed=True)["clean_windows"], 1)

    def test_kubernetes_interval_configuration_is_validated(self):
        with self.assertRaises(ValueError):
            KubernetesRecoveryAdapter(api=FakeKubernetesAPI(), min_window_interval=-1)
        with mock.patch.dict(os.environ, {"RESILIENCE_MIN_WINDOW_SECONDS": "abc"}):
            with self.assertRaises(ValueError):
                KubernetesRecoveryAdapter(api=FakeKubernetesAPI())
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("RESILIENCE_MIN_WINDOW_SECONDS", None)
            self.assertEqual(KubernetesRecoveryAdapter(api=FakeKubernetesAPI()).min_window_interval, 30.0)

    def test_kubernetes_recovery_failure_reasserts_quarantine(self):
        api = FakeKubernetesAPI(fail_ready=True)
        adapter = KubernetesRecoveryAdapter(api=api, rollout_timeout=.01, poll_interval=0)
        failed = adapter.run(consensus_committed=True, value="CONTAIN", target="records",
                             trust_score=55)
        self.assertEqual(failed["status"], "quarantined")
        self.assertEqual(api.policy_stages, ["quarantined", "quarantined"])
        self.assertIn("failure handler restored deny-all policy", failed["actions"])

    def test_four_independent_mtls_replicas_run_safe_scenario_matrix(self):
        root = Path(__file__).resolve().parent.parent
        certs = Path(generate_dev_pki(root / "work" / "network-cluster-test-pki", force=True)["directory"])
        keyring = NodeKeyring.generate(["portal", "identity", "records", "database"])
        key_root = root / "work" / "network-cluster-test-keys"
        (key_root / "private").mkdir(parents=True, exist_ok=True)
        (key_root / "public").mkdir(parents=True, exist_ok=True)
        for node in ("portal", "identity", "records", "database"):
            (key_root / "private" / f"{node}.pem").write_bytes(keyring.private_pem(node))
            (key_root / "public" / f"{node}.pub.pem").write_bytes(keyring.public_pem(node))

        servers = {}
        threads = []
        local_rings = {}
        state_temp = tempfile.TemporaryDirectory(dir=root / "work", prefix="replica-state-test-")
        state_root = Path(state_temp.name)
        try:
            for node in ("portal", "identity", "records", "database"):
                local_ring = NodeKeyring.load(
                    node, key_root / "private" / f"{node}.pem",
                    {peer: key_root / "public" / f"{peer}.pub.pem"
                     for peer in ("portal", "identity", "records", "database")})
                local_rings[node] = local_ring
                replica = PBFTReplica(node, local_ring, state_db=state_root / f"{node}.sqlite3")
                server = create_mtls_server(
                    "127.0.0.1", 0, str(certs / f"{node}.crt"),
                    str(certs / f"{node}.key"), str(certs / "ca.crt"), replica=replica)
                servers[node] = server
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            hosts = {node: "127.0.0.1" for node in servers}
            ports = {node: server.server_port for node, server in servers.items()}
            cluster = NetworkPBFTCluster(certs, hosts, ports,
                                         public_key_dir=key_root / "public")

            expected = {
                "genuine-compromise": ("CONTAIN", True, 0),
                "false-evidence": ("NOOP", True, 1),
                "silent-node": ("CONTAIN", True, 0),
                "block-vote": ("CONTAIN", True, 1),
                "two-compromised": (None, False, 0),
            }
            for sequence, (scenario, (value, committed, view)) in enumerate(expected.items(), start=101):
                with self.subTest(scenario=scenario):
                    result = cluster.run(scenario, sequence)
                    self.assertEqual(result["consensus"]["value"], value)
                    self.assertEqual(result["consensus"]["committed"], committed)
                    self.assertEqual(result["decision_parameters"]["reporter_quorum"], 3)
                    self.assertEqual(result["decision_parameters"]["minimum_weighted_evidence_score"], .60)
                    if committed:
                        self.assertEqual(result["consensus"]["view"], view)
                        self.assertTrue(all(replica["committed"] for replica in result["replicas"].values()))
                        trust_views = [replica["trust_scores"]
                                       for replica in result["replicas"].values()]
                        self.assertTrue(all(view == trust_views[0] for view in trust_views))
                        self.assertEqual(result["trust_scores_after_commit"], trust_views[0])
                    if scenario in {"false-evidence", "block-vote"}:
                        new_view = next(phase for phase in result["consensus"]["phases"]
                                        if phase["phase"] == "NEW-VIEW")
                        self.assertEqual(len(new_view["certificate_signers"]), 3)
                    if scenario == "false-evidence":
                        self.assertTrue(result["rejected_unsupported_primary_proposal"])
                        self.assertFalse(result["evidence_authorized"])
                        self.assertFalse(result["response"]["executed"])
                        self.assertEqual(result["trust_scores_after_commit"]["portal"], 55)
                        self.assertEqual(result["trust_scores_after_commit"],
                                         {"portal": 55, "identity": 85,
                                          "records": 60, "database": 85})
                        self.assertEqual({item["finding"] for item in result["proposal"]["evidence"]},
                                         {"anomaly", "normal"})
                    if scenario == "silent-node":
                        self.assertEqual(result["decision_parameters"]["reporter_trust_scores"]["portal"],
                                         55)
                    if scenario == "genuine-compromise":
                        self.assertEqual(result["response"]["status"], "fully-reintegrated")
                    if scenario == "two-compromised":
                        self.assertEqual(result["active_replicas"], ["records", "database"])
                        self.assertEqual(len(result["active_replicas"]), 2)
            failed_validation = cluster.run(
                "genuine-compromise", 106,
                {"integrity": True, "health": False, "behavior": True})
            self.assertTrue(failed_validation["consensus"]["committed"])
            self.assertEqual(failed_validation["response"]["status"], "quarantined")
            self.assertEqual(failed_validation["response"]["failed_checks"], ["health"])
            original_try_request = cluster._try_request

            def timeout_primary_once(node, path, body=None):
                if node == "portal" and path == "/v1/pre-prepare":
                    cluster.unavailable[node] = "synthetic transport timeout after proposal cache"
                    return None
                return original_try_request(node, path, body)

            cluster._try_request = timeout_primary_once
            timed_out_primary = cluster.run("genuine-compromise", 107)
            cluster._try_request = original_try_request
            self.assertTrue(timed_out_primary["consensus"]["committed"])
            self.assertEqual(timed_out_primary["consensus"]["view"], 1)
            self.assertTrue(any("primary request timed out" in event
                                for event in timed_out_primary["events"]))
            reloaded = PBFTReplica("portal", local_rings["portal"],
                                   state_db=state_root / "portal.sqlite3")
            restored_state = reloaded.state_report(101)
            self.assertTrue(restored_state["committed"])
            self.assertEqual(restored_state["value"], "CONTAIN")
            prepared_failover = cluster.run("prepared-primary-failure", 108)
            self.assertTrue(prepared_failover["consensus"]["committed"])
            self.assertEqual(prepared_failover["consensus"]["view"], 1)
            view_phase = next(phase for phase in prepared_failover["consensus"]["phases"]
                              if phase["phase"] == "NEW-VIEW")
            self.assertEqual(len(view_phase["prepared_certificate_signers"]), 3)
            self.assertEqual(view_phase["selected_prepared_digest"],
                             prepared_failover["digest"])
            unavailable_server = servers.pop("portal")
            unavailable_server.shutdown()
            unavailable_server.server_close()
            failed_primary = cluster.run("genuine-compromise", 109)
            self.assertTrue(failed_primary["consensus"]["committed"])
            self.assertEqual(failed_primary["consensus"]["view"], 1)
            self.assertIn("portal", failed_primary["unavailable_replicas"])
            self.assertEqual(len(failed_primary["active_replicas"]), 3)

            replacement = PBFTReplica("portal", local_rings["portal"],
                                      state_db=state_root / "portal-recovered.sqlite3")
            replacement_server = create_mtls_server(
                "127.0.0.1", 0, str(certs / "portal.crt"), str(certs / "portal.key"),
                str(certs / "ca.crt"), replica=replacement)
            servers["portal"] = replacement_server
            replacement_thread = Thread(target=replacement_server.serve_forever, daemon=True)
            replacement_thread.start()
            ports["portal"] = replacement_server.server_port
            cluster = NetworkPBFTCluster(certs, hosts, ports,
                                         public_key_dir=key_root / "public")

            recovered_peer = cluster.run("genuine-compromise", 110)
            self.assertTrue(recovered_peer["consensus"]["committed"])
            self.assertTrue(any("portal" in transfer["targets"]
                                for transfer in recovered_peer["checkpoint_transfers"]))
            self.assertEqual(recovered_peer["replicas"]["portal"]["highest_committed_sequence"], 110)
            self.assertEqual(replacement.trust_scores, recovered_peer["trust_scores_after_commit"])
            self.assertTrue(all(sequence in replacement.rounds and replacement.rounds[sequence].committed
                                for sequence in (101, 102, 103, 104, 106, 107, 108, 109)),
                            "state recovery should replay every committed round before the new request")

            unavailable_server = servers.pop("database")
            unavailable_server.shutdown()
            unavailable_server.server_close()
            one_peer_down = cluster.run("genuine-compromise", 111)
            self.assertTrue(one_peer_down["consensus"]["committed"])
            self.assertEqual(one_peer_down["consensus"]["value"], "CONTAIN")
            self.assertIn("database", one_peer_down["unavailable_replicas"])
            self.assertEqual(len(one_peer_down["active_replicas"]), 3)
            kube_api = FakeKubernetesAPI()
            kube_adapter = KubernetesRecoveryAdapter(
                api=kube_api,
                probe=lambda path: ({"status": "healthy"} if path == "/healthz"
                                    else {"status": "normal", "records": "synthetic-only"}),
                rollout_timeout=1, poll_interval=0, min_window_interval=0)
            initial_restore = kube_adapter.run(
                consensus_committed=True, value="CONTAIN", target="records", trust_score=55)
            self.assertEqual(initial_restore["status"], "reintegration-pending")
            cluster.apply_kubernetes_response = True
            cluster.kubernetes_adapter = kube_adapter
            trust_before_clean_window = one_peer_down["trust_scores_after_commit"]["portal"]
            clean_window = cluster.run("healthy-window", 112, trust_target="records")
            self.assertTrue(clean_window["consensus"]["committed"])
            self.assertEqual(clean_window["consensus"]["value"], "NOOP")
            self.assertEqual(clean_window["trust_window_quorum"], 3)
            self.assertEqual(clean_window["trust_scores_after_commit"]["portal"],
                             min(100, trust_before_clean_window + 5))
            self.assertEqual(clean_window["response"]["status"], "reintegration-pending")
            self.assertEqual(clean_window["response"]["trust_score"],
                             clean_window["trust_scores_after_commit"]["records"])
            self.assertEqual(kube_api.policy["metadata"]["annotations"]["resilience.demo/stage"],
                             "restricted")
            self.assertEqual(len(set(tuple(sorted(state["trust_scores"].items()))
                                     for state in clean_window["replicas"].values())), 1)
            with self.assertRaisesRegex(ValueError, "stale sequence"):
                cluster.run("genuine-compromise", 101)
        finally:
            for server in servers.values():
                server.shutdown()
                server.server_close()
            state_temp.cleanup()

    def test_signed_evidence_rejects_tampering(self):
        sim = ResilienceSimulator()
        evidence = sim._emit("portal", "records", "network", .8)
        self.assertTrue(sim.verify(evidence))
        evidence.confidence = .99
        self.assertFalse(sim.verify(evidence))

    def test_same_type_reports_do_not_stack_as_independent_evidence(self):
        sim = ResilienceSimulator()
        reports = [sim._emit(origin, "records", "network", .88)
                   for origin in ("portal", "identity", "database")]
        self.assertAlmostEqual(sim._score(reports), .704)

    def test_genuine_compromise_completes_recovery_cycle(self):
        report = ResilienceSimulator().run("genuine-compromise")
        self.assertEqual(report["decision"], "contain")
        self.assertEqual(len(report["evidence_types"]), 4)
        self.assertEqual(report["metrics"]["target_stage"], "full")
        self.assertEqual(report["metrics"]["target_trust"], 100)
        self.assertEqual(report["metrics"]["trust_recovery_windows"], 6)
        self.assertEqual(report["metrics"]["trust_recovery_time_ticks"], 6)
        self.assertEqual([step["window"] for step in report["metrics"]["trust_trajectory"]
                          if step["promotion"]], [2, 4, 6])
        self.assertEqual([step["stage"] for step in report["metrics"]["trust_trajectory"]
                          if step["promotion"]], ["monitored", "peer-validated", "full"])
        self.assertEqual(report["metrics"]["time_to_isolate_seconds"], 2)
        self.assertEqual(report["metrics"]["recovery_time_seconds"], 4)
        self.assertEqual(report["metrics"]["availability_percent"], 87.5)
        self.assertEqual(report["decision_parameters"]["committee_size_n"], 4)
        self.assertEqual(report["decision_parameters"]["byzantine_fault_limit_f"], 1)
        self.assertEqual(report["decision_parameters"]["corroborating_reporter_quorum"], 3)

    def test_trust_stage_promotion_requires_two_sustained_healthy_windows(self):
        from resilience.engine import Incident

        sim = ResilienceSimulator()
        target = sim.nodes["records"]
        target.trust = 55
        target.stage = "restricted"
        incident = Incident("trust-window-test", "records")
        sim._advance_trust_recovery(target, incident, healthy_windows=1)
        self.assertEqual(target.stage, "restricted")
        sim._advance_trust_recovery(target, incident, healthy_windows=1)
        self.assertEqual(target.stage, "monitored")
        self.assertEqual([step["promotion"] for step in incident.trust_trajectory],
                         [False, True])

    def test_unhealthy_window_resets_sustained_trust_promotion(self):
        from resilience.engine import Incident

        sim = ResilienceSimulator()
        target = sim.nodes["records"]
        target.trust = 55
        target.stage = "restricted"
        incident = Incident("trust-window-reset-test", "records")
        sim._record_trust_window(target, incident, healthy=True)
        sim._record_trust_window(target, incident, healthy=False)
        sim._record_trust_window(target, incident, healthy=True)
        self.assertEqual(target.stage, "restricted")
        self.assertEqual(target.healthy_window_streak, 1)
        sim._record_trust_window(target, incident, healthy=True)
        self.assertEqual(target.stage, "monitored")
        self.assertEqual([step["healthy"] for step in incident.trust_trajectory],
                         [True, False, True, True])

    def test_unsupported_accusation_does_not_isolate(self):
        report = ResilienceSimulator().run("false-evidence")
        self.assertEqual(report["decision"], "withhold")
        self.assertEqual(report["metrics"]["false_isolations"], 0)
        self.assertEqual(report["metrics"]["trust_scores"]["portal"], 55)
        self.assertEqual(next(item["change"] for item in report["trust_updates"]
                              if item["node"] == "portal"), -25)
        self.assertIn("portal trust reduced after unsupported accusation", report["events"])

    def test_clean_observation_window_recovers_trust_without_containment(self):
        sim = ResilienceSimulator()
        sim.nodes["portal"].trust = 55
        report = sim.run("healthy-window")
        self.assertEqual(report["decision"], "withhold")
        self.assertEqual(report["metrics"]["trust_scores"]["portal"], 60)
        self.assertFalse(report["pbft_consensus"]["value"] == "CONTAIN")
        self.assertEqual(set(report["normal_reporters"]),
                         {"portal", "identity", "records", "database"})
        self.assertTrue(all(item["change"] == 5 for item in report["trust_updates"]))

    def test_lower_trust_downweights_later_signed_evidence(self):
        sim = ResilienceSimulator()
        evidence = sim._emit("portal", "records", "network", .8)
        baseline = sim._score([evidence])
        sim.nodes["portal"].trust = 55
        downweighted = sim._score([evidence])
        self.assertAlmostEqual(baseline, .64)
        self.assertAlmostEqual(downweighted, .44)

    def test_one_silent_agent_is_tolerated_with_three_reporters(self):
        report = ResilienceSimulator().run("silent-node")
        self.assertEqual(report["decision"], "contain")
        self.assertEqual(report["corroboration"]["verified_reporters"], 3)
        self.assertIn("database agent went silent; its vote was unavailable", report["events"])

    def test_two_compromised_agents_exceed_model_limit(self):
        report = ResilienceSimulator().run("two-compromised")
        self.assertEqual(report["decision"], "withhold")
        self.assertFalse(report["pbft_consensus"]["committed"])
        self.assertTrue(any("exceed this 4-node model" in e for e in report["events"]))

    def test_pbft_primary_failure_changes_view_and_commits(self):
        report = ResilienceSimulator().run("block-vote")
        proof = report["pbft_consensus"]
        self.assertTrue(proof["committed"])
        self.assertEqual(proof["view"], 1)
        self.assertEqual([p["phase"] for p in proof["phases"]],
                         ["VIEW-CHANGE", "PRE-PREPARE", "PREPARE", "COMMIT"])

    def test_unauthorized_primary_proposal_is_rejected_and_noop_commits(self):
        report = ResilienceSimulator().run("false-evidence")
        proof = report["pbft_consensus"]
        self.assertEqual(report["decision"], "withhold")
        self.assertTrue(proof["committed"])
        self.assertEqual(proof["value"], "NOOP")
        self.assertEqual(proof["view"], 1)

    def test_pbft_rejects_tampered_signed_message(self):
        nodes = ["a", "b", "c", "d"]
        ring = NodeKeyring.generate(nodes)
        consensus = PBFTConsensus(nodes, ring, 1)
        message = consensus._message("a", "PREPARE", 0, consensus.digest("CONTAIN"))
        self.assertTrue(consensus.verify_message(message))
        tampered = type(message)(message.sender, message.phase, message.view,
                                 message.sequence, consensus.digest("NOOP"), message.signature)
        self.assertFalse(consensus.verify_message(tampered))

    def test_peer_transport_requires_and_verifies_mutual_tls(self):
        root = Path(__file__).resolve().parent.parent
        certs = Path(generate_dev_pki(root / "work" / "mtls-test", force=True)["directory"])
        nodes = ["portal", "identity", "records", "database"]
        ring = NodeKeyring.generate(nodes)
        consensus = PBFTConsensus(nodes, ring, 1)
        server = create_mtls_server("127.0.0.1", 0,
                                    str(certs / "portal.crt"), str(certs / "portal.key"),
                                    str(certs / "ca.crt"), consensus)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            message = consensus._message("portal", "PREPARE", 0, consensus.digest("CONTAIN"))
            response = send_mtls_message("127.0.0.1", server.server_port,
                                         str(certs / "ca.crt"), str(certs / "portal.crt"),
                                         str(certs / "portal.key"), message)
            self.assertTrue(response["accepted"])
            self.assertEqual(len(server.received_messages), 1)
            forged = type(message)(message.sender, message.phase, message.view,
                                   message.sequence, consensus.digest("NOOP"), message.signature)
            with self.assertRaises(RuntimeError):
                send_mtls_message("127.0.0.1", server.server_port,
                                  str(certs / "ca.crt"), str(certs / "portal.crt"),
                                  str(certs / "portal.key"), forged)
            self.assertEqual(len(server.received_messages), 1)
            no_client_cert = ssl.create_default_context(cafile=str(certs / "ca.crt"))
            connection = http.client.HTTPSConnection(
                "127.0.0.1", server.server_port, context=no_client_cert, timeout=2)
            try:
                with self.assertRaises((ssl.SSLError, http.client.RemoteDisconnected, ConnectionResetError)):
                    connection.request("GET", "/healthz")
                    connection.getresponse()
            finally:
                connection.close()
        finally:
            server.shutdown()
            server.server_close()

    def test_experiment_compares_architectures_and_repeats(self):
        report = run_experiment(2, ("genuine-compromise", "false-evidence"))
        self.assertEqual(report["repeats"], 2)
        self.assertEqual(len(report["results"]), 2)
        self.assertEqual(report["results"][0]["distributed"]["containment_rate_percent"], 100)
        self.assertEqual(report["results"][1]["centralized"]["false_isolations"], 2)

    def test_dashboard_metrics_and_comparison_endpoints_are_read_only(self):
        import threading, urllib.request
        from http.server import ThreadingHTTPServer
        from resilience.dashboard import make_handler
        simulator = ResilienceSimulator()
        simulator.run("genuine-compromise")
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(simulator))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with urllib.request.urlopen(base + "/metrics", timeout=10) as reply:
                text = reply.read().decode()
                self.assertIn("text/plain", reply.headers["Content-Type"])
            self.assertIn('resilience_node_trust{node=', text)
            self.assertIn("resilience_incidents_total 1", text)
            self.assertIn("resilience_false_isolations_total 0", text)
            with urllib.request.urlopen(base + "/api/comparison", timeout=30) as reply:
                data = json.loads(reply.read())
            self.assertEqual(len(data["experiment"]["results"]), 5)
            self.assertEqual(data["boundary"]["sweeps"][0]["n"], 4)
            with urllib.request.urlopen(base + "/", timeout=10) as reply:
                page = reply.read().decode()
            self.assertIn('id="comparison"', page)
            self.assertIn('id="boundary"', page)
            request = urllib.request.Request(base + "/metrics", data=b"{}", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request, timeout=10)
            self.assertEqual(caught.exception.code, 404)
        finally:
            server.shutdown()
            server.server_close()

    def test_health_summary_releases_database_handle(self):
        import tempfile
        from unittest import mock
        from resilience import health_records
        opened = []

        class Tracked:
            """Proxy that records whether close() was called on the real connection."""
            def __init__(self, real):
                self._real, self.closed = real, False
                opened.append(self)
            def __getattr__(self, name):
                return getattr(self._real, name)
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return self._real.__exit__(*exc)
            def close(self):
                self.closed = True
                self._real.close()

        real_connect = sqlite3.connect
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            path = health_records.database_path(root)
            path.parent.mkdir(parents=True, exist_ok=True)
            with closing(real_connect(path)) as db:
                db.execute("CREATE TABLE encounters (demo_id TEXT, readmitted TEXT, age TEXT)")
                db.execute("INSERT INTO encounters VALUES ('a','NO','[70-80)')")
                db.commit()
            with mock.patch.object(health_records.sqlite3, "connect",
                                   side_effect=lambda *a, **k: Tracked(real_connect(*a, **k))):
                self.assertEqual(health_records.health_summary(root)["encounters"], 1)
            self.assertTrue(opened)
            self.assertTrue(all(handle.closed for handle in opened))

    def test_dev_pki_passes_strict_x509_verification(self):
        import ssl, tempfile
        from resilience.pki_tools import generate_dev_pki
        with tempfile.TemporaryDirectory() as temp_dir:
            generate_dev_pki(Path(temp_dir))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(str(Path(temp_dir) / "ca.crt"))
            context.verify_flags |= ssl.VERIFY_X509_STRICT  # default on Python 3.13+
            server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.load_cert_chain(str(Path(temp_dir) / "portal.crt"), str(Path(temp_dir) / "portal.key"))
            import socket, threading
            listener = socket.socket(); listener.bind(("127.0.0.1", 0)); listener.listen(1)
            def accept():
                try:
                    conn, _ = listener.accept()
                    with server.wrap_socket(conn, server_side=True):
                        pass
                except (ssl.SSLError, OSError):
                    pass
            thread = threading.Thread(target=accept, daemon=True); thread.start()
            with socket.create_connection(listener.getsockname(), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as tls:
                    self.assertTrue(tls.version())
            thread.join(5); listener.close()

    def test_centralized_baseline_is_executed_not_tabulated(self):
        from resilience.baseline import CentralizedController
        self.assertTrue(CentralizedController().run("false-evidence")["metrics"]["false_isolation"])
        blocked = CentralizedController("block").run("genuine-compromise")
        self.assertEqual(blocked["decision"], "withhold")
        self.assertTrue(blocked["metrics"]["missed_containment"])
        with self.assertRaises(ValueError):
            CentralizedController("bogus")

    def test_distributed_false_isolation_and_tainted_restore_metrics(self):
        report = ResilienceSimulator().run("false-evidence")
        self.assertFalse(report["metrics"]["false_isolation"])
        tainted = ResilienceSimulator().run("genuine-compromise", tainted_restore=True)
        self.assertFalse(tainted["metrics"]["recovery_success"])
        self.assertFalse(tainted["metrics"]["false_reintegration"])
        self.assertEqual(tainted["metrics"]["target_stage"], "quarantine")

    def test_boundary_sweep_matches_bft_theory_and_never_fails_within_f(self):
        from resilience.boundary import run_boundary_sweep
        report = run_boundary_sweep((4, 7))
        for sweep in report["sweeps"]:
            for name, attack in sweep["attacks"].items():
                for cell in attack["cells"]:
                    if cell["k"] <= sweep["f"]:
                        self.assertTrue(cell["correct"], (sweep["n"], name, cell))
                if name in ("silent", "block"):
                    self.assertEqual(attack["first_failing_k"], sweep["f"] + 1)
                else:  # safety: colluders need a full 2f+1 quorum to force a false isolation
                    self.assertEqual(attack["first_failing_k"], 2 * sweep["f"] + 1)
        self.assertTrue(all(not row["correct"] for row in report["centralized_controller_compromised"]))
        integrity = report["reintegration_integrity"]
        self.assertFalse(integrity["distributed"]["false_reintegration"])
        self.assertTrue(integrity["centralized_compromised_controller"]["false_reintegration"])

    def test_boundary_sweep_rejects_bad_sizes(self):
        from resilience.boundary import run_boundary_sweep, run_cell
        with self.assertRaises(ValueError):
            run_boundary_sweep((3,))
        with self.assertRaises(ValueError):
            run_cell(4, 1, "nonsense")

    def test_experiment_repeat_count_is_bounded(self):
        with self.assertRaises(ValueError):
            run_experiment(0)

    def test_dashboard_is_read_only_and_accepts_cli_simulation_api(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(ResilienceSimulator()))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request("GET", "/")
            page = connection.getresponse().read().decode()
            self.assertIn("read-only dashboard", page)
            self.assertNotIn("<button", page)
            connection.request("POST", "/api/simulate", body=json.dumps({"scenario": "genuine-compromise"}),
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["decision"], "contain")
            connection.request("GET", "/api/state")
            state = json.loads(connection.getresponse().read())
            self.assertEqual(state["latest"]["scenario"], "genuine-compromise")
            self.assertEqual(state["decision_parameters"]["quorum_formula"], "2f+1")
            self.assertNotIn("patient_nbr", json.dumps(state))
        finally:
            connection.close()
            server.shutdown()
            server.server_close()

    def test_imported_public_dataset_store_drops_source_ids(self):
        summary = health_summary()
        if not summary["loaded"]:
            self.skipTest("Fetch and import the public UCI dataset first")
        self.assertEqual(summary["encounters"], 101766)
        with closing(sqlite3.connect(database_path())) as db:
            columns = {row[1] for row in db.execute("PRAGMA table_info(encounters)")}
        self.assertNotIn("patient_nbr", columns)
        self.assertNotIn("encounter_id", columns)


if __name__ == "__main__":
    unittest.main()
