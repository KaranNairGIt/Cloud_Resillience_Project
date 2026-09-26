"""Least-privilege recovery controls for one synthetic Kubernetes lab workload."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import ssl
import time
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


LAB_NAMESPACE = "resilience-lab"
WORKLOAD_NAME = "resilience-demo-records"
ACCESS_POLICY_NAME = "resilience-demo-access"
WORKLOAD_SERVICE = f"{WORKLOAD_NAME}.{LAB_NAMESPACE}.svc.cluster.local"
KNOWN_GOOD_IMAGE = "distributed-cyber-resilience:dev"
STAGE_TRUST = {"quarantined": 0, "restricted": 45, "monitored": 60,
               "peer-validated": 75, "full": 90}
SUSTAINED_WINDOWS_PER_STAGE = 2
STAGE_ORDER = ("quarantined", "restricted", "monitored", "peer-validated", "full")


def _known_good_container() -> dict:
    return {
        "name": "demo-workload",
        "image": KNOWN_GOOD_IMAGE,
        "imagePullPolicy": "Never",
        "command": ["python", "-m", "resilience.demo_workload"],
        "ports": [{"name": "http-demo", "containerPort": 8080, "protocol": "TCP"}],
        "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080},
                           "initialDelaySeconds": 2, "periodSeconds": 3},
        "livenessProbe": {"httpGet": {"path": "/healthz", "port": 8080},
                          "initialDelaySeconds": 5, "periodSeconds": 5},
        "securityContext": {"allowPrivilegeEscalation": False,
                             "readOnlyRootFilesystem": True,
                             "capabilities": {"drop": ["ALL"]}},
        "resources": {"requests": {"cpu": "25m", "memory": "32Mi"},
                      "limits": {"cpu": "200m", "memory": "128Mi"}},
    }


class InClusterKubernetesAPI:
    """Small verified-TLS client using the pod's projected service-account token."""

    def __init__(self, request_timeout: float = 5):
        service_host = os.environ.get("KUBERNETES_SERVICE_HOST")
        service_port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not service_host:
            raise RuntimeError("Kubernetes API access requires an in-cluster service environment")
        host = f"[{service_host}]" if ":" in service_host and not service_host.startswith("[") else service_host
        self.base_url = f"https://{host}:{service_port}"
        self.token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
        self.ca_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
        self.context = ssl.create_default_context(cafile=str(self.ca_path))
        self.timeout = request_timeout

    def request(self, method: str, path: str, payload: dict | None = None) -> dict:
        token = self.token_path.read_text(encoding="utf-8").strip()
        data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/merge-patch+json"
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, context=self.context, timeout=self.timeout) as response:
                content = response.read(1_048_576)
                return json.loads(content) if content else {}
        except HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", "replace")
            raise RuntimeError(f"Kubernetes API returned HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"Kubernetes API request failed: {exc.reason}") from exc


class KubernetesRecoveryAdapter:
    """Apply a committed decision only to the named synthetic lab Deployment.

    No namespace, workload or policy name comes from caller input. NetworkPolicy
    stages keep all traffic denied except the explicitly listed project peers.
    """

    CHECKS = ("integrity", "health", "behavior")
    DEPLOYMENT_PATH = (f"/apis/apps/v1/namespaces/{LAB_NAMESPACE}/deployments/"
                       f"{WORKLOAD_NAME}")
    POLICY_PATH = (f"/apis/networking.k8s.io/v1/namespaces/{LAB_NAMESPACE}/networkpolicies/"
                   f"{ACCESS_POLICY_NAME}")

    def __init__(self, api=None, probe: Callable[[str], dict] | None = None,
                 rollout_timeout: float = 45, poll_interval: float = .5):
        self.api = api or InClusterKubernetesAPI()
        self.probe = probe or self._http_probe
        self.rollout_timeout = rollout_timeout
        self.poll_interval = poll_interval

    @staticmethod
    def _peer_selector() -> dict:
        return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "resilience"}},
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "resilience-peer"}}}

    @staticmethod
    def _portal_selector() -> dict:
        return {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "resilience"}},
                "podSelector": {"matchLabels": {"resilience-node": "portal"}}}

    @classmethod
    def stage_rules(cls, stage: str) -> dict:
        if stage == "quarantined":
            return {"ingress": [], "egress": []}
        ingress_peer = {"from": [cls._peer_selector()],
                        "ports": [{"protocol": "TCP", "port": 8080}]}
        egress_peer = {"to": [cls._peer_selector()],
                       "ports": [{"protocol": "TCP", "port": 8766}]}
        if stage == "restricted":
            return {"ingress": [{"from": [cls._portal_selector()],
                                  "ports": [{"protocol": "TCP", "port": 8080}]}],
                    "egress": []}
        if stage == "monitored":
            return {"ingress": [ingress_peer], "egress": []}
        if stage == "peer-validated":
            return {"ingress": [ingress_peer], "egress": [egress_peer]}
        if stage == "full":
            return {"ingress": [ingress_peer],
                    "egress": [egress_peer, {
                        "to": [{"namespaceSelector": {
                            "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}],
                        "ports": [{"protocol": "UDP", "port": 53},
                                  {"protocol": "TCP", "port": 53}],
                    }]}
        raise ValueError(f"unsupported workload network stage: {stage}")

    def _set_stage(self, stage: str, *, trust_score: float | None = None,
                   clean_windows: int = 0) -> None:
        if stage not in STAGE_TRUST or not 0 <= clean_windows < SUSTAINED_WINDOWS_PER_STAGE:
            raise ValueError("invalid reintegration stage state")
        annotations = {"resilience.demo/stage": stage,
                       "resilience.demo/clean-windows": str(clean_windows)}
        if trust_score is not None:
            annotations["resilience.demo/trust-score"] = str(round(trust_score, 2))
        self.api.request("PATCH", self.POLICY_PATH,
                         {"metadata": {"annotations": annotations},
                          "spec": self.stage_rules(stage)})

    @staticmethod
    def _trust_input(trust_score: float | None) -> float:
        if (isinstance(trust_score, bool) or not isinstance(trust_score, (int, float))
                or not 0 <= trust_score <= 100):
            return 0.0
        return float(trust_score)

    def _actual_checks(self) -> dict[str, bool]:
        deployment = self.api.request("GET", self.DEPLOYMENT_PATH)
        health = self.probe("/healthz")
        behavior = self.probe("/behavior")
        return {
            "integrity": self._check_known_good(deployment),
            "health": health.get("status") == "healthy",
            "behavior": (behavior.get("status") == "normal"
                         and behavior.get("records") == "synthetic-only"),
        }

    def advance_trust_window(self, *, consensus_committed: bool, value: str,
                             target: str, trust_score: float | None,
                             healthy_window_committed: bool,
                             validation: dict[str, bool] | None = None) -> dict:
        """Advance one stage only after a committed clean window and fresh checks."""
        if (not consensus_committed or value != "NOOP" or target != "records"
                or not healthy_window_committed):
            return {"executed": False, "status": "unchanged",
                    "reason": "a committed clean observation window for records is required",
                    "actions": []}
        score = self._trust_input(trust_score)
        if validation is None:
            validation = {name: True for name in self.CHECKS}
        if set(validation) != set(self.CHECKS) or not all(isinstance(v, bool) for v in validation.values()):
            raise ValueError("validation must provide boolean integrity, health, and behavior results")
        try:
            policy = self.api.request("GET", self.POLICY_PATH)
            annotations = policy.get("metadata", {}).get("annotations", {})
            stage = annotations.get("resilience.demo/stage", "quarantined")
            clean_windows = int(annotations.get("resilience.demo/clean-windows", "0"))
            if stage not in STAGE_TRUST or not 0 <= clean_windows < SUSTAINED_WINDOWS_PER_STAGE:
                raise RuntimeError("saved reintegration state is invalid")
            if stage == "full":
                return {"executed": False, "status": "fully-reintegrated",
                        "trust_score": score, "current_stage": stage,
                        "actions": ["workload is already at full access"]}
            actions = []
            if stage == "quarantined":
                if score < STAGE_TRUST["restricted"]:
                    return {"executed": True, "status": "quarantined",
                            "trust_score": score, "current_stage": stage,
                            "reason": "trust is below restricted-access threshold",
                            "actions": []}
                # The only ingress opened at this point is from the portal monitor.
                stage = "restricted"
                clean_windows = 0
                self._set_stage(stage, trust_score=score, clean_windows=clean_windows)
                actions.append("opened portal-only restricted access for recovery checks")

            actual_checks = self._actual_checks()
            failed = sorted(name for name in self.CHECKS
                            if not validation[name] or not actual_checks[name])
            next_stage = STAGE_ORDER[STAGE_ORDER.index(stage) + 1]
            if failed:
                self._set_stage("restricted", trust_score=score, clean_windows=0)
                return {"executed": True, "target": target, "namespace": LAB_NAMESPACE,
                        "status": "restricted-validation-failed", "available": True,
                        "current_stage": "restricted", "trust_score": score,
                        "validation": {name: validation[name] and actual_checks[name]
                                       for name in self.CHECKS},
                        "failed_checks": failed, "reintegration_stages": ["restricted"],
                        "actions": actions + ["validation failed; access reset to portal-only restricted stage"]}

            if score < STAGE_TRUST[next_stage]:
                clean_windows = 0
            else:
                clean_windows += 1
            if clean_windows >= SUSTAINED_WINDOWS_PER_STAGE:
                stage = next_stage
                clean_windows = 0
                self._set_stage(stage, trust_score=score, clean_windows=clean_windows)
                actions.append(f"two clean windows and trust threshold promoted access to {stage}")
            else:
                self._set_stage(stage, trust_score=score, clean_windows=clean_windows)
                actions.append(f"recorded clean trust window {clean_windows}/{SUSTAINED_WINDOWS_PER_STAGE} for {next_stage}")
            return {"executed": True, "target": target, "namespace": LAB_NAMESPACE,
                    "status": "fully-reintegrated" if stage == "full" else "reintegration-pending",
                    "available": True, "current_stage": stage,
                    "next_stage": None if stage == "full" else next_stage,
                    "clean_windows": clean_windows, "trust_score": score,
                    "next_stage_trust_threshold": (None if stage == "full"
                                                   else STAGE_TRUST[next_stage]),
                    "validation": actual_checks, "failed_checks": [],
                    "reintegration_stages": [stage], "actions": actions,
                    "network_policy_scope": ACCESS_POLICY_NAME}
        except Exception as exc:
            try:
                self._set_stage("quarantined", trust_score=score, clean_windows=0)
                lockdown = "deny-all policy reasserted"
            except Exception as lockdown_error:
                lockdown = f"deny-all reassertion failed: {lockdown_error}"
            return {"executed": True, "target": target, "namespace": LAB_NAMESPACE,
                    "status": "quarantined", "available": False,
                    "trust_score": score, "error": str(exc), "actions": [lockdown]}

    @staticmethod
    def _http_probe(path: str) -> dict:
        from urllib.request import urlopen
        url = f"http://{WORKLOAD_SERVICE}:8080{path}"
        with urlopen(url, timeout=3) as response:
            if response.status != 200:
                raise RuntimeError(f"workload probe returned HTTP {response.status}")
            value = json.loads(response.read(4096))
        if not isinstance(value, dict):
            raise RuntimeError("workload probe did not return a JSON object")
        return value

    @staticmethod
    def inject_demo_attack() -> dict:
        """Flip only the sample app's in-memory anomaly flag; no exploit or data access."""
        from urllib.request import Request, urlopen
        request = Request(f"http://{WORKLOAD_SERVICE}:8080/simulate/attack",
                          data=b"{}", headers={"Content-Type": "application/json"},
                          method="POST")
        with urlopen(request, timeout=3) as response:
            result = json.loads(response.read(4096))
        if result.get("status") != "anomalous":
            raise RuntimeError("demo workload did not enter its synthetic anomalous state")
        return result

    def _wait_ready(self, generation: int) -> dict:
        deadline = time.monotonic() + self.rollout_timeout
        last = {}
        while time.monotonic() < deadline:
            last = self.api.request("GET", self.DEPLOYMENT_PATH)
            metadata = last.get("metadata", {})
            status = last.get("status", {})
            if (metadata.get("generation", 0) >= generation
                    and status.get("observedGeneration", 0) >= metadata.get("generation", 0)
                    and status.get("updatedReplicas", 0) == 1
                    and status.get("readyReplicas", 0) == 1
                    and status.get("availableReplicas", 0) == 1):
                return last
            time.sleep(self.poll_interval)
        raise TimeoutError(f"synthetic workload did not become ready: {last.get('status', {})}")

    @staticmethod
    def _check_known_good(deployment: dict) -> bool:
        containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        return (len(containers) == 1
                and containers[0].get("name") == "demo-workload"
                and containers[0].get("image") == KNOWN_GOOD_IMAGE
                and containers[0].get("command") == ["python", "-m", "resilience.demo_workload"]
                and containers[0].get("imagePullPolicy") == "Never")

    def run(self, *, consensus_committed: bool, value: str, target: str,
            validation: dict[str, bool] | None = None,
            trust_score: float | None = None) -> dict:
        if not consensus_committed or value != "CONTAIN":
            return {"executed": False, "status": "unchanged",
                    "reason": "a committed CONTAIN decision is required", "actions": []}
        if target != "records":
            return {"executed": False, "status": "not-applicable",
                    "reason": "only the dedicated synthetic records workload is mapped in Kubernetes",
                    "actions": []}
        validation = validation or {name: True for name in self.CHECKS}
        score = self._trust_input(trust_score)
        if set(validation) != set(self.CHECKS) or not all(isinstance(v, bool) for v in validation.values()):
            raise ValueError("validation must provide boolean integrity, health, and behavior results")

        actions = []
        isolation_attempted = False
        isolation_confirmed = False
        try:
            isolation_attempted = True
            self._set_stage("quarantined")
            isolation_confirmed = True
            actions.append("dedicated synthetic workload isolated by namespace-scoped NetworkPolicy")

            now = datetime.now(timezone.utc).isoformat()
            patch = {"spec": {"replicas": 1, "template": {
                "metadata": {"annotations": {"resilience-demo/recovered-at": now}},
                "spec": {"containers": [_known_good_container()]},
            }}}
            updated = self.api.request("PATCH", self.DEPLOYMENT_PATH, patch)
            generation = updated.get("metadata", {}).get("generation", 1)
            deployment = self._wait_ready(generation)
            actions.append("known-good demo container template restored and replacement pod became Ready")

            if score < STAGE_TRUST["restricted"]:
                self._set_stage("quarantined", trust_score=score, clean_windows=0)
                return {"executed": True, "target": target, "namespace": LAB_NAMESPACE,
                        "status": "quarantined", "available": False,
                        "trust_score": score, "validation": None,
                        "failed_checks": [], "reintegration_stages": ["quarantine"],
                        "reason": "trust is below restricted-access threshold",
                        "actions": actions + ["workload remains quarantined until trust reaches 45"]}
            self._set_stage("restricted", trust_score=score, clean_windows=0)
            actual_integrity = self._check_known_good(deployment)
            health = self.probe("/healthz")
            behavior = self.probe("/behavior")
            actual_checks = {
                "integrity": actual_integrity,
                "health": health.get("status") == "healthy",
                "behavior": (behavior.get("status") == "normal"
                             and behavior.get("records") == "synthetic-only"),
            }
            failed = sorted(name for name in self.CHECKS
                            if not validation[name] or not actual_checks[name])
            if failed:
                fail_stage = ("restricted" if score >= STAGE_TRUST["restricted"]
                              else "quarantined")
                self._set_stage(fail_stage, trust_score=score, clean_windows=0)
                actions.append("validation failed; access remains restricted to the portal health monitor")
                return {"executed": True, "target": target, "namespace": LAB_NAMESPACE,
                        "status": "restricted-validation-failed" if fail_stage == "restricted" else "quarantined",
                        "available": fail_stage == "restricted",
                        "validation": {name: validation[name] and actual_checks[name]
                                       for name in self.CHECKS},
                        "failed_checks": failed,
                        "reintegration_stages": ["quarantine", fail_stage],
                        "actions": actions}

            actions.append("container-template integrity, HTTP health and synthetic behavior checks passed")
            return {"executed": True, "target": target, "namespace": LAB_NAMESPACE,
                    "status": "reintegration-pending", "available": True,
                    "current_stage": "restricted", "trust_score": score,
                    "next_stage": "monitored",
                    "next_stage_trust_threshold": STAGE_TRUST["monitored"],
                    "clean_windows": 0,
                    "validation": actual_checks, "failed_checks": [],
                    "reintegration_stages": ["quarantine", "restricted"], "actions": actions,
                    "network_policy_scope": ACCESS_POLICY_NAME}
        except Exception as exc:
            if isolation_attempted:
                try:
                    self._set_stage("quarantined")
                    isolation_confirmed = True
                    actions.append("failure handler restored deny-all policy")
                except Exception as lockdown_error:
                    actions.append(f"failed to re-assert deny-all policy: {lockdown_error}")
            return {"executed": True, "target": target, "namespace": LAB_NAMESPACE,
                    "status": ("quarantined" if isolation_confirmed else
                               "isolation-unconfirmed" if isolation_attempted else "failed-before-isolation"),
                    "available": False, "error": str(exc),
                    "reintegration_stages": ["quarantine"] if isolation_confirmed else [],
                    "actions": actions}
