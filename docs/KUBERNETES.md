# Local Kubernetes deployment

The manifests deploy four independent mTLS PBFT-style replicas and a separate synthetic records workload in `resilience-lab`. The portal coordinator has narrowly scoped RBAC to one Deployment and one NetworkPolicy in that lab namespace. The response adapter can isolate and restart only this toy workload; it cannot change peer Deployments, other namespaces, or actual healthcare records. This is an educational single-round protocol demo, not a production PBFT cluster (see [Voting](VOTING.md)).

## Prerequisites

- Minikube, `kubectl`, Helm, and a compatible container or virtual-machine driver.
- At least 2 CPUs, 2 GB RAM, and 20 GB free disk, as recommended by Minikube.
- A CNI plugin that enforces Kubernetes NetworkPolicy. A default Minikube install uses Kindnet and does not enforce policies; the commands below choose Calico.
- A default StorageClass for the four 128Mi peer-state claims (`kubectl get storageclass`). Each peer needs its own volume.

Before applying the portal egress policy, check the Kubernetes API Service address:

```powershell
kubectl get service kubernetes -n default -o jsonpath='{.spec.clusterIP}'
```

The manifest allows the Minikube default `10.96.0.1/32` on TCP 443. If your cluster reports a different address, update that `ipBlock` in `k8s/network-policy.yaml` before continuing.

## Build and deploy

Run from the project root:

```powershell
minikube start --cni=calico
minikube image build -t distributed-cyber-resilience:dev .
kubectl apply -f k8s/namespace.yaml
helm upgrade --install cert-manager oci://quay.io/jetstack/charts/cert-manager `
  --namespace cert-manager --create-namespace --version v1.21.2 --set crds.enabled=true
kubectl rollout status deployment/cert-manager -n cert-manager --timeout=180s
kubectl apply -f k8s/cert-manager.yaml
kubectl apply -f k8s/response-rbac.yaml
kubectl wait --for=condition=Ready certificate/resilience-root-ca -n resilience --timeout=180s
kubectl wait --for=condition=Ready certificate/peer-portal -n resilience --timeout=180s
kubectl wait --for=condition=Ready certificate/peer-identity -n resilience --timeout=180s
kubectl wait --for=condition=Ready certificate/peer-records -n resilience --timeout=180s
kubectl wait --for=condition=Ready certificate/peer-database -n resilience --timeout=180s
```

Generate local signing keys once. The private keys are unencrypted development material under ignored `work/keys`; never reuse them outside a local learning cluster.

```powershell
python -m resilience.cli keys generate
kubectl create secret generic pbft-signing-portal -n resilience --from-file=signing-key.pem=work/keys/private/portal.pem
kubectl create secret generic pbft-signing-identity -n resilience --from-file=signing-key.pem=work/keys/private/identity.pem
kubectl create secret generic pbft-signing-records -n resilience --from-file=signing-key.pem=work/keys/private/records.pem
kubectl create secret generic pbft-signing-database -n resilience --from-file=signing-key.pem=work/keys/private/database.pem
kubectl create configmap pbft-public-keys -n resilience `
  --from-file=portal.pub.pem=work/keys/public/portal.pub.pem `
  --from-file=identity.pub.pem=work/keys/public/identity.pub.pem `
  --from-file=records.pub.pem=work/keys/public/records.pub.pem `
  --from-file=database.pub.pem=work/keys/public/database.pub.pem
kubectl apply -f k8s/peer-state.yaml
kubectl apply -f k8s/network-policy.yaml
kubectl apply -f k8s/demo-workload.yaml
kubectl apply -f k8s/agents.yaml
kubectl rollout status deployment/resilience-demo-records -n resilience-lab --timeout=120s
kubectl get pods,services -n resilience
kubectl get certificates -n resilience
```

Each signing Secret contains only one node's private key. The ConfigMap contains only public keys. cert-manager creates each node's TLS key/certificate Secret with client and server authentication usages. The container mounts only its own key and certificate, plus the public committee keys.

The default-deny policy is followed by an allow rule for peer TCP port 8766 and CoreDNS. NetworkPolicy enforcement depends on the CNI; Kubernetes accepts the resource even when the plugin ignores it.

Each peer stores signed PBFT state under `/var/lib/resilience/state` on its own 128Mi PVC, separate from all other peers. The portal uses a projected ServiceAccount token for API access and can only `get`/`patch` the named demo Deployment and access NetworkPolicy in `resilience-lab`.

When every peer pod is Ready, run a scenario from the portal pod. It uses its own TLS client certificate to relay protocol messages to the four Kubernetes Services; each peer separately verifies signed evidence and PBFT messages:

```powershell
kubectl exec deployment/resilience-peer-portal -n resilience -- python -m resilience.cli cluster simulate genuine-compromise --pki-dir /var/run/resilience-pki --key-dir /var/run/resilience-keys --kubernetes
kubectl exec deployment/resilience-peer-portal -n resilience -- python -m resilience.cli cluster simulate false-evidence --pki-dir /var/run/resilience-pki --key-dir /var/run/resilience-keys --kubernetes
kubectl exec deployment/resilience-peer-portal -n resilience -- python -m resilience.cli cluster simulate healthy-window --pki-dir /var/run/resilience-pki --key-dir /var/run/resilience-keys --kubernetes
kubectl exec deployment/resilience-peer-portal -n resilience -- python -m resilience.cli cluster simulate genuine-compromise --pki-dir /var/run/resilience-pki --key-dir /var/run/resilience-keys --kubernetes --fail-check health
kubectl exec deployment/resilience-peer-portal -n resilience -- python -m resilience.cli cluster simulate genuine-compromise --pki-dir /var/run/resilience-pki --key-dir /var/run/resilience-keys --kubernetes --apply-kubernetes-response
```

`--apply-kubernetes-response` opts into the actual lab-only action. For a records-target scenario, the portal first sends `POST /simulate/attack` to the demo app; that changes one in-memory flag and makes `/behavior` report anomalous. After a committed CONTAIN, the controller applies a deny-all policy to that workload, restores the fixed known-good container template, waits for a Ready replacement, checks image/command integrity plus `/healthz` and `/behavior`, and records a `restricted` reintegration stage. Access is promoted only after the committee commits signed healthy windows for the same target. Each next stage needs two consecutive windows and the quorum-agreed trust threshold: 60 for monitored, 75 for peer-validated, and 90 for full. A failed check or unhealthy window keeps the workload restricted and resets the streak. Use a distinct sequence number for each window, for example:

```powershell
kubectl exec deployment/resilience-peer-portal -n resilience -- python -m resilience.cli cluster simulate genuine-compromise --pki-dir /var/run/resilience-pki --key-dir /var/run/resilience-keys --kubernetes --apply-kubernetes-response --sequence 2000
kubectl exec deployment/resilience-peer-portal -n resilience -- python -m resilience.cli cluster simulate healthy-window --trust-target records --pki-dir /var/run/resilience-pki --key-dir /var/run/resilience-keys --kubernetes --apply-kubernetes-response --sequence 2001
```

Repeat `healthy-window` with new sequence values until the policy annotation reports `full` (up to eight clean windows when trust starts at 55). Counted windows must be at least 30 seconds apart (`RESILIENCE_MIN_WINDOW_SECONDS`, set on the portal pod in `k8s/agents.yaml`). A trigger that arrives sooner returns `window-not-elapsed` with `seconds_remaining`, changes nothing and does not quarantine; expect roughly four minutes end to end. Each update also carries the policy's `resourceVersion`, so two overlapping triggers cannot both count: the loser returns `conflict` and can simply be re-run. A saved window timestamp more than a few seconds in the future is treated as tampering and fails closed to quarantine. `false-evidence` targets an unmapped healthy identity service and is a no-op; `two-compromised` can leave the toy records process marked anomalous because the replicas correctly cannot reach quorum. Its baseline policy already allows only portal access. These controls do not reach actual medical systems or data.

`--fail-check health` exercises fail-closed reintegration after a successful commit. The portal pod only has its own private signing key; it relays other replicas' signed protocol messages and cannot sign on their behalf. The output shows evidence, quorum, each replica's state and whether the response was simulated or applied to the lab workload.

## Inspect and stop

```powershell
kubectl logs deployment/resilience-peer-portal -n resilience
kubectl describe certificate peer-portal -n resilience
kubectl get networkpolicy -n resilience
minikube stop
```

To start the cluster again use `minikube start`, then inspect pod readiness with `kubectl get pods -n resilience`.

## Secret boundary

Kubernetes Secrets are not automatically a production vault. Kubernetes warns that Secrets are stored unencrypted in etcd by default unless encryption at rest is configured, and RBAC must restrict access. A real environment should use an external KMS/HSM or secret manager, least-privilege RBAC, API-server encryption at rest, and audited rotation. cert-manager handles leaf certificate renewal; the demo self-signed root CA is not an appropriate production trust root.

Reference docs: [Minikube Network Policy](https://minikube.sigs.k8s.io/docs/handbook/network_policy/), [Kubernetes NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/), [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/), [cert-manager Helm installation](https://cert-manager.io/docs/installation/helm/), and [cert-manager Certificates](https://cert-manager.io/docs/usage/certificate/).
