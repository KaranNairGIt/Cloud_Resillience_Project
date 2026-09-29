# Live cluster runbook for the Distributed Cyber-Resilience Platform.
#
# Run each block yourself, checking the output before moving to the next one.
# Do NOT dot-source or run this whole file unattended: several steps wait on
# real cluster state and one waits ~4 minutes for trust-window spacing, and if
# an earlier step failed silently you want to know before the next one runs.
#
# Prerequisite already confirmed: Docker Desktop is installed and running.
# Everything below is scoped to this project only; it does not touch any
# other cluster, namespace, or Docker image on your machine.

# ============================================================
# Step 0 - install kubectl and minikube (skip if already present)
# ============================================================
# winget is the built-in Windows package manager (Windows 10 2004+/11).
# If this fails, install manually from:
#   kubectl:  https://kubernetes.io/docs/tasks/tools/install-kubectl-windows/
#   minikube: https://minikube.sigs.k8s.io/docs/start/
winget install -e --id Kubernetes.kubectl
winget install -e --id Kubernetes.minikube

# Close and reopen PowerShell after this step so PATH picks up the new tools,
# then confirm both are visible:
kubectl version --client
minikube version

# ============================================================
# Step 1 - start Minikube with a policy-enforcing CNI
# ============================================================
# --cni=calico matters: the default Kindnet CNI does not enforce
# NetworkPolicy, and NetworkPolicy is how this project isolates a
# compromised workload. Without Calico the response would "succeed" without
# actually blocking traffic.
minikube start --cni=calico --cpus=2 --memory=3000

# Sanity check: this should print calico-node pods as Running.
kubectl get pods -n kube-system | Select-String calico

# ============================================================
# Step 2 - build the project image inside Minikube's Docker
# ============================================================
cd C:\Users\Karan\Desktop\MajorProject
minikube image build -t distributed-cyber-resilience:dev .

# ============================================================
# Step 3 - deploy (namespace, cert-manager, RBAC, PKI, workloads)
# ============================================================
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

# Local PBFT signing keys (separate from the mTLS certs above). Development
# material only - already gitignored under work/keys, never reused elsewhere.
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

# Before this next apply, confirm the API server ClusterIP matches what
# k8s/network-policy.yaml allows (default Minikube: 10.96.0.1). If it
# differs, edit that file's ipBlock before applying.
kubectl get service kubernetes -n default -o jsonpath='{.spec.clusterIP}'

kubectl apply -f k8s/peer-state.yaml
kubectl apply -f k8s/network-policy.yaml
kubectl apply -f k8s/demo-workload.yaml
kubectl apply -f k8s/agents.yaml

kubectl rollout status deployment/resilience-demo-records -n resilience-lab --timeout=120s
kubectl rollout status deployment/resilience-peer-portal -n resilience --timeout=120s
kubectl rollout status deployment/resilience-peer-identity -n resilience --timeout=120s
kubectl rollout status deployment/resilience-peer-records -n resilience --timeout=120s
kubectl rollout status deployment/resilience-peer-database -n resilience --timeout=120s

# All four peers and the demo workload should show Ready here.
kubectl get pods,services -n resilience
kubectl get pods -n resilience-lab

# ============================================================
# Step 4 - the actual measured run
# ============================================================
# This drives the deployment above and times it for real: the five BFT
# scenarios, a genuine-compromise isolate/restore cycle (polled every 0.25s),
# the full trust-recovery climb (respects the 30s window spacing - expect
# ~4 minutes for this part alone), and a tainted-restore check. Writes a
# timestamped JSON to work/live-results/.
python -m resilience.cli live-validate

# To iterate faster while debugging deployment issues, skip the multi-minute
# trust climb:
#   python -m resilience.cli live-validate --skip-trust-recovery

# ============================================================
# Step 5 - inspect, then tear down when done
# ============================================================
kubectl logs deployment/resilience-peer-portal -n resilience
Get-Content work/live-results/*.json | Select-Object -Last 1

# minikube stop        # pause, keeps the cluster for next time
# minikube delete      # full teardown
