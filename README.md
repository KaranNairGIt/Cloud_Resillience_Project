# Distributed Cyber-Resilience Platform

A local capstone implementation of the project brief. It models a four-service healthcare application, loads a publicly released hospital-encounter dataset, runs safe synthetic attack scenarios, shows every evidence/quorum parameter, and demonstrates signed PBFT phases plus a mutual-TLS peer-message endpoint.

All project files, downloaded dataset files, generated keys, certificates, and test artifacts belong under this project directory. Raw health records and local secrets are excluded by `.gitignore`.

## Start here

See [Operations Guide](docs/OPERATIONS.md) for exact Windows commands, scenario explanations, dashboard use, dataset setup, and peer mTLS steps. See [Glossary](docs/GLOSSARY.md) for plain-language definitions of the technical terms.

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m resilience.cli demo
```

To start the read-only dashboard, run `python -m resilience.cli serve` and then, in a second terminal, run `python -m resilience.cli trigger genuine-compromise`.

## Implemented phases

1. **Resilience loop:** typed signed observations, trust-weighted diversity scoring, quarantine/recovery, validation, and trust-gated reintegration. The local simulator shows per-window trust trajectory and requires two clean windows before each stage promotion; those are model ticks rather than real-time delays.
2. **Public clinical demo data:** UCI’s 101,766-row hospital encounter set is downloaded with attribution, validated, and loaded into local SQLite after source patient/encounter IDs are removed from the demo copy.
3. **Voting and PBFT model:** four-node committee, `n=4`, `f=1`, `2f+1=3` quorum, typed evidence thresholds, signed `PRE-PREPARE`, `PREPARE`, `COMMIT`, `VIEW-CHANGE`, and certificate-bound `NEW-VIEW` messages. Networked view changes carry the sender's signed prepared certificate when available, and the report shows its signers and selected digest. The dashboard and CLI reports show thresholds and the decision path.
4. **Networked replicas:** each peer is an independent process with its own Ed25519 private key and durable SQLite round snapshots backed by a node-signed, hash-chained transition journal. A coordinator relays signed observations/protocol messages over mTLS; every replica checks evidence, signatures, sequence/view, and quorum locally. Lagging peers can replay the source's committed rounds in ascending sequence order, validating each 2f+1 prepare/commit proof before journaling it. The integration test starts four real local mTLS servers, exercises six scenarios including a prepared-primary failure and multi-round state-loss recovery, and reloads committed state from disk.
5. **Response workflow:** a committed `CONTAIN` result drives quarantine, known-good restore, validation and staged reintegration. By default this is reported as a simulation; an explicit Kubernetes option applies the workflow only to a synthetic app in an isolated lab namespace.
6. **Kubernetes packaging:** four peer Deployments/Services with one persistent claim each, a synthetic records app, scoped response RBAC, cert-manager certificates, per-peer key Secrets, public key ConfigMap, and default-deny/peer-mesh NetworkPolicies are defined.

## Remaining environment verification

See [Kubernetes guide](docs/KUBERNETES.md) for deployment steps and the opt-in `--apply-kubernetes-response` operation. No Kubernetes cluster, `kubectl`, Helm, YAML parser, or container runtime is installed in this environment, so the manifests and in-cluster API actions have not been deployed or validated by Kubernetes here. The network consensus is an educational PBFT-style implementation, not a production consensus library: signed journals detect snapshot/history modification when the journal remains available, but the prototype lacks rollback anchoring, crash-safe protocol recovery, and a guarantee that every possible committed sequence is retained by an online peer. It transfers available committed rounds in ascending order with a valid quorum certificate; this is not a guarantee of a gap-free replicated log. Transport retries are bounded, and a failed primary request triggers a signed view change; there are no autonomous round deadlines while idle. Each replica rejects stale sequence replays. Each replica caches one request per sequence; if a valid prepared certificate conflicts with that cached request, the new view safely stops rather than installing a different proposal. Do not use it to protect clinical or production workloads.

The local attack inputs are synthetic and never exploit software. The optional Kubernetes simulator changes only an in-memory flag in the dedicated demo app and confines recovery to that app's Deployment and NetworkPolicy. The clinical dataset is historical demonstration data and is not for clinical decisions. More details: [Operations Guide](docs/OPERATIONS.md), [Glossary](docs/GLOSSARY.md), [Dataset handling](docs/DATASET.md), [Voting and consensus](docs/VOTING.md), [Security model](docs/SECURITY.md).
