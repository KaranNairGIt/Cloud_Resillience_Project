# Operations Guide

These steps are for Windows PowerShell, run from `C:\Users\Karan\Desktop\MajorProject`.

## Install and verify

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The only runtime package is `cryptography`; the data store, command-line program, HTTPS server and dashboard use Python's standard library.

## Simulate an attack

Run one scenario and print its full JSON evidence, corroboration, PBFT phases, metrics and events:

```powershell
python -m resilience.cli simulate genuine-compromise
```

Available scenarios:

| Command scenario | Synthetic event | Expected result |
| --- | --- | --- |
| `genuine-compromise` | Diverse synthetic observations identify abnormal records-service behavior. | Contain, restore, validate, then reintegrate in trust-gated stages. |
| `false-evidence` | Portal agent makes one high-confidence anomaly accusation about a healthy target; other peers sign normal findings. | Other agents reject the proposal; PBFT commits `NOOP`; portal trust falls and corroborating normal reporters gain trust. |
| `healthy-window` | All agents make signed normal findings about a healthy target. | PBFT commits `NOOP`; participating reporters regain five trust points. |
| `silent-node` | Database agent stops sending observations/votes during a genuine anomaly. | Three remaining replicas can reach quorum and recover the affected service. |
| `block-vote` | Portal, the current primary, refuses to lead a legitimate containment decision. | A 3-of-4 view-change selects a new primary, which completes the PBFT phases. |
| `prepared-primary-failure` | Portal stops after a prepare quorum has formed. | Remaining peers include signed prepared proofs in view change; the next primary carries the prepared digest into a new round and finishes containment. This scenario is available in the networked `cluster simulate` command. |
| `two-compromised` | Portal and identity agents are marked Byzantine. | Their two honest peers cannot make a 3-of-4 commit; containment is withheld. |

`python -m resilience.cli demo` is a shortcut for `genuine-compromise`.

## Dashboard and command workflow

Terminal 1:

```powershell
python -m resilience.cli serve
```

Open `http://127.0.0.1:8765/`. The dashboard is read-only: it displays node state, trust, current voting parameters, the most recent simulation, and aggregate clinical data. It has no action buttons.

Terminal 2:

```powershell
python -m resilience.cli trigger false-evidence
```

This CLI command sends the named synthetic scenario to the local server. The dashboard refreshes automatically. The server binds only to loopback (`127.0.0.1`).

## Clinical dataset

```powershell
python -m resilience.cli dataset fetch
python -m resilience.cli dataset import
python -m resilience.cli dataset summary
```

`fetch` retrieves and validates the official UCI archive. `import` builds `data/clinical.db` with a generated demo row number and without the source `encounter_id` or `patient_nbr`. `summary` prints aggregate counts. Raw source files and the SQLite copy stay in ignored `data/`; do not commit or publish them.

## Local peer keys and mTLS listener

Generate one local signing keypair per consensus node:

```powershell
python -m resilience.cli keys generate
```

This writes development-only Ed25519 private keys under `work/keys/private/` and public verification keys under `work/keys/public/`. The private keys are ignored by Git. Re-running is refused; use `--rotate` only when you intend to replace all deployed trust keys. Do not use these unencrypted development keys in a real deployment.

Create a self-signed development CA and a client/server certificate for each peer:

```powershell
python -m resilience.cli pki generate-dev
```

The files go to ignored `work/pki/`. These certificates are for the local integration demonstration only; the Kubernetes manifests use cert-manager-issued leaf certificates.

The peer listener requires TLS server certificate/key files and a CA certificate in `work/pki`, named for the node, plus its PBFT signing key and all four public keys:

```powershell
python -m resilience.cli peer serve --node-id portal --host 127.0.0.1 --port 8766
```

The listener requires a CA-valid client certificate from a committee member, and separately verifies the Ed25519 protocol-message signature. A committee member may relay another node's signed message; the certificate authenticates the relay connection, while the Ed25519 signature authenticates the original protocol sender. Each peer stores round snapshots and a node-signed hash-chain journal in `work/replica-state/<node>.sqlite3`; the CLI's `--state-dir` changes the containing directory.

## Run the networked replica simulation

Start one peer per PowerShell window (the keys and certificates from the previous section are required):

```powershell
python -m resilience.cli peer serve --node-id portal --host 127.0.0.1 --port 8766
python -m resilience.cli peer serve --node-id identity --host 127.0.0.1 --port 8767
python -m resilience.cli peer serve --node-id records --host 127.0.0.1 --port 8768
python -m resilience.cli peer serve --node-id database --host 127.0.0.1 --port 8769
```

In a fifth window, invoke any synthetic scenario:

```powershell
python -m resilience.cli cluster simulate genuine-compromise --ports 8766 8767 8768 8769
```

The command prints each signed observation, voting parameters, quorum proof, view and each replica's result. The default request sequence is a timestamp; `--sequence N` lets you set it explicitly. Peers reject stale sequence replays. The coordinator blocks a request only when at least `2f+1` active peers report a committed high-water mark that includes it, so one Byzantine peer cannot veto requests by lying about its watermark. If only some peers have committed a higher sequence, local checks may reject it and the round may fail to reach quorum. The coordinator checks before injecting a simulated workload anomaly. Proposal pre-caching is accepted only from the current primary's mTLS identity. An uncommitted proposal does not advance the committed high-water mark. `two-compromised` stops safely with only two active replicas, below the three-message quorum. The `false-evidence` scenario shows the primary's unsupported CONTAIN proposal being rejected, then a NOOP commit after a view change. Network requests are retried at most twice for transient failures. If a primary request still fails, the coordinator now attempts a signed view change automatically; there is no background timer for a leader that is idle without a request.

On a committed `CONTAIN`, the local simulator reports the response sequence: quarantine, restore a known-good demo snapshot, check integrity/health/behavior, then model trust recovery through restricted, monitored, peer-validated and full service. Each stage promotion requires two consecutive clean monitoring windows; trust rises by ten points per modeled window. An unhealthy window resets the streak, lowers trust, and may demote the stage. The JSON includes the trust trajectory and number of recovery ticks. These are deterministic simulation ticks, not elapsed wall-clock time. The Kubernetes adapter persists the current stage and clean-window count on the lab NetworkPolicy and applies the same thresholds after committed `healthy-window` rounds. Use `cluster simulate healthy-window --trust-target records --kubernetes --apply-kubernetes-response --sequence N` with a new sequence number for each clean window. To demonstrate that an unhealthy restored workload stays quarantined, run `cluster simulate genuine-compromise --ports 8766 8767 8768 8769 --fail-check health`. A committed NOOP or missing quorum produces no recovery action.

Each peer has its own durable SQLite snapshots and signed journal and validates the journal chain, saved protocol signatures and quorums when reloading. Before a new round, the coordinator can request committed checkpoints after a lagging peer's watermark from an available peer; it installs each returned round in ascending sequence order, with the receiver independently verifying the signed quorum proof before journaling that round. This recovers all committed rounds retained by that source, but cannot fill gaps the source itself does not retain or guarantee a gap-free log. A malformed or unverifiable saved state stops that peer instead of silently starting from an empty history. Use a fresh explicit `--state-dir` for a clean lab run; don't delete a live peer database as a recovery step. The journal is local and can be rolled back with its head absent an external anchor. See [Voting and consensus](VOTING.md) for the protocol boundaries.

For the Minikube image, cert-manager certificates, and four peer-listener pods, follow the [Kubernetes deployment guide](KUBERNETES.md). The Kubernetes manifest has not been run in a cluster in this environment.

The Kubernetes guide also defines a dedicated `resilience-lab` workload. After deploying it, `cluster simulate genuine-compromise --kubernetes --apply-kubernetes-response` injects only an in-memory synthetic anomaly, obtains the distributed decision, and applies the namespace-scoped quarantine/restore workflow after a committed containment. Without `--apply-kubernetes-response`, the cluster command stays non-mutating and reports the recovery simulation only.

## Compare architectures

```powershell
python -m resilience.cli experiment --repeats 3
```

The comparison baseline is an illustrative model. All timings and availability percentages are simulator checkpoints, not empirical measurements from Kubernetes.
