# Evidence weights and PBFT voting

The engine exposes these settings in its JSON report, and the dashboard renders the same values in a voting-parameters table.

## Evidence authorization

1. Verify the reporter's Ed25519 signature over the canonical evidence fields.
2. Signed evidence includes a `finding` (`anomaly` or `normal`) in addition to its category. Only anomaly findings contribute to containment. A quorum of normal findings contradicting an anomaly claim lowers that reporter's trust by 25 points after the round commits.
3. For each evidence type, retain the single strongest `confidence × (reporter trust / 100) × type weight` value. Duplicate observations of the same type do not add together. Reporter scores are derived from committed rounds on each peer; the coordinator uses only scores that at least `2f+1` replicas report identically.
4. Sum the strongest values from distinct anomaly evidence types and cap the total at `1.0`.
5. Require at least three distinct signed anomaly reporters, at least two distinct anomaly evidence types, and a weighted score of at least `0.60` before proposing `CONTAIN`.
6. If any condition fails, propose `NOOP` instead. A committed NOOP supported by at least three signed normal findings raises those reporters' trust by five points, capped at 100.

All four evidence-type weights (`network`, `process`, `file-integrity`, `auth`) currently equal `1.0`. They are demonstration parameters, visible in the report; there is no hidden learned weighting.

## PBFT phase sequence

- Four replicas form the committee: `n = 4`.
- The theoretical Byzantine bound is `f = floor((n - 1) / 3) = 1`.
- A matching phase quorum is `2f + 1 = 3` signed messages.
- The primary sends `PRE-PREPARE` with the value digest.
- Replicas send `PREPARE` only for the proposal authorized by evidence scoring.
- After a 3-message prepare certificate, replicas send `COMMIT`.
- Three matching commits finalize the operation in this model.
- A silent or invalid primary triggers a 3-of-4 signed `VIEW-CHANGE` certificate. Each message carries a signed prepared quorum when the sender has one, and signs the digest of that proof.
- The next primary signs `NEW-VIEW`, binding the exact certificate; each replica verifies its view-change messages and attached prepare certificates before moving to that view. The report lists view-change signers, prepared-certificate signers and the selected digest.

The JSON report includes the phase, view, digest, message signers, threshold, commit value, checkpoint transfers, trust scores before/after commit and per-peer trust audit. Replicas derive trust changes from the same committed signed findings, rebuild trust by replaying committed rounds after restart, and apply those values to future evidence scores. Run `cluster simulate false-evidence` followed by `cluster simulate healthy-window` with new sequences to observe trust decay and recovery. The report also includes bounded transport attempts and each peer's committed-sequence high-water mark. Before accepting a new round, the coordinator asks lagging peers to replay committed checkpoints after their high-water mark, in ascending sequence order; each peer independently validates the signed 2f+1 prepare/commit certificate and journals every recovered snapshot. Replay is limited to rounds the source retains and does not promise a gap-free log. Peers reject stale sequence replays; the coordinator blocks before injection when `2f+1` active peers report the sequence committed, so one Byzantine watermark report cannot veto a request. Only the primary's authenticated mTLS identity may pre-cache the request, and an uncommitted proposal does not advance the high-water mark. The coordinator retries transient connection or service failures at most twice; duplicate PREPARE messages return the peer's same signed COMMIT, so a lost HTTP response does not make that transition unrecoverable. Run `cluster simulate prepared-primary-failure` to observe prepared-certificate signers and the selected digest in the network report. A two-compromised scenario has only two honest replicas, so it cannot reach the three-message quorum. That failure is expected and deliberately reported.

## Running the network replica demo

The peer services now keep separate state and Ed25519 signing keys, and exchange messages over mTLS. For one local machine, start each peer in its own PowerShell window after generating the development keys and certificates:

```powershell
python -m resilience.cli keys generate
python -m resilience.cli pki generate-dev
python -m resilience.cli peer serve --node-id portal --host 127.0.0.1 --port 8766
python -m resilience.cli peer serve --node-id identity --host 127.0.0.1 --port 8767
python -m resilience.cli peer serve --node-id records --host 127.0.0.1 --port 8768
python -m resilience.cli peer serve --node-id database --host 127.0.0.1 --port 8769
```

In another window, run `python -m resilience.cli cluster simulate genuine-compromise --ports 8766 8767 8768 8769`. Choose any listed synthetic scenario. The JSON output prints observations, evidence score, active members, each phase signer, quorum size, primary/view and each peer's local final state. A committed CONTAIN also runs a safe recovery simulation: quarantine, restore a simulated known-good snapshot, validate, then promote through four trust stages. To prove failed validation blocks reintegration, add `--fail-check health`. The coordinator relays messages but replicas independently validate signatures and policy. Local mTLS client identity is portal; the signed PBFT message identifies its own node, so a relay cannot impersonate a signer.

With the Kubernetes demo deployed, add `--kubernetes --apply-kubernetes-response` to inject an anomaly into and recover the lab workload. Its RBAC is restricted to one named Deployment and NetworkPolicy in `resilience-lab`. The command returns the simulation result when these flags are absent.

## Scope and limitations

The network integration is an educational PBFT-style implementation for a single request sequence. It verifies separate signed replicas, evidence gates, matching prepare/commit quorums, signed `NEW-VIEW` certificates and per-node SQLite snapshots. A view-change message signs the digest of its attached prepared certificate. The new primary verifies these certificates and identifies the highest prepared view; because replicas cache one proposal per sequence, they safely reject a new-view certificate whose selected digest differs from that cached request rather than installing an alternate proposal. Lagging peers can import the latest committed snapshot after validating its signed prepare/commit quorum; the implementation does not transfer a complete ordered history or fill every sequence gap. Transport retries are bounded at two attempts, and a failed primary request automatically triggers a signed view change; there is still no background round deadline or leader-suspicion timer while a request is idle. Duplicate PREPARE handling is idempotent. Each snapshot write is accompanied in the same SQLite transaction by a node-signed hash-chain entry. On restart, each peer validates the journal chain, current snapshot correspondence, saved protocol signatures and quorum state; failure to persist makes that peer stop accepting protocol messages. This detects altered or missing journal entries while the trusted head remains intact; it cannot detect a full rollback of both the journal and its head without an external anchor. It still does **not** claim a full production PBFT implementation: the journal is local rather than replicated, and the system lacks alternate-request installation and crash-safe protocol recovery. The Kubernetes response adapter is scoped to one synthetic Deployment and one NetworkPolicy, but it hasn't been exercised on a live cluster here. Do not connect this capstone prototype to actual clinical or production systems.
