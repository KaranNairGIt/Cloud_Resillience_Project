# Glossary in plain language

## Cyber-resilience terms

- **Workload/service:** One application component, such as the patient portal or records API.
- **Resilience agent:** The security-side process that observes a workload, shares signed evidence, and takes part in a response decision.
- **Telemetry:** Measurements or event descriptions collected from a running service. In the current attack scenarios, telemetry is generated synthetically.
- **Evidence:** A structured, digitally signed observation about a target: type, finding (`anomaly` or `normal`), confidence, time and reporter.
- **Confidence:** A number from 0 to 1 expressing how strongly one observation supports a claim. It is not a probability that the node is malicious.
- **Evidence diversity:** Corroboration from different observation categories. Repeating ten network alerts does not count as ten different kinds of evidence.
- **Trust score:** A score from 0 to 100, independently derived by replicas from committed signed findings. It down-weights later anomaly reports from reporters whose claims were contradicted by at least three normal reports. Contradicted claims and committed isolation each lower the affected member's score by 25 points; committed normal windows add five points to participating reporters, up to 100. The local workload reintegration model separately gains ten points per simulated clean recovery window.
- **Quarantine/isolation:** Temporarily taking a workload out of service or restricting its connectivity while it is checked. Current isolation only appears in the simulator's response output; it does not apply a Kubernetes NetworkPolicy.
- **Recovery:** In the simulation, restoring a named known-good demo snapshot. The Kubernetes deployment currently does not roll back a real container image.
- **Validation:** Simulated integrity, health and behavior checks after restoration. Failed checks keep the target quarantined and block reintegration.
- **Reintegration:** Promoting a recovered service through restricted, monitored, peer-validated and full access. Each promotion requires two consecutive clean monitoring windows and the next stage's trust threshold. An unhealthy window breaks the streak, lowers trust, and can demote the stage. These windows are model ticks, not elapsed wall-clock time. The Kubernetes adapter persists the stage and streak on the lab NetworkPolicy and applies the same gates after committed healthy findings.
- **Availability:** The fraction of modeled service checkpoints that remain available. Current numbers are coarse simulator values.

## Voting and Byzantine faults

- **Replica/node:** One member of the distributed security committee. This prototype has four named nodes.
- **`n`:** Total committee size. Here `n = 4`.
- **Byzantine node:** A participant that may lie, send conflicting messages, refuse to vote, or stop responding.
- **`f`:** Maximum faulty replicas the protocol is designed to tolerate. PBFT requires `n >= 3f + 1`; for `n = 4`, `f = 1`.
- **Quorum:** The minimum number of matching, valid messages needed to move forward. Here `2f + 1 = 3`.
- **Primary/leader:** The replica that proposes the operation for a PBFT view. The primary role rotates after a view change.
- **View:** A round with a particular primary. If the primary stalls or proposes a value that conflicts with valid evidence, replicas change views.
- **Sequence/high-water mark:** The request number and highest request number a peer has committed. Peers reject lower or reused committed request numbers to prevent replay; merely caching an uncommitted proposal does not advance it. This prototype does not yet guarantee a gap-free replicated command log.
- **Checkpoint:** A saved committed round with signed quorum proof. A lagging peer can validate and install committed rounds retained by a source in ascending sequence order; rounds absent from all sources and gaps in the log cannot be recovered by this prototype.
- **`PRE-PREPARE`:** The primary signs and proposes one operation/digest.
- **`PREPARE`:** Replicas sign that they received the same proposal.
- **`COMMIT`:** Replicas confirm the prepared value; a 3-of-4 commit certificate makes it final in the model.
- **View change:** A signed quorum that moves the committee to the next primary after a leader failure.
- **`NEW-VIEW`:** The next primary's signed announcement containing at least `2f+1` view-change messages and their prepared proofs. Replicas verify these before accepting the new leader; this prototype stops if the selected request is not the one already cached.
- **`NOOP`:** A valid consensus result that means “take no containment action.” It prevents a single false accusation from being treated as approval.
- **PBFT:** Practical Byzantine Fault Tolerance, a consensus protocol family that can make progress with up to `f` Byzantine replicas among `3f+1` replicas under its assumptions. This project has an educational networked single-round demonstration with signatures and prepared-proof-carrying view changes; it does not yet implement production crash recovery, alternate-request state transfer, timeout handling or complete proposal installation.

## Cryptography and deployment

- **Digital signature:** A private-key operation that lets peers check which node signed a message and whether it changed afterward. This project uses Ed25519 signatures for evidence and PBFT messages.
- **Public/private keypair:** The private half signs and must stay secret; the public half verifies and can be shared.
- **mTLS (mutual Transport Layer Security):** An encrypted network connection where the server verifies the client certificate and the client verifies the server certificate. Regular HTTPS often authenticates only the server; mTLS authenticates both ends.
- **CA (Certificate Authority):** The root that signs certificates so peers can verify who they are talking to.
- **PKI (Public Key Infrastructure):** The certificates, CA, identities, trust rules and renewal process used to establish secure connections.
- **KMS/HSM:** A Key Management Service or Hardware Security Module that stores and uses private keys without exposing them as ordinary application files. The current local key generator is not a KMS.
- **Kubernetes Pod:** The running unit that contains an application process or container.
- **Kubernetes Service:** A stable DNS name and network endpoint for reaching a set of Pods.
- **Secret:** A Kubernetes object intended for confidential configuration, such as a private key. A Secret is not automatically a production-grade KMS; cluster encryption and access control still matter.
- **ConfigMap:** Kubernetes storage for non-secret configuration, such as public verification keys.
- **NetworkPolicy:** A Kubernetes rule that restricts which Pods can connect to which other Pods.
- **Minikube:** A local Kubernetes cluster intended for development and learning.
- **Container image:** A packaged filesystem and application used to start a container consistently.
- **SQLite:** A local, file-based relational database. The demo copy of clinical data is stored here.
- **Encounter:** One hospital admission record. The UCI dataset has 101,766 encounter rows; that does not mean 101,766 distinct people.
- **Readmission label:** The UCI target says whether the encounter was followed by another admission within 30 days (`<30`), after 30 days (`>30`), or none (`NO`). It is a historical dataset label, not a prediction from this project.
- **CC BY 4.0:** Creative Commons Attribution 4.0. It allows reuse and adaptation when attribution and the license are retained.
