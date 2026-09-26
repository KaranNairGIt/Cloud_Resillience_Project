# Security and key handling

## Current local prototype

- The single-process simulator generates ephemeral Ed25519 identities in memory. The independent peer demo loads one Ed25519 private key per peer and public verification keys for the committee.
- The peer HTTPS endpoint uses TLS 1.2 or newer and requires a client certificate signed by the configured CA.
- The endpoint checks that the mTLS client is a committee member, then separately verifies the signed PBFT message origin. This allows a peer to relay another node's signed message without becoming that signer.
- Dataset records remain local under ignored `data/`; the application database omits source encounter/patient IDs and exposes aggregate summaries only.
- The web dashboard binds to `127.0.0.1` and does not offer response controls.

## Development key files

`python -m resilience.cli keys generate` writes unencrypted development private keys into ignored `work/keys/private/` and public keys into `work/keys/public/`. These are for local protocol experiments only. Do not add private keys, TLS keys, or downloaded raw health records to Git or screenshots.

The CLI refuses to replace existing signing keys unless `--rotate` is supplied. Rotation changes the public verification key for that node, so update the public-key ConfigMap and all dependent peers as one planned operation; do not rotate one participant and assume the old quorum remains valid.

## Kubernetes key controls

The Kubernetes manifests use cert-manager for short-lived TLS server/client certificates and separate Kubernetes Secrets for node signing keys; public signing keys belong in a ConfigMap. The portal ServiceAccount's Role in `resilience-lab` is limited to `get` and `patch` on one named demo Deployment and one named NetworkPolicy. The optional recovery operation cannot patch objects in the peer namespace. On Minikube this demonstrates separation and rotation workflow but does not provide a managed KMS. A production environment should use a cloud KMS/HSM or external secret manager, encrypt Kubernetes Secrets at rest, restrict RBAC access, rotate keys, and audit issuance and access.

The current client certificate checks establish possession of a CA-issued committee certificate. Production identity should bind certificate SANs to the expected Kubernetes service/node identity; the prototype's Common Name committee-membership check is a local demonstration rule.
