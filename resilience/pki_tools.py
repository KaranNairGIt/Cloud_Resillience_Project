"""Create throwaway local ECDSA certificates for development mTLS tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .engine import SERVICES


def generate_dev_pki(directory: Path, *, force: bool = False) -> dict:
    """Generate a private development CA and dual-use node certificates locally."""
    directory.mkdir(parents=True, exist_ok=True)
    existing = [p for p in [directory / "ca.key", directory / "ca.crt"]
                if p.exists()]
    if existing and not force:
        raise FileExistsError("Development PKI already exists; use --rotate to replace it")
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "majorproject-local-dev-ca")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1))
               .not_valid_after(now + timedelta(days=365))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False,
                                            key_agreement=False, key_cert_sign=True,
                                            crl_sign=True, encipher_only=False,
                                            decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))
    (directory / "ca.key").write_bytes(ca_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (directory / "ca.crt").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    for node_id in SERVICES:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
        sans = [x509.DNSName("localhost"), x509.DNSName(node_id),
                x509.DNSName(f"resilience-peer-{node_id}"),
                x509.DNSName(f"resilience-peer-{node_id}.resilience.svc.cluster.local"),
                x509.IPAddress(ip_address("127.0.0.1"))]
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                # Python 3.13+ enables strict X.509 verification, which requires these identifiers.
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                                      ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        (directory / f"{node_id}.key").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        (directory / f"{node_id}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return {"directory": str(directory), "nodes": list(SERVICES),
            "ca_certificate": str(directory / "ca.crt"),
            "warning": "Development-only unencrypted private keys; do not use in production."}
