"""Ephemeral Ed25519 node identities used by the local PBFT simulation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


@dataclass
class NodeKeyring:
    private: dict[str, Ed25519PrivateKey]
    public: dict[str, Ed25519PublicKey]

    @classmethod
    def generate(cls, node_ids: list[str]) -> "NodeKeyring":
        private = {node_id: Ed25519PrivateKey.generate() for node_id in node_ids}
        return cls(private, {node_id: key.public_key() for node_id, key in private.items()})

    @classmethod
    def load(cls, private_node: str, private_path: Path,
             public_paths: dict[str, Path]) -> "NodeKeyring":
        """Load one node's private key and the committee's public verification keys."""
        private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("PBFT signing key must be Ed25519")
        public = {node_id: serialization.load_pem_public_key(path.read_bytes())
                  for node_id, path in public_paths.items()}
        if not all(isinstance(key, Ed25519PublicKey) for key in public.values()):
            raise ValueError("All PBFT public keys must be Ed25519")
        public[private_node] = private_key.public_key()
        return cls({private_node: private_key}, public)

    def sign(self, node_id: str, payload: bytes) -> bytes:
        return self.private[node_id].sign(payload)

    def verify(self, node_id: str, payload: bytes, signature: bytes) -> bool:
        key = self.public.get(node_id)
        if key is None:
            return False
        try:
            key.verify(signature, payload)
            return True
        except InvalidSignature:
            return False

    def private_pem(self, node_id: str) -> bytes:
        return self.private[node_id].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def public_pem(self, node_id: str) -> bytes:
        return self.public[node_id].public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
