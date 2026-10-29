"""A software passkey: just enough of an authenticator to drive WebAuthn tests."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
from typing import Any

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class SoftAuthenticator:
    """An ES256 key with "none" attestation, for one relying party."""

    def __init__(self, rp_id: str, origin: str) -> None:
        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = secrets.token_bytes(16)
        self.sign_count = 0

    def _client_data(self, kind: str, challenge: str) -> bytes:
        return json.dumps({
            "type": kind,
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": False,
        }).encode()

    def _auth_data(self, flags: int, extra: bytes = b"") -> bytes:
        rp_id_hash = hashlib.sha256(self.rp_id.encode()).digest()
        return rp_id_hash + bytes([flags]) + struct.pack(">I", self.sign_count) + extra

    def register(self, challenge: str) -> dict[str, Any]:
        """The browser's answer to `navigator.credentials.create()`."""
        numbers = self.key.public_key().public_numbers()
        cose_key = cbor2.dumps({
            1: 2,  # kty: EC2
            3: -7,  # alg: ES256
            -1: 1,  # crv: P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })
        attested = (
            bytes(16)  # AAGUID
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + cose_key
        )
        auth_data = self._auth_data(0x45, attested)  # UP | UV | AT
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64(self._client_data("webauthn.create", challenge)),
                "attestationObject": _b64(attestation),
            },
        }

    def sign_in(self, challenge: str) -> dict[str, Any]:
        """The browser's answer to `navigator.credentials.get()`."""
        self.sign_count += 1
        client_data = self._client_data("webauthn.get", challenge)
        auth_data = self._auth_data(0x05)  # UP | UV
        signature = self.key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": _b64(self.credential_id),
            "rawId": _b64(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64(client_data),
                "authenticatorData": _b64(auth_data),
                "signature": _b64(signature),
            },
        }
