"""Digital signing for certificates.

A real RSA keypair (not just a hash) is used to sign certificate content.
The private key is generated on first run and stored under
``instance/keys/`` which is outside the source repository (gitignored) --
never commit it. This is a demo-appropriate key management approach: for
production, the private key should live in an HSM / secrets manager, not on
local disk.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.config import settings

_PRIVATE_KEY_PATH = settings.keys_dir / "certificate_signing_key.pem"
_PUBLIC_KEY_PATH = settings.keys_dir / "certificate_signing_key.pub.pem"


def _generate_keypair() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    settings.keys_dir.mkdir(parents=True, exist_ok=True)
    _PRIVATE_KEY_PATH.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    _PUBLIC_KEY_PATH.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        import os

        os.chmod(_PRIVATE_KEY_PATH, 0o600)
    except OSError:
        pass


def _load_private_key():
    if not _PRIVATE_KEY_PATH.exists():
        _generate_keypair()
    return serialization.load_pem_private_key(_PRIVATE_KEY_PATH.read_bytes(), password=None)


def _load_public_key():
    if not _PUBLIC_KEY_PATH.exists():
        _generate_keypair()
    return serialization.load_pem_public_key(_PUBLIC_KEY_PATH.read_bytes())


def public_key_fingerprint() -> str:
    public_bytes = _load_public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_bytes).hexdigest()


def sign_bytes(data: bytes) -> str:
    private_key = _load_private_key()
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


def verify_signature(data: bytes, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
    except Exception:
        return False
    public_key = _load_public_key()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
