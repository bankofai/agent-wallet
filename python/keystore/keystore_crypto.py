"""Keystore encryption: scrypt + AES-256-GCM (compatible with TypeScript payload)."""
import base64
import hashlib
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
SALT_LEN = 16
IV_LEN = 12
TAG_LEN = 16
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1


def _derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LEN,
    )


def encrypt(plaintext: str, password: str) -> dict[str, Any]:
    """Encrypt plaintext with password. Returns payload (version, salt, iv, tag, data) matching TS."""
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    plainbytes = plaintext.encode("utf-8")
    ct_with_tag = aes.encrypt(iv, plainbytes, None)
    ciphertext_only = ct_with_tag[:-TAG_LEN]
    tag = ct_with_tag[-TAG_LEN:]
    return {
        "version": 1,
        "salt": salt.hex(),
        "iv": iv.hex(),
        "tag": tag.hex(),
        "data": base64.b64encode(ciphertext_only).decode("ascii"),
    }


def decrypt(payload: dict[str, Any], password: str) -> str:
    """Decrypt payload with password. Returns plaintext string."""
    salt = bytes.fromhex(payload["salt"])
    iv = bytes.fromhex(payload["iv"])
    tag = bytes.fromhex(payload["tag"])
    if len(salt) != SALT_LEN:
        raise ValueError(f"Invalid salt length: expected {SALT_LEN}, got {len(salt)}")
    if len(iv) != IV_LEN:
        raise ValueError(f"Invalid iv length: expected {IV_LEN}, got {len(iv)}")
    if len(tag) != TAG_LEN:
        raise ValueError(f"Invalid tag length: expected {TAG_LEN}, got {len(tag)}")
    # Always decode data as base64 (matches TypeScript encrypt which always outputs base64)
    ciphertext_only = base64.b64decode(payload["data"])
    ciphertext = ciphertext_only + tag
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    plainbytes = aes.decrypt(iv, ciphertext, None)
    return plainbytes.decode("utf-8")


def is_encrypted_payload(obj: Any) -> bool:
    """Return True if obj looks like an encrypted payload (version, salt, iv, tag, data)."""
    if not isinstance(obj, dict):
        return False
    return (
        obj.get("version") == 1
        and isinstance(obj.get("salt"), str)
        and isinstance(obj.get("iv"), str)
        and isinstance(obj.get("tag"), str)
        and isinstance(obj.get("data"), str)
    )
