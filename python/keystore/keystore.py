"""Keystore: fixed-path protobuf file for account info with optional encryption."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Optional

from common.logger import get_logger
from keystore.base import KeystoreBase, KeystoreData
from keystore.keystore_crypto import decrypt, encrypt, is_encrypted_payload
from keystore.keystore_proto import decode_keystore_data, encode_keystore_data

DEFAULT_KEYSTORE_FILENAME = "Keystore"


def _default_path() -> str:
    return str(Path.home() / ".agent_wallet" / DEFAULT_KEYSTORE_FILENAME)


class Keystore(KeystoreBase):
    """File-based keystore (protobuf bytes; optionally encrypted JSON wrapper)."""

    def __init__(
        self,
        file_path: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.file_path = file_path or os.environ.get("KEYSTORE_PATH") or _default_path()
        self.password = password or os.environ.get("KEYSTORE_PASSWORD")
        self._data: KeystoreData = {}
        self._loaded = False

    def get_path(self) -> str:
        return self.file_path

    def read(self) -> KeystoreData:
        log = get_logger(__name__)
        log.debug("keystore: read start path=%s", self.file_path)

        if not os.path.isfile(self.file_path):
            self._data = {}
            self._loaded = True
            log.debug("keystore: file missing, returning empty path=%s", self.file_path)
            return self._data

        with open(self.file_path, "rb") as f:
            raw = f.read()

        # Try JSON first (encrypted or legacy plaintext)
        parsed: object
        parsed_as_json = False
        try:
            txt = raw.decode("utf-8")
            parsed = json.loads(txt)
            parsed_as_json = True
        except Exception:
            parsed = None
            parsed_as_json = False

        if parsed_as_json and is_encrypted_payload(parsed):
            if not self.password:
                raise ValueError(
                    "Keystore is encrypted but no password provided (KEYSTORE_PASSWORD or password=)"
                )
            log.debug("keystore: detected encrypted JSON payload path=%s", self.file_path)
            plain = decrypt(parsed, self.password)
            # Backwards compatibility: plaintext may be JSON or base64-encoded protobuf
            try:
                maybe_json = json.loads(plain)
                if isinstance(maybe_json, dict):
                    self._data = maybe_json  # legacy JSON data
                else:
                    raise ValueError("not plain object")
            except Exception:
                buf = base64.b64decode(plain)
                self._data = decode_keystore_data(buf)
        elif parsed_as_json and isinstance(parsed, dict):
            # Legacy unencrypted JSON format
            log.debug("keystore: detected legacy JSON plaintext path=%s", self.file_path)
            self._data = parsed
        else:
            # New protobuf binary format
            log.debug("keystore: detected protobuf binary path=%s", self.file_path)
            self._data = decode_keystore_data(raw)

        self._loaded = True
        log.info(
            "keystore: read ok path=%s keys=%d encrypted=%s",
            self.file_path,
            len(self._data),
            bool(self.password),
        )
        return self._data.copy()

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.read()

    def get(self, key: str) -> Optional[str]:
        self._ensure_loaded()
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        """Set a value by key. Loads existing data first if not yet loaded."""
        self._ensure_loaded()
        self._data[key] = value

    def keys(self) -> list[str]:
        self._ensure_loaded()
        return list(self._data.keys())

    def get_all(self) -> KeystoreData:
        self._ensure_loaded()
        return self._data.copy()

    def write(self) -> None:
        """Write current data to file. Atomic via tmp+rename."""
        log = get_logger(__name__)
        Path(self.file_path).parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.file_path + ".tmp"

        proto_bytes = encode_keystore_data(self._data)
        if self.password:
            plaintext = base64.b64encode(proto_bytes).decode("ascii")
            payload = encrypt(plaintext, self.password)
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        else:
            with open(tmp_path, "wb") as f:
                f.write(proto_bytes)

        os.replace(tmp_path, self.file_path)
        log.info(
            "keystore: write ok path=%s keys=%d encrypted=%s",
            self.file_path,
            len(self._data),
            bool(self.password),
        )

    @staticmethod
    def from_file(file_path: str, password: Optional[str] = None) -> KeystoreData:
        ks = Keystore(file_path=file_path, password=password)
        return ks.read()

    @staticmethod
    def to_file(
        file_path: str,
        data: KeystoreData,
        password: Optional[str] = None,
    ) -> None:
        ks = Keystore(file_path=file_path, password=password)
        ks._data = dict(data)
        ks._loaded = True
        ks.write()

