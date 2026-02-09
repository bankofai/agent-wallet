"""Keystore: fixed-path JSON file for account info (privateKey, apiKey, secretKey, etc.) with optional encryption."""
import json
import os
from pathlib import Path
from typing import Optional

from keystore.keystore_crypto import decrypt, encrypt, is_encrypted_payload

DEFAULT_KEYSTORE_FILENAME = ".keystore.json"
KeystoreData = dict[str, str]


def _default_path() -> str:
    return str(Path.cwd() / DEFAULT_KEYSTORE_FILENAME)


class Keystore:
    """
    Keystore: fixed-address JSON file storing account info with optional password-based encryption.
    """

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
        if not os.path.isfile(self.file_path):
            self._data = {}
            self._loaded = True
            return self._data
        with open(self.file_path, "r", encoding="utf-8") as f:
            raw = f.read()
        parsed = json.loads(raw)
        if is_encrypted_payload(parsed):
            if not self.password:
                raise ValueError(
                    "Keystore is encrypted but no password provided (KEYSTORE_PASSWORD or password=)"
                )
            plain = decrypt(parsed, self.password)
            self._data = json.loads(plain)
        else:
            self._data = parsed if isinstance(parsed, dict) else {}
        self._loaded = True
        return self._data.copy()

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.read()

    def get(self, key: str) -> Optional[str]:
        self._ensure_loaded()
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value
        self._loaded = True

    def keys(self) -> list[str]:
        self._ensure_loaded()
        return list(self._data.keys())

    def get_all(self) -> KeystoreData:
        self._ensure_loaded()
        return self._data.copy()

    def write(self) -> None:
        Path(self.file_path).parent.mkdir(parents=True, exist_ok=True)
        json_str = json.dumps(self._data, indent=2, ensure_ascii=False)
        if self.password:
            payload = encrypt(json_str, self.password)
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        else:
            with open(self.file_path, "w", encoding="utf-8") as f:
                f.write(json_str)

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
