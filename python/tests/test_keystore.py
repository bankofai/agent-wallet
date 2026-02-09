import json
import os
import tempfile
import shutil

import pytest

from keystore.keystore import Keystore
from keystore.keystore_crypto import encrypt, decrypt, is_encrypted_payload
from keystore.keystore_proto import encode_keystore_data, decode_keystore_data


# ---------- fixtures ----------

@pytest.fixture
def tmp_dir():
    d = tempfile.mkdtemp(prefix="ks-test-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def tmp_file(tmp_dir, name):
    return os.path.join(tmp_dir, name)


# ============================================================
# Protobuf encode / decode
# ============================================================

class TestKeystoreProto:
    def test_roundtrip_empty(self):
        buf = encode_keystore_data({})
        assert len(buf) == 0
        assert decode_keystore_data(buf) == {}

    def test_roundtrip_single_entry(self):
        data = {"privateKey": "abc123"}
        buf = encode_keystore_data(data)
        assert len(buf) > 0
        assert decode_keystore_data(buf) == data

    def test_roundtrip_multiple_entries(self):
        data = {
            "privateKey": "deadbeef",
            "apiKey": "my-api-key",
            "secretKey": "super-secret",
            "address": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
        }
        buf = encode_keystore_data(data)
        assert decode_keystore_data(buf) == data

    def test_unicode_values(self):
        data = {"note": "hello world \U0001f600", "key": "\u00e9\u00e8\u00ea"}
        buf = encode_keystore_data(data)
        assert decode_keystore_data(buf) == data

    def test_truncated_buffer_raises(self):
        data = {"key": "value"}
        buf = encode_keystore_data(data)
        truncated = buf[: len(buf) - 3]
        with pytest.raises(ValueError):
            decode_keystore_data(truncated)


# ============================================================
# Crypto encrypt / decrypt
# ============================================================

class TestKeystoreCrypto:
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "hello world"
        password = "test-password"
        payload = encrypt(plaintext, password)
        assert is_encrypted_payload(payload)
        assert payload["version"] == 1
        result = decrypt(payload, password)
        assert result == plaintext

    def test_wrong_password_fails(self):
        payload = encrypt("secret", "correct-password")
        with pytest.raises(Exception):
            decrypt(payload, "wrong-password")

    def test_different_ciphertext_for_same_input(self):
        plaintext = "same input"
        password = "pw"
        a = encrypt(plaintext, password)
        b = encrypt(plaintext, password)
        assert a["salt"] != b["salt"]
        assert a["iv"] != b["iv"]
        assert decrypt(a, password) == plaintext
        assert decrypt(b, password) == plaintext

    def test_is_encrypted_payload_rejects_non_payloads(self):
        assert is_encrypted_payload(None) is False
        assert is_encrypted_payload(42) is False
        assert is_encrypted_payload({}) is False
        assert is_encrypted_payload({"version": 2, "salt": "", "iv": "", "tag": "", "data": ""}) is False
        assert is_encrypted_payload({"version": 1, "salt": "a", "iv": "b", "tag": "c", "data": "d"}) is True


# ============================================================
# Keystore class — unencrypted (protobuf)
# ============================================================

class TestKeystoreUnencrypted:
    def test_read_nonexistent_file(self, tmp_dir):
        ks = Keystore(file_path=tmp_file(tmp_dir, "nonexistent"))
        data = ks.read()
        assert data == {}

    def test_write_and_read_protobuf(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks1")
        ks = Keystore(file_path=fp)
        ks.read()
        ks.set("privateKey", "abc")
        ks.set("apiKey", "xyz")
        ks.write()

        # File should be binary protobuf, not JSON
        raw = open(fp, "rb").read()
        with pytest.raises(json.JSONDecodeError):
            json.loads(raw.decode("utf-8"))

        # Read back with a fresh instance
        ks2 = Keystore(file_path=fp)
        data = ks2.read()
        assert data == {"privateKey": "abc", "apiKey": "xyz"}

    def test_set_without_read_preserves_existing(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-preserve")
        Keystore.to_file(fp, {"existingKey": "existingVal"})

        ks = Keystore(file_path=fp)
        ks.set("newKey", "newVal")  # auto-loads
        ks.write()

        result = Keystore.from_file(fp)
        assert result == {"existingKey": "existingVal", "newKey": "newVal"}

    def test_get_missing_key(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-get")
        Keystore.to_file(fp, {"a": "1"})
        ks = Keystore(file_path=fp)
        assert ks.get("a") == "1"
        assert ks.get("b") is None

    def test_keys(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-keys")
        Keystore.to_file(fp, {"x": "1", "y": "2", "z": "3"})
        ks = Keystore(file_path=fp)
        assert sorted(ks.keys()) == ["x", "y", "z"]

    def test_get_all_returns_copy(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-copy")
        Keystore.to_file(fp, {"k": "v"})
        ks = Keystore(file_path=fp)
        snapshot = ks.get_all()
        snapshot["k"] = "modified"
        assert ks.get("k") == "v"

    def test_atomic_write(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-atomic")
        Keystore.to_file(fp, {"a": "b"})
        assert not os.path.exists(fp + ".tmp")
        assert os.path.exists(fp)

    def test_creates_parent_directories(self, tmp_dir):
        fp = os.path.join(tmp_dir, "deep", "nested", "Keystore")
        Keystore.to_file(fp, {"k": "v"})
        assert os.path.exists(fp)
        assert Keystore.from_file(fp) == {"k": "v"}


# ============================================================
# Keystore class — encrypted
# ============================================================

class TestKeystoreEncrypted:
    def test_write_and_read_encrypted(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-enc")
        pw = "my-password"
        Keystore.to_file(fp, {"secret": "treasure"}, pw)

        raw = json.loads(open(fp, "r").read())
        assert is_encrypted_payload(raw)

        data = Keystore.from_file(fp, pw)
        assert data == {"secret": "treasure"}

    def test_read_encrypted_without_password(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-enc-nopw")
        Keystore.to_file(fp, {"a": "b"}, "pw")
        ks = Keystore(file_path=fp)
        with pytest.raises(ValueError, match="no password provided"):
            ks.read()

    def test_read_encrypted_wrong_password(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-enc-wrong")
        Keystore.to_file(fp, {"a": "b"}, "correct")
        ks = Keystore(file_path=fp, password="wrong")
        with pytest.raises(Exception):
            ks.read()

    def test_roundtrip_multiple_entries_encrypted(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-enc-multi")
        pw = "complex-pw-123!"
        original = {
            "privateKey": "deadbeefdeadbeef",
            "apiKey": "ak-123456",
            "secretKey": "sk-abcdef",
            "address": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
        }
        Keystore.to_file(fp, original, pw)
        result = Keystore.from_file(fp, pw)
        assert result == original

    def test_set_write_preserves_encryption(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-enc-set")
        pw = "pw"
        Keystore.to_file(fp, {"a": "1"}, pw)

        ks = Keystore(file_path=fp, password=pw)
        ks.read()
        ks.set("b", "2")
        ks.write()

        data = Keystore.from_file(fp, pw)
        assert data == {"a": "1", "b": "2"}

        raw = json.loads(open(fp, "r").read())
        assert is_encrypted_payload(raw)


# ============================================================
# Keystore — legacy JSON backward compatibility
# ============================================================

class TestKeystoreLegacyJson:
    def test_read_legacy_json(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-legacy")
        with open(fp, "w") as f:
            json.dump({"oldKey": "oldVal"}, f)
        ks = Keystore(file_path=fp)
        data = ks.read()
        assert data == {"oldKey": "oldVal"}

    def test_overwrite_legacy_json_with_protobuf(self, tmp_dir):
        fp = tmp_file(tmp_dir, "ks-legacy-overwrite")
        with open(fp, "w") as f:
            json.dump({"a": "1"}, f)

        ks = Keystore(file_path=fp)
        ks.read()
        ks.set("b", "2")
        ks.write()

        # File should now be protobuf
        raw = open(fp, "rb").read()
        with pytest.raises(json.JSONDecodeError):
            json.loads(raw.decode("utf-8"))

        result = Keystore.from_file(fp)
        assert result == {"a": "1", "b": "2"}
