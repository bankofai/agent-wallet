"""Minimal protobuf encoder/decoder for:

message KeystoreData {
  map<string, string> entries = 1;
}

Wire-level equivalent to:

message KeystoreData {
  message EntriesEntry {
    string key = 1;
    string value = 2;
  }
  repeated EntriesEntry entries = 1;
}
"""
from __future__ import annotations

from typing import Dict

WIRE_TYPE_VARINT = 0
WIRE_TYPE_64BIT = 1
WIRE_TYPE_LENGTH_DELIMITED = 2
WIRE_TYPE_32BIT = 5


def _encode_varint(value: int) -> bytes:
    v = value & 0xFFFFFFFF
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _decode_varint(buf: bytes, offset: int) -> tuple:
    """Decode a varint from buf at offset. Returns (value, next_offset)."""
    result = 0
    shift = 0
    pos = offset
    bytes_read = 0
    while pos < len(buf):
        if bytes_read >= 5:
            raise ValueError("Varint too long (> 5 bytes for uint32)")
        b = buf[pos]
        pos += 1
        bytes_read += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result & 0xFFFFFFFF, pos
        shift += 7
    raise ValueError("Unexpected end of buffer while decoding varint")


def _skip_field(buf: bytes, offset: int, wire_type: int, limit: int) -> int:
    """Skip a field based on wire type. Returns new offset."""
    if wire_type == WIRE_TYPE_VARINT:
        _, offset = _decode_varint(buf, offset)
        return offset
    elif wire_type == WIRE_TYPE_64BIT:
        if offset + 8 > limit:
            raise ValueError("Unexpected end of buffer skipping 64-bit field")
        return offset + 8
    elif wire_type == WIRE_TYPE_LENGTH_DELIMITED:
        skip_len, offset = _decode_varint(buf, offset)
        if offset + skip_len > limit:
            raise ValueError("Length-delimited field exceeds buffer")
        return offset + skip_len
    elif wire_type == WIRE_TYPE_32BIT:
        if offset + 4 > limit:
            raise ValueError("Unexpected end of buffer skipping 32-bit field")
        return offset + 4
    else:
        raise ValueError(f"Unknown wire type {wire_type}")


def _encode_string_field(field_number: int, value: str) -> bytes:
    tag = _encode_varint((field_number << 3) | WIRE_TYPE_LENGTH_DELIMITED)
    data = value.encode("utf-8")
    return tag + _encode_varint(len(data)) + data


def encode_keystore_data(data: Dict[str, str]) -> bytes:
    """Encode dict[str, str] as KeystoreData protobuf bytes."""
    chunks: list[bytes] = []
    for key, value in data.items():
        entry = _encode_string_field(1, key) + _encode_string_field(2, value)
        tag = _encode_varint((1 << 3) | WIRE_TYPE_LENGTH_DELIMITED)
        chunks.append(tag + _encode_varint(len(entry)) + entry)
    return b"".join(chunks)


def decode_keystore_data(buf: bytes) -> Dict[str, str]:
    """Decode KeystoreData protobuf bytes into dict[str, str]."""
    result: Dict[str, str] = {}
    offset = 0
    length = len(buf)

    while offset < length:
        # Decode tag as varint
        tag_val, offset = _decode_varint(buf, offset)
        field_number = tag_val >> 3
        wire_type = tag_val & 0x07

        if field_number != 1 or wire_type != WIRE_TYPE_LENGTH_DELIMITED:
            offset = _skip_field(buf, offset, wire_type, length)
            continue

        # Read sub-message length
        msg_len, offset = _decode_varint(buf, offset)
        if offset + msg_len > length:
            raise ValueError(
                f"Sub-message length {msg_len} exceeds buffer (offset={offset}, bufLen={length})"
            )
        end = offset + msg_len

        key: str | None = None
        value: str | None = None
        while offset < end:
            inner_tag, offset = _decode_varint(buf, offset)
            inner_field = inner_tag >> 3
            inner_wire = inner_tag & 0x07

            if inner_wire != WIRE_TYPE_LENGTH_DELIMITED:
                offset = _skip_field(buf, offset, inner_wire, end)
                continue

            str_len, offset = _decode_varint(buf, offset)
            if offset + str_len > end:
                raise ValueError(f"String length {str_len} exceeds sub-message boundary")
            s = buf[offset : offset + str_len].decode("utf-8")
            offset += str_len
            if inner_field == 1:
                key = s
            elif inner_field == 2:
                value = s

        if key is not None and value is not None:
            result[key] = value

    return result
