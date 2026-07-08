#!/usr/bin/env python3
"""Generate AndroidQF protobuf test fixtures for libmvt."""

from __future__ import annotations

import json
from pathlib import Path


def write_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def write_string_field(field_number: int, value: str) -> bytes:
    encoded = value.encode("utf-8")
    tag = (field_number << 3) | 2
    return write_varint(tag) + write_varint(len(encoded)) + encoded


def write_double_field(field_number: int, value: float) -> bytes:
    import struct

    tag = (field_number << 3) | 1
    return write_varint(tag) + struct.pack("<d", value)


def write_int64_field(field_number: int, value: int) -> bytes:
    tag = (field_number << 3) | 0
    return write_varint(tag) + write_varint(value)


def write_delimited(record: bytes) -> bytes:
    return write_varint(len(record)) + record


def write_bool_field(field_number: int, value: bool) -> bytes:
    tag = (field_number << 3) | 0
    return write_varint(tag) + write_varint(1 if value else 0)


def write_int32_field(field_number: int, value: int) -> bytes:
    tag = (field_number << 3) | 0
    return write_varint(tag) + write_varint(value)


def write_bytes_field(field_number: int, value: bytes) -> bytes:
    tag = (field_number << 3) | 2
    return write_varint(tag) + write_varint(len(value)) + value


def encode_certificate_record(certificate: dict) -> bytes:
    record = bytearray()
    mapping = [
        (1, certificate.get("Md5") or certificate.get("md5")),
        (2, certificate.get("Sha1") or certificate.get("sha1")),
        (3, certificate.get("Sha256") or certificate.get("sha256")),
        (4, certificate.get("ValidFrom") or certificate.get("valid_from")),
        (5, certificate.get("ValidTo") or certificate.get("valid_to")),
        (6, certificate.get("Issuer") or certificate.get("issuer")),
        (7, certificate.get("Subject") or certificate.get("subject")),
        (8, certificate.get("SignatureAlgorithm") or certificate.get("signature_algorithm")),
        (9, str(certificate.get("SerialNumber") or certificate.get("serial_number") or "")),
    ]
    for field_number, value in mapping:
        if value:
            record.extend(write_string_field(field_number, value))
    return bytes(record)


def encode_package_file_record(file_entry: dict) -> bytes:
    record = bytearray()
    record.extend(write_string_field(1, file_entry.get("path", "")))
    local_name = file_entry.get("local_name", "")
    if local_name:
        record.extend(write_string_field(2, local_name))
    for field_number, key in ((3, "md5"), (4, "sha1"), (5, "sha256"), (6, "sha512")):
        value = file_entry.get(key, "")
        if value:
            record.extend(write_string_field(field_number, value))
    if file_entry.get("suspicious"):
        record.extend(write_bool_field(7, True))
    certificate = file_entry.get("certificate")
    if certificate:
        record.extend(write_bytes_field(8, encode_certificate_record(certificate)))
    return bytes(record)


def encode_package_record(package: dict) -> bytes:
    record = bytearray()
    record.extend(write_string_field(1, package["name"]))
    installer = package.get("installer", "")
    if installer:
        record.extend(write_string_field(2, installer))
    record.extend(write_int32_field(3, int(package.get("uid", 0))))
    record.extend(write_bool_field(4, bool(package.get("disabled", False))))
    record.extend(write_bool_field(5, bool(package.get("system", False))))
    record.extend(write_bool_field(6, bool(package.get("third_party", False))))
    for file_entry in package.get("files", []):
        record.extend(write_bytes_field(7, encode_package_file_record(file_entry)))
    return write_delimited(bytes(record))


def encode_string_record(value: str) -> bytes:
    return write_delimited(write_string_field(1, value))


def encode_file_record(
    path: str,
    mtime: float | None = None,
    mode: str | None = None,
    size: int | None = None,
    user: str | None = None,
    group: str | None = None,
) -> bytes:
    record = bytearray()
    record.extend(write_string_field(1, path))
    if mtime is not None:
        record.extend(write_double_field(2, mtime))
    if mode:
        record.extend(write_string_field(3, mode))
    if size is not None:
        record.extend(write_int64_field(4, size))
    if user:
        record.extend(write_string_field(5, user))
    if group:
        record.extend(write_string_field(6, group))
    return write_delimited(bytes(record))


def main() -> None:
    root = Path(__file__).resolve().parent
    android_data = root / "android_data"

    root_binaries = json.loads((android_data / "root_binaries.json").read_text())
    (android_data / "root_binaries.pb").write_bytes(
        b"".join(encode_string_record(path) for path in root_binaries)
    )

    mounts = json.loads((android_data / "mounts.json").read_text())
    (android_data / "mounts.pb").write_bytes(
        b"".join(encode_string_record(entry) for entry in mounts)
    )

    files = json.loads((root / "androidqf" / "files.json").read_text())
    file_records = []
    for entry in files:
        file_records.append(
            encode_file_record(
                path=entry["path"],
                mtime=float(entry["modified_time"]) if entry.get("modified_time") is not None else None,
                mode=entry.get("mode") or None,
                size=int(entry["size"]) if entry.get("size") is not None else None,
                user=entry.get("user_name") or None,
                group=entry.get("group_name") or None,
            )
        )
    (android_data / "files.pb").write_bytes(b"".join(file_records))

    packages = json.loads((root / "androidqf" / "packages.json").read_text())
    (android_data / "packages.pb").write_bytes(
        b"".join(encode_package_record(package) for package in packages)
    )

    print("Wrote root_binaries.pb, mounts.pb, files.pb, packages.pb")


if __name__ == "__main__":
    main()
