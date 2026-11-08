"""Artifact measurement, manifest authentication, and receipt storage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .model import ANCHOR, FILES, FORMAT, MANIFEST, ReceiptError


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def measure(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if not data:
        raise ReceiptError(f"empty AOT artifact: {path}")
    return {"bytes": len(data), "sha256": sha256_bytes(data)}


def load_bundle(path: Path) -> dict[str, Any]:
    path = path.resolve()
    measurements = {name: measure(path / name) for name in FILES}
    manifest_bytes = (path / MANIFEST).read_bytes()
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"invalid AOT manifest: {path / MANIFEST}: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
        raise ReceiptError("AOT manifest format mismatch")
    if manifest.get("toolchain") is None:
        raise ReceiptError("built AOT manifest is missing toolchain identity")

    source = manifest.get("source")
    artifacts = manifest.get("artifacts")
    if not isinstance(source, dict) or not isinstance(artifacts, dict):
        raise ReceiptError("AOT manifest is missing source or artifact identity")
    declared = {
        "stwo_zig_core.metal": source,
        "stwo_zig_core.air": artifacts.get("air"),
        "stwo_zig_core.metallib": artifacts.get("metallib"),
    }
    for filename, identity in declared.items():
        if not isinstance(identity, dict) or identity.get("path") != filename:
            raise ReceiptError(f"AOT manifest path mismatch for {filename}")
        actual = measurements[filename]
        if identity.get("sha256") != actual["sha256"] or identity.get("bytes") != actual["bytes"]:
            raise ReceiptError(f"AOT manifest measurement mismatch for {filename}")

    expected_anchor = f"{measurements[MANIFEST]['sha256']}  {MANIFEST}\n".encode()
    if (path / ANCHOR).read_bytes() != expected_anchor:
        raise ReceiptError("AOT manifest trust anchor mismatch")
    return {"path": str(path), "files": measurements, "manifest": manifest}


def bundle_identity(bundle: dict[str, Any]) -> dict[str, Any]:
    return {"files": bundle["files"], "manifest": bundle["manifest"]}


def recorded_bundle_identity(bundle: dict[str, Any], name: str) -> dict[str, Any]:
    return {"relative_path": name, **bundle_identity(bundle)}


def require_reproducible(first: dict[str, Any], second: dict[str, Any]) -> None:
    for filename in FILES:
        if first["files"][filename] != second["files"][filename]:
            raise ReceiptError(f"independent AOT builds differ: {filename}")


def executable_identity(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    result = measure(resolved)
    result["path"] = str(resolved)
    return result


def checksum_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".sha256")


def write_receipt(path: Path, receipt: dict[str, Any]) -> str:
    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(encoded)
    temporary.replace(path)
    digest = sha256_bytes(encoded)
    checksum_path(path).write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    return digest


def read_receipt(path: Path, expected_schema: str) -> tuple[dict[str, Any], str]:
    path = path.resolve(strict=True)
    encoded = path.read_bytes()
    digest = sha256_bytes(encoded)
    expected_anchor = f"{digest}  {path.name}\n".encode()
    try:
        actual_anchor = checksum_path(path).read_bytes()
    except FileNotFoundError as error:
        raise ReceiptError(f"receipt checksum is missing: {checksum_path(path)}") from error
    if actual_anchor != expected_anchor:
        raise ReceiptError("receipt checksum mismatch")
    try:
        receipt = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReceiptError(f"invalid receipt JSON: {path}: {error}") from error
    if not isinstance(receipt, dict) or receipt.get("schema") != expected_schema:
        raise ReceiptError(f"receipt schema mismatch: expected {expected_schema}")
    return receipt, digest
