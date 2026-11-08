"""Content-address and verify every raw Native profiler artifact."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

try:
    from scripts.benchmark_product_contract_lib import (
        ProductEvidenceError,
        validate_receipt,
    )
except ModuleNotFoundError:
    from benchmark_product_contract_lib import ProductEvidenceError, validate_receipt

if __package__.startswith("scripts."):
    from scripts.native_proof_matrix_lib.artifacts import atomic_write_bytes, atomic_write_json
else:
    from native_proof_matrix_lib.artifacts import atomic_write_bytes, atomic_write_json

from .model import (
    MAX_ARTIFACT_BYTES,
    MAX_CAPTURE_BYTES,
    MAX_CAPTURE_FILES,
    CaptureError,
)


MANIFEST_NAME = "manifest.json"
CHECKSUM_NAME = "manifest.sha256"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def artifact_inventory(root: Path) -> dict[str, dict[str, int | str]]:
    records: dict[str, dict[str, int | str]] = {}
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if path.name in {MANIFEST_NAME, CHECKSUM_NAME}:
            continue
        if path.is_symlink() or not path.is_file():
            if path.is_dir():
                continue
            raise CaptureError(f"profile evidence contains a non-regular artifact: {path}")
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            raise CaptureError(f"profile artifact exceeds byte limit: {relative}")
        total_bytes += size
        records[relative] = {"bytes": size, "sha256": sha256_file(path)}
    if not records:
        raise CaptureError("profile capture contains no artifacts")
    if len(records) > MAX_CAPTURE_FILES:
        raise CaptureError(f"profile capture exceeds {MAX_CAPTURE_FILES} files")
    if total_bytes > MAX_CAPTURE_BYTES:
        raise CaptureError(f"profile capture exceeds {MAX_CAPTURE_BYTES} bytes")
    return records


def publish_manifest(root: Path, document: dict[str, Any]) -> dict[str, Any]:
    if "artifacts" in document:
        raise CaptureError("manifest payload already contains an artifact inventory")
    manifest = {**document, "artifacts": artifact_inventory(root)}
    encoded = atomic_write_json(root / MANIFEST_NAME, manifest)
    digest = hashlib.sha256(encoded).hexdigest()
    atomic_write_bytes(root / CHECKSUM_NAME, f"{digest}  {MANIFEST_NAME}\n".encode())
    verify_manifest(root)
    return {"manifest": str(root / MANIFEST_NAME), "manifest_sha256": digest}


def verify_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / MANIFEST_NAME
    checksum_path = root / CHECKSUM_NAME
    if not manifest_path.is_file() or not checksum_path.is_file():
        raise CaptureError("profile capture is missing its manifest or checksum")
    raw = manifest_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if checksum_path.read_text(encoding="ascii") != f"{digest}  {MANIFEST_NAME}\n":
        raise CaptureError("profile manifest checksum does not match")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CaptureError("profile manifest is not valid JSON") from error
    if not isinstance(document, dict) or not isinstance(document.get("artifacts"), dict):
        raise CaptureError("profile manifest has an invalid artifact inventory")
    if document["artifacts"] != artifact_inventory(root):
        raise CaptureError("profile artifact tree differs from its manifest")
    if document.get("protocol") == "native_profiler_baseline_v2":
        _validate_product_receipts(document)
    return document


def _validate_product_receipts(document: dict[str, Any]) -> None:
    receipts = document.get("product_receipts")
    binaries = document.get("binaries")
    rows = document.get("rows")
    host_environment = document.get("host_environment")
    if (
        not isinstance(receipts, dict)
        or set(receipts) != {"cpu", "metal"}
        or not isinstance(binaries, dict)
        or set(binaries) != {"cpu", "metal"}
        or not isinstance(rows, list)
        or not rows
        or not isinstance(host_environment, dict)
        or not host_environment
    ):
        raise CaptureError("profile manifest has invalid focused-product evidence")
    for lane in ("cpu", "metal"):
        try:
            identities = [row["lanes"][lane]["product_identity"] for row in rows]
        except (KeyError, TypeError) as error:
            raise CaptureError(f"profile rows lack {lane} product identity") from error
        if any(identity != identities[0] for identity in identities[1:]):
            raise CaptureError(f"profile {lane} product identity changed between rows")
        binary = binaries[lane]
        if not isinstance(binary, dict):
            raise CaptureError(f"profile {lane} binary evidence is invalid")
        try:
            receipt = validate_receipt(
                receipts[lane],
                lane=lane,
                evidence_kind="profile",
                expected_identity=identities[0],
                expected_executable_sha256=binary.get("sha256"),
                expected_host_device=host_environment,
            )
        except ProductEvidenceError as error:
            raise CaptureError(f"profile {lane} receipt is invalid: {error}") from error
        if len(receipt["measurements"]) != len(rows):
            raise CaptureError(f"profile {lane} receipt row count differs")
        for index, (row, measurement) in enumerate(
            zip(rows, receipt["measurements"], strict=True)
        ):
            workload = row.get("workload")
            if not isinstance(workload, dict):
                raise CaptureError(f"profile row {index} workload is invalid")
            if measurement["workload"] != {
                **workload,
                "descriptor_sha256": row.get("descriptor_sha256"),
            }:
                raise CaptureError(f"profile {lane} receipt workload differs at row {index}")
            proof = row["lanes"][lane].get("proof")
            if (
                not isinstance(proof, dict)
                or measurement["proof_status"]["proof_sha256"]
                != proof.get("proof_sha256")
            ):
                raise CaptureError(f"profile {lane} receipt proof differs at row {index}")


def write_bytes_exclusive(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as destination:
            destination.write(contents)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)
