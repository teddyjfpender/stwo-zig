"""Content-addressed artifacts and executable provenance for interop evidence."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable


ARCHIVE_PROTOCOL = "native_e2e_interop_receipt_v2"
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
MAX_ARCHIVED_RUN_BYTES = 256 * 1024 * 1024


class EvidenceError(RuntimeError):
    """Evidence could not be bound to immutable bytes or exact tooling."""


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _command_output(command: list[str], *, cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise EvidenceError(f"provenance command failed ({result.returncode}): {command}")
    return result.stdout.strip() or result.stderr.strip()


def _file_identity(path: Path, *, root: Path) -> dict[str, Any]:
    resolved = path.resolve()
    try:
        rendered = resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        rendered = str(resolved)
    return {
        "path": rendered,
        "bytes": resolved.stat().st_size,
        "sha256": file_sha256(resolved),
    }


def collect_provenance(
    *,
    root: Path,
    rust_toolchain: str,
    upstream_commit: str,
    zig_optimize: str,
    zig_binary: Path,
    native_cpu_binary: Path,
    rust_binary: Path,
    gate_sources: Iterable[Path],
) -> dict[str, Any]:
    zig_executable_raw = shutil.which("zig")
    cargo_executable_raw = shutil.which("cargo")
    rustup_executable_raw = shutil.which("rustup")
    if zig_executable_raw is None or cargo_executable_raw is None or rustup_executable_raw is None:
        raise EvidenceError("zig, cargo, and rustup must resolve for executable provenance")
    zig_executable = Path(zig_executable_raw)
    cargo_executable = Path(cargo_executable_raw)
    rustup_executable = Path(rustup_executable_raw)
    rustc_toolchain = Path(
        _command_output(
            [str(rustup_executable), "which", "--toolchain", rust_toolchain, "rustc"],
            cwd=root,
        )
    )
    cargo_toolchain = Path(
        _command_output(
            [str(rustup_executable), "which", "--toolchain", rust_toolchain, "cargo"],
            cwd=root,
        )
    )
    status = _command_output(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root
    )
    source_identities = [_file_identity(path, root=root) for path in sorted(gate_sources)]
    return {
        "repository": {
            "commit": _command_output(["git", "rev-parse", "HEAD"], cwd=root),
            "clean": status == "",
            "worktree_status_sha256": sha256_bytes(status.encode("utf-8")),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "zig": {
            "version": _command_output([str(zig_executable), "version"], cwd=root),
            "optimize": zig_optimize,
            "compiler": _file_identity(zig_executable, root=root),
            "interop_binary": _file_identity(zig_binary, root=root),
            "native_cpu_binary": _file_identity(native_cpu_binary, root=root),
        },
        "rust_oracle": {
            "toolchain": rust_toolchain,
            "upstream_commit": upstream_commit,
            "rustc_version": _command_output(
                ["rustc", f"+{rust_toolchain}", "--version", "--verbose"], cwd=root
            ),
            "cargo_version": _command_output(
                [str(cargo_executable), f"+{rust_toolchain}", "--version"], cwd=root
            ),
            "rustup_proxy": _file_identity(cargo_executable, root=root),
            "rustc": _file_identity(rustc_toolchain, root=root),
            "cargo": _file_identity(cargo_toolchain, root=root),
            "interop_binary": _file_identity(rust_binary, root=root),
            "manifest": _file_identity(root / "tools/stwo-interop-rs/Cargo.toml", root=root),
            "lockfile": _file_identity(root / "tools/stwo-interop-rs/Cargo.lock", root=root),
        },
        "gate_sources": source_identities,
    }


def register_artifact(
    path: Path,
    *,
    example: str,
    direction: str,
    role: str,
    mutation_id: str | None = None,
) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise EvidenceError(
            f"interop artifact exceeds {MAX_ARTIFACT_BYTES} byte evidence bound: {path}"
        )
    try:
        artifact = json.loads(raw)
        proof_hex = artifact["proof_bytes_hex"]
        proof_bytes = bytes.fromhex(proof_hex)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot bind proof bytes in artifact {path}") from error
    return {
        "_source_path": str(path.resolve()),
        "example": example,
        "direction": direction,
        "role": role,
        "mutation_id": mutation_id,
        "artifact_bytes": len(raw),
        "artifact_sha256": sha256_bytes(raw),
        "proof_bytes": len(proof_bytes),
        "proof_sha256": sha256_bytes(proof_bytes),
    }


def _archive_blob(archive_dir: Path, relative: Path, raw: bytes) -> str:
    destination = archive_dir / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not destination.is_file() or destination.read_bytes() != raw:
            raise EvidenceError(f"content-addressed archive collision: {destination}")
    else:
        try:
            with destination.open("xb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            if destination.read_bytes() != raw:
                raise EvidenceError(f"content-addressed archive collision: {destination}")
    return relative.as_posix()


def _normalize_string(value: str, replacements: dict[str, str]) -> str:
    normalized = value
    aliases: list[tuple[str, str]] = []
    for source, target in replacements.items():
        candidates = {source, os.path.abspath(source), os.path.realpath(source)}
        candidates.update(
            candidate[len("/private") :]
            for candidate in tuple(candidates)
            if candidate.startswith("/private/")
        )
        aliases.extend((candidate, target) for candidate in candidates)
    for source, target in sorted(aliases, key=lambda item: len(item[0]), reverse=True):
        normalized = normalized.replace(source, target)
    return normalized


def _normalize_value(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _normalize_string(value, replacements)
    if isinstance(value, list):
        return [_normalize_value(item, replacements) for item in value]
    if isinstance(value, dict):
        return {key: _normalize_value(item, replacements) for key, item in value.items()}
    return value


def _receipt_steps(
    steps: list[dict[str, Any]], replacements: dict[str, str]
) -> list[dict[str, Any]]:
    fields = (
        "name",
        "command",
        "cwd",
        "expect_failure",
        "required_rejection_class",
        "return_code",
        "status",
        "rejection_class",
        "mutation_id",
        "mutation_category",
        "artifact_sha256",
    )
    receipt_steps: list[dict[str, Any]] = []
    for step in steps:
        selected = {field: step[field] for field in fields if field in step}
        command = selected.get("command")
        if isinstance(command, list):
            selected["command"] = [
                _normalize_string(str(argument), replacements) for argument in command
            ]
        receipt_steps.append(selected)
    return receipt_steps


def archive_receipt(
    *,
    archive_dir: Path,
    report: dict[str, Any],
    artifact_records: list[dict[str, Any]],
    provenance: dict[str, Any],
    path_replacements: dict[str, str],
) -> dict[str, Any]:
    repository = provenance.get("repository")
    if report.get("status") == "ok" and (
        not isinstance(repository, dict) or repository.get("clean") is not True
    ):
        raise EvidenceError("accepted interop receipts require a clean repository")

    total_bytes = sum(int(record["artifact_bytes"]) for record in artifact_records)
    if total_bytes > MAX_ARCHIVED_RUN_BYTES:
        raise EvidenceError(
            f"interop evidence exceeds {MAX_ARCHIVED_RUN_BYTES} byte per-run archive bound"
        )

    archived_records: list[dict[str, Any]] = []
    for record in artifact_records:
        source = Path(str(record["_source_path"]))
        raw = source.read_bytes()
        digest = sha256_bytes(raw)
        if digest != record["artifact_sha256"]:
            raise EvidenceError(f"artifact changed after verification: {source}")
        relative = Path("objects") / "sha256" / digest[:2] / f"{digest}.json"
        object_path = _archive_blob(archive_dir, relative, raw)
        archived = {key: value for key, value in record.items() if not key.startswith("_")}
        archived["object_path"] = object_path
        archived_records.append(archived)

    receipt = {
        "receipt_protocol": ARCHIVE_PROTOCOL,
        "status": report["status"],
        "schema_version": report["schema_version"],
        "exchange_mode": report["exchange_mode"],
        "upstream_commit": report["upstream_commit"],
        "summary": report["summary"],
        "mutation_coverage": report["mutation_coverage"],
        "cases": _normalize_value(report["cases"], path_replacements),
        "failure": _normalize_value(report["failure"], path_replacements),
        "provenance": provenance,
        "commands": _receipt_steps(report["steps"], path_replacements),
        "artifacts": archived_records,
    }
    encoded = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    digest = sha256_bytes(encoded)
    relative = Path("receipts") / ARCHIVE_PROTOCOL / f"{digest}.json"
    receipt_path = _archive_blob(archive_dir, relative, encoded)
    return {
        "protocol": ARCHIVE_PROTOCOL,
        "directory": str(archive_dir.resolve()),
        "receipt_path": receipt_path,
        "receipt_sha256": digest,
        "artifacts": len(archived_records),
        "artifact_bytes": total_bytes,
    }
