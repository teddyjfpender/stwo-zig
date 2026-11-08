"""Benchmark report and delta archive — layout v2.

Runs are stored under human-readable directories; sha256 digests live in
index.json as the integrity authority instead of being filenames:

    runs/<run-id>/report.json
    runs/<run-id>/delta-from-<baseline-run-id>.json

A v1 (content-hash filename) archive is refused with a pointer to the
one-shot migration script so the two layouts never interleave.
"""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .common import (
    DeltaError,
    atomic_write,
    digest_json,
    encoded_json,
    require_list,
    require_object,
)

from .naming import NamingError, run_id, run_id_for_report


ARCHIVE_SCHEMA_VERSION = 2
MIGRATION_HINT = (
    "archive uses the v1 content-hash layout; run "
    "`python3 scripts/migrate_benchmark_history_v2.py --archive-dir <dir>` once"
)


@contextmanager
def archive_lock(archive_dir: Path) -> Iterator[None]:
    archive_dir.mkdir(parents=True, exist_ok=True)
    lock_path = archive_dir / ".benchmark-delta.lock"
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise DeltaError(f"benchmark archive is locked: {archive_dir}") from error
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode())
        os.fsync(descriptor)
        yield
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


def load_index(archive_dir: Path) -> dict[str, Any]:
    index_path = archive_dir / "index.json"
    if not index_path.exists():
        return {
            "schema_version": ARCHIVE_SCHEMA_VERSION,
            "runs": {},
            "artifacts": {},
            "deltas": {},
            "comparisons": [],
        }
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeltaError("benchmark archive index is invalid") from error
    if not isinstance(index, dict):
        raise DeltaError("benchmark archive index must be an object")
    if index.get("schema_version") == 1:
        raise DeltaError(MIGRATION_HINT)
    if index.get("schema_version") != ARCHIVE_SCHEMA_VERSION:
        raise DeltaError("benchmark archive index schema is incompatible")
    index.setdefault("runs", {})
    return index


def _write_blob(destination: Path, raw: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not destination.is_file() or destination.read_bytes() != raw:
            raise DeltaError(f"archive collision: {destination}")
        return
    try:
        with destination.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        if destination.read_bytes() != raw:
            raise DeltaError(f"archive collision: {destination}")


def _report_run_id(raw: bytes, sha256: str, fallback_generated_at: str | None) -> str:
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeltaError(f"archived report {sha256[:12]} is not valid JSON") from error
    try:
        return run_id_for_report(report)
    except NamingError:
        # Upstream comparison reports carry no generated_at/provenance of their
        # own; identify their run by the archival moment instead.
        if fallback_generated_at is None or not isinstance(report.get("protocol"), str):
            raise DeltaError(f"report {sha256[:12]} has no identity fields for a run id")
        return run_id(fallback_generated_at, report["protocol"], None)


def archive_report(
    archive_dir: Path,
    index: dict[str, Any],
    raw: bytes,
    sha256: str,
    protocol: str,
    fallback_generated_at: str | None = None,
) -> str:
    """Store one report under its run directory; returns the run id.

    Identical bytes are reused; a run-id collision with different bytes gets
    a deterministic disambiguating suffix derived from the report digest.
    """
    artifacts = require_object(index.setdefault("artifacts", {}), "archive.artifacts")
    existing = artifacts.get(sha256)
    if existing is not None:
        run = existing.get("run")
        recorded = archive_dir / existing["path"]
        if not recorded.is_file() or recorded.read_bytes() != raw:
            raise DeltaError(f"archive artifact index conflicts with content: {sha256[:12]}")
        return run

    runs = require_object(index["runs"], "archive.runs")
    base_id = _report_run_id(raw, sha256, fallback_generated_at)
    candidate = base_id
    if candidate in runs:
        candidate = f"{base_id}-{sha256[:6]}"
        if candidate in runs:
            raise DeltaError(f"run id collision cannot be resolved: {base_id}")
    relative = Path("runs") / candidate / "report.json"
    _write_blob(archive_dir / relative, raw)
    artifacts[sha256] = {
        "path": relative.as_posix(),
        "bytes": len(raw),
        "run": candidate,
    }
    runs[candidate] = {
        "kind": protocol,
        "report": {"path": relative.as_posix(), "bytes": len(raw), "sha256": sha256},
        "deltas": [],
        "bundle": None,
    }
    return candidate


def update_archive(
    archive_dir: Path,
    document: dict[str, Any],
    baseline_raw: bytes,
    current_raw: bytes,
) -> dict[str, Any]:
    with archive_lock(archive_dir):
        index = load_index(archive_dir)
        sources = document["sources"]
        baseline_run = archive_report(
            archive_dir,
            index,
            baseline_raw,
            sources["baseline"]["sha256"],
            sources["baseline"]["report_protocol"],
            fallback_generated_at=document["generated_at"],
        )
        current_run = archive_report(
            archive_dir,
            index,
            current_raw,
            sources["current"]["sha256"],
            sources["current"]["report_protocol"],
            fallback_generated_at=document["generated_at"],
        )

        core_delta = encoded_json(document)
        delta_sha256 = hashlib.sha256(core_delta).hexdigest()
        deltas = require_object(index.setdefault("deltas", {}), "archive.deltas")
        existing_delta = deltas.get(delta_sha256)
        if existing_delta is not None:
            delta_relative = existing_delta["path"]
            recorded = archive_dir / delta_relative
            if not recorded.is_file() or recorded.read_bytes() != core_delta:
                raise DeltaError("archive delta index conflicts with immutable content")
        else:
            delta_name = f"delta-from-{baseline_run}.json"
            delta_path = Path("runs") / current_run / delta_name
            if (archive_dir / delta_path).exists():
                delta_path = delta_path.with_name(
                    f"delta-from-{baseline_run}-{delta_sha256[:6]}.json"
                )
            _write_blob(archive_dir / delta_path, core_delta)
            delta_relative = delta_path.as_posix()
            deltas[delta_sha256] = {
                "path": delta_relative,
                "bytes": len(core_delta),
                "run": current_run,
                "baseline_run": baseline_run,
            }
            run_entry = index["runs"][current_run]
            if delta_relative not in run_entry["deltas"]:
                run_entry["deltas"].append(delta_relative)

        comparison = {
            "archived_at": document["generated_at"],
            "report_kind": document["report_kind"],
            "status": document["status"],
            "comparison_identity_sha256": (
                document["comparison_identity"]["sha256"]
                if document["comparison_identity"] is not None
                else None
            ),
            "baseline_sha256": sources["baseline"]["sha256"],
            "current_sha256": sources["current"]["sha256"],
            "baseline_run": baseline_run,
            "current_run": current_run,
            "delta_sha256": delta_sha256,
            "delta_path": delta_relative,
        }
        comparison["id"] = digest_json(comparison)
        comparisons = require_list(index.get("comparisons"), "archive.comparisons")
        existing_ids = {
            entry.get("id")
            for entry in comparisons
            if isinstance(entry, dict) and isinstance(entry.get("id"), str)
        }
        if comparison["id"] not in existing_ids:
            comparisons.append(comparison)
        comparisons.sort(key=lambda entry: (entry["archived_at"], entry["id"]))
        atomic_write(archive_dir / "index.json", encoded_json(index))
    return {
        "directory": str(archive_dir.resolve()),
        "index": str((archive_dir / "index.json").resolve()),
        "baseline_run": baseline_run,
        "current_run": current_run,
        "baseline_artifact": index["artifacts"][sources["baseline"]["sha256"]]["path"],
        "current_artifact": index["artifacts"][sources["current"]["sha256"]]["path"],
        "delta_artifact": delta_relative,
        "delta_sha256": delta_sha256,
        "delta_representation": "core_delta_without_archive_block",
    }
