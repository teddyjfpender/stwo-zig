"""Normalize immutable Native benchmark runs into a bounded site catalog."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any


CATALOG_SCHEMA = "stwo_benchmark_catalog_v1"
INDEX_SCHEMA_VERSION = 2
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PUBLICATION_STATUSES = {"active", "invalidated", "superseded"}
LANES = ("cpu", "metal")
METRICS = (
    "native_mhz",
    "request_native_mhz",
    "prove_seconds",
    "request_seconds",
    "verify_seconds",
    "peak_rss_kib",
    "committed_mcells_per_second",
)
PROCESS_RESOURCE_KEYS = {
    "measurement",
    "measurement_locale",
    "normalized_unit",
    "peak_rss_kib",
}
REQUEST_RESOURCE_KEYS = {
    "measurement_scope",
    "source",
    "measured_warmups",
    "measured_samples",
    "lifetime_peak_physical_footprint_bytes",
    "energy_nj",
    "instructions",
    "cycles",
    "canonical_proof_bytes",
    "complete",
    "unavailable_reason",
}


class CatalogError(RuntimeError):
    """Committed benchmark evidence cannot be published safely."""


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogError(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CatalogError(f"{label} must be an array")
    return value


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CatalogError(f"{label} is not valid JSON: {error}") from error
    return _object(value, label), raw


def _safe_path(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise CatalogError(f"{label} must be a nonempty relative path")
    posix = PurePosixPath(value)
    if posix.is_absolute() or "." in posix.parts or ".." in posix.parts:
        raise CatalogError(f"{label} is not a safe relative path")
    candidate = root.joinpath(*posix.parts)
    if not candidate.is_file():
        raise CatalogError(f"{label} does not exist: {value}")
    return candidate


def _utc_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise CatalogError(f"{label} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CatalogError(f"{label} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CatalogError(f"{label} must carry an explicit UTC offset")
    return parsed.isoformat()


def _number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CatalogError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise CatalogError(f"{label} must be finite and nonnegative")
    return result


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{label} must be nonempty text")
    return value.strip()


def _validate_blob(
    history_dir: Path,
    identity: dict[str, Any],
    digest: str,
    label: str,
) -> Path:
    if not SHA256_RE.fullmatch(digest):
        raise CatalogError(f"{label} has an invalid digest")
    path = _safe_path(history_dir, identity.get("path"), f"{label}.path")
    raw = path.read_bytes()
    if _sha256(raw) != digest:
        raise CatalogError(f"{label} digest mismatch")
    if len(raw) != identity.get("bytes"):
        raise CatalogError(f"{label} byte count mismatch")
    return path


def _validate_archive_integrity(
    history_dir: Path,
    index: dict[str, Any],
) -> None:
    runs = _object(index.get("runs"), "benchmark history runs")
    artifacts = _object(index.get("artifacts"), "benchmark history artifacts")
    deltas = _object(index.get("deltas"), "benchmark history deltas")
    bundles = _object(index.get("bundles"), "benchmark history bundles")
    comparisons = _array(
        index.get("comparisons"), "benchmark history comparisons"
    )

    for digest, value in artifacts.items():
        identity = _object(value, f"artifact {digest}")
        _validate_blob(history_dir, identity, digest, f"artifact {digest}")
        run_id = identity.get("run")
        run = _object(runs.get(run_id), f"artifact {digest}.run")
        if run.get("report") != {
            "path": identity.get("path"),
            "bytes": identity.get("bytes"),
            "sha256": digest,
        }:
            raise CatalogError(f"artifact {digest} disagrees with its run")

    for digest, value in deltas.items():
        identity = _object(value, f"delta {digest}")
        _validate_blob(history_dir, identity, digest, f"delta {digest}")
        if identity.get("run") not in runs or identity.get("baseline_run") not in runs:
            raise CatalogError(f"delta {digest} names an unknown run")

    for digest, value in bundles.items():
        locator = _object(value, f"bundle {digest}")
        manifest_path = _safe_path(
            history_dir,
            f"{locator.get('path')}/manifest.json",
            f"bundle {digest}.manifest",
        )
        manifest_raw = manifest_path.read_bytes()
        if not SHA256_RE.fullmatch(digest) or _sha256(manifest_raw) != digest:
            raise CatalogError(f"bundle {digest} manifest digest mismatch")
        manifest, _ = _load_json(manifest_path, f"bundle {digest} manifest")
        run_id = locator.get("run")
        run = _object(runs.get(run_id), f"bundle {digest}.run")
        report = _object(run.get("report"), f"bundle {digest}.report")
        manifest_report = _object(
            manifest.get("report"), f"bundle {digest}.manifest.report"
        )
        if (
            locator.get("report_sha256") != report.get("sha256")
            or manifest_report.get("sha256") != report.get("sha256")
            or manifest_report.get("bytes") != report.get("bytes")
        ):
            raise CatalogError(f"bundle {digest} report binding mismatch")
        files = _array(manifest.get("files"), f"bundle {digest}.files")
        artifact_bytes = 0
        for file_index, value in enumerate(files):
            item = _object(value, f"bundle {digest}.files[{file_index}]")
            artifact = _validate_blob(
                history_dir,
                {
                    "path": f"{locator.get('path')}/tree/{item.get('path')}",
                    "bytes": item.get("bytes"),
                },
                str(item.get("sha256")),
                f"bundle {digest}.files[{file_index}]",
            )
            artifact_bytes += artifact.stat().st_size
        totals = _object(manifest.get("totals"), f"bundle {digest}.totals")
        if totals != {"artifact_files": len(files), "artifact_bytes": artifact_bytes}:
            raise CatalogError(f"bundle {digest} totals are inconsistent")
        if (
            locator.get("artifact_files") != len(files)
            or locator.get("artifact_bytes") != artifact_bytes
            or run.get("bundle") != locator
        ):
            raise CatalogError(f"bundle {digest} locator is inconsistent")

    for index_value, value in enumerate(comparisons):
        comparison = _object(value, f"comparison[{index_value}]")
        if (
            comparison.get("baseline_sha256") not in artifacts
            or comparison.get("current_sha256") not in artifacts
            or comparison.get("delta_sha256") not in deltas
        ):
            raise CatalogError(f"comparison[{index_value}] references unknown evidence")
        delta = deltas[comparison["delta_sha256"]]
        if comparison.get("delta_path") != delta.get("path"):
            raise CatalogError(f"comparison[{index_value}] delta path mismatch")


def _formal_blockers(report: dict[str, Any]) -> list[str]:
    configuration = report.get("configuration")
    if not isinstance(configuration, dict):
        return ["configuration is missing"]
    provenance = configuration.get("provenance")
    host = configuration.get("host_environment")
    blockers: list[str] = []
    if not isinstance(provenance, dict) or provenance.get("complete") is not True:
        blockers.append("source provenance is incomplete")
    else:
        if not COMMIT_RE.fullmatch(str(provenance.get("git_commit", ""))):
            blockers.append("measurement commit is missing")
        if provenance.get("git_dirty") is not False:
            blockers.append("measurement worktree was dirty")
    if not isinstance(host, dict) or host.get("complete") is not True:
        blockers.append("machine provenance is incomplete")
    else:
        hardware = host.get("hardware")
        platform = host.get("platform")
        toolchain = host.get("toolchain")
        for value, label in (
            (hardware, "hardware"),
            (platform, "platform"),
            (toolchain, "toolchain"),
        ):
            if not isinstance(value, dict):
                blockers.append(f"{label} provenance is missing")
        if isinstance(hardware, dict):
            for field in ("chip", "machine_model", "machine_name", "physical_memory"):
                if not isinstance(hardware.get(field), str) or not hardware[field].strip():
                    blockers.append(f"hardware.{field} is missing")
        if isinstance(platform, dict):
            for field in ("system", "machine", "os_product_version", "os_build_version"):
                if not isinstance(platform.get(field), str) or not platform[field].strip():
                    blockers.append(f"platform.{field} is missing")
        if isinstance(toolchain, dict) and not toolchain.get("zig_version"):
            blockers.append("toolchain.zig_version is missing")
    try:
        _utc_timestamp(report.get("generated_at"), "generated_at")
    except CatalogError as error:
        blockers.append(str(error))
    return blockers


def _publication_state(
    run_id: str,
    entry: dict[str, Any],
    run_entries: dict[str, Any],
) -> dict[str, str | None]:
    status = entry.get("status", "active")
    if not isinstance(status, str) or status not in PUBLICATION_STATUSES:
        raise CatalogError(
            f"run {run_id}.status must be active, invalidated, or superseded"
        )

    reason = entry.get("status_reason")
    superseded_by = entry.get("superseded_by")
    if status == "active":
        if "status_reason" in entry:
            raise CatalogError(f"run {run_id}.status_reason is forbidden when active")
        if "superseded_by" in entry:
            raise CatalogError(f"run {run_id}.superseded_by is forbidden when active")
        return {"status": status, "reason": None, "superseded_by": None}

    reason = _text(reason, f"run {run_id}.status_reason")
    if status == "invalidated":
        if "superseded_by" in entry:
            raise CatalogError(
                f"run {run_id}.superseded_by is forbidden when invalidated"
            )
        return {"status": status, "reason": reason, "superseded_by": None}

    superseded_by = _text(superseded_by, f"run {run_id}.superseded_by")
    if superseded_by == run_id:
        raise CatalogError(f"run {run_id}.superseded_by must name a different run")
    if superseded_by not in run_entries:
        raise CatalogError(f"run {run_id}.superseded_by names an unknown run")
    return {"status": status, "reason": reason, "superseded_by": superseded_by}


def _metric(lane: dict[str, Any], name: str, label: str) -> dict[str, float]:
    metrics = _object(lane.get("metrics"), f"{label}.metrics")
    value = _object(metrics.get(name), f"{label}.metrics.{name}")
    return {
        "median": _number(value.get("median"), f"{label}.metrics.{name}.median"),
        "mad": _number(value.get("mad"), f"{label}.metrics.{name}.mad"),
        "min": _number(value.get("min"), f"{label}.metrics.{name}.min"),
        "max": _number(value.get("max"), f"{label}.metrics.{name}.max"),
    }


def _process_resources(value: Any, label: str) -> dict[str, Any]:
    resources = _object(value, label)
    if set(resources) != PROCESS_RESOURCE_KEYS:
        raise CatalogError(f"{label} has the wrong schema")
    if resources["measurement"] not in {
        "darwin_usr_bin_time_l_v1",
        "gnu_usr_bin_time_v_v1",
    }:
        raise CatalogError(f"{label}.measurement is unsupported")
    if resources["measurement_locale"] != "C":
        raise CatalogError(f"{label}.measurement_locale must be C")
    if resources["normalized_unit"] != "KiB":
        raise CatalogError(f"{label}.normalized_unit must be KiB")
    peak = resources["peak_rss_kib"]
    if type(peak) is not int or peak <= 0:
        raise CatalogError(f"{label}.peak_rss_kib must be a positive integer")
    return dict(resources)


def _request_resources(
    value: Any,
    proof_bytes: int,
    label: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    resources = _object(value, label)
    if set(resources) != REQUEST_RESOURCE_KEYS:
        raise CatalogError(f"{label} has the wrong schema")
    if resources["measurement_scope"] != "verified_process_request_batch":
        raise CatalogError(f"{label}.measurement_scope is not governed")
    warmups = resources["measured_warmups"]
    samples = resources["measured_samples"]
    if type(warmups) is not int or warmups < 0:
        raise CatalogError(f"{label}.measured_warmups must be nonnegative")
    if type(samples) is not int or samples <= 0:
        raise CatalogError(f"{label}.measured_samples must be positive")
    if resources["canonical_proof_bytes"] != proof_bytes:
        raise CatalogError(f"{label}.canonical_proof_bytes disagrees with proof")

    complete = resources["complete"]
    if type(complete) is not bool:
        raise CatalogError(f"{label}.complete must be boolean")
    counters = (
        "lifetime_peak_physical_footprint_bytes",
        "energy_nj",
        "instructions",
        "cycles",
    )
    if complete:
        if (
            resources["source"] != "darwin_proc_pid_rusage_v6"
            or resources["unavailable_reason"] is not None
        ):
            raise CatalogError(f"{label} complete source is invalid")
        for counter in counters:
            value = resources[counter]
            if type(value) is not int or value <= 0:
                raise CatalogError(f"{label}.{counter} must be a positive integer")
    else:
        reason = resources["unavailable_reason"]
        if resources["source"] != "unsupported":
            raise CatalogError(f"{label} incomplete source must be unsupported")
        if not isinstance(reason, str) or not reason.strip():
            raise CatalogError(f"{label} incomplete measurement requires a reason")
        if any(resources[counter] is not None for counter in counters):
            raise CatalogError(f"{label} unsupported counters must be null")
    return dict(resources)


def _lane(row: dict[str, Any], lane_name: str, row_index: int) -> dict[str, Any]:
    lane = _object(
        _object(row.get("lanes"), f"row[{row_index}].lanes").get(lane_name),
        f"row[{row_index}].lanes.{lane_name}",
    )
    proof = _object(lane.get("proof"), f"row[{row_index}].lanes.{lane_name}.proof")
    proof_bytes = int(
        _number(proof.get("bytes"), f"row[{row_index}].proof.bytes")
    )
    label = f"row[{row_index}].lanes.{lane_name}"
    return {
        "backend": _text(lane.get("backend"), f"row[{row_index}].lanes.{lane_name}.backend"),
        "display_name": _text(
            lane.get("display_name"), f"row[{row_index}].lanes.{lane_name}.display_name"
        ),
        "metrics": {
            metric: _metric(lane, metric, f"row[{row_index}].lanes.{lane_name}")
            for metric in METRICS
        },
        "proof": {
            "bytes": proof_bytes,
            "sha256": _text(proof.get("sha256"), f"row[{row_index}].proof.sha256"),
            "verified_samples": int(
                _number(
                    proof.get("verified_samples"),
                    f"row[{row_index}].proof.verified_samples",
                )
            ),
            "byte_identical": proof.get("all_samples_byte_identical") is True,
        },
        "resources": _process_resources(lane.get("resources"), f"{label}.resources"),
        "request_resources": _request_resources(
            lane.get("request_resources"),
            proof_bytes,
            f"{label}.request_resources",
        ),
        "process_wall_seconds": _number(
            lane.get("process_wall_seconds"),
            f"row[{row_index}].lanes.{lane_name}.process_wall_seconds",
        ),
    }


def _normalize_row(row: Any, expected_index: int) -> dict[str, Any]:
    row = _object(row, f"row[{expected_index}]")
    if row.get("index") != expected_index:
        raise CatalogError(f"row[{expected_index}] index drifted")
    descriptor = _text(row.get("descriptor_sha256"), f"row[{expected_index}].descriptor")
    if not SHA256_RE.fullmatch(descriptor):
        raise CatalogError(f"row[{expected_index}] descriptor digest is invalid")
    workload = _object(row.get("workload"), f"row[{expected_index}].workload")
    lanes = {lane: _lane(row, lane, expected_index) for lane in LANES}
    rust_oracle = _object(row.get("rust_oracle"), f"row[{expected_index}].rust_oracle")
    if row.get("proof_parity") is not True:
        raise CatalogError(f"row[{expected_index}] does not have CPU/Metal proof parity")
    if rust_oracle.get("verified") is not True or rust_oracle.get("status") != "passed":
        raise CatalogError(f"row[{expected_index}] did not pass the Rust oracle")
    if lanes["cpu"]["proof"]["sha256"] != lanes["metal"]["proof"]["sha256"]:
        raise CatalogError(f"row[{expected_index}] proof digests differ")
    return {
        "id": descriptor[:12],
        "index": expected_index,
        "descriptor_sha256": descriptor,
        "workload": {
            "name": _text(workload.get("name"), f"row[{expected_index}].workload.name"),
            "parameters": _object(
                workload.get("parameters"), f"row[{expected_index}].workload.parameters"
            ),
            "native_unit": _text(
                workload.get("native_unit"), f"row[{expected_index}].workload.native_unit"
            ),
            "native_units": int(
                _number(workload.get("native_units"), f"row[{expected_index}].native_units")
            ),
            "trace_rows": int(
                _number(workload.get("trace_rows"), f"row[{expected_index}].trace_rows")
            ),
            "trace_log_rows": int(
                _number(
                    workload.get("trace_log_rows"), f"row[{expected_index}].trace_log_rows"
                )
            ),
            "committed_columns": int(
                _number(
                    workload.get("committed_columns"),
                    f"row[{expected_index}].committed_columns",
                )
            ),
            "committed_trace_cells": int(
                _number(
                    workload.get("committed_trace_cells"),
                    f"row[{expected_index}].committed_trace_cells",
                )
            ),
        },
        "headline_eligible": row.get("headline_eligible") is True,
        "headline_blockers": [str(value) for value in row.get("headline_blockers", [])],
        "proof": {
            "bytes": int(_number(row.get("proof_bytes"), f"row[{expected_index}].proof_bytes")),
            "sha256": _text(
                row.get("proof_digest_sha256"), f"row[{expected_index}].proof_digest"
            ),
            "parity": True,
            "rust_oracle_verified": True,
            "rust_upstream_commit": _text(
                rust_oracle.get("upstream_commit"),
                f"row[{expected_index}].rust_oracle.upstream_commit",
            ),
        },
        "lanes": lanes,
        "speedup": {
            key: _number(value, f"row[{expected_index}].speedup.{key}")
            for key, value in _object(row.get("speedup"), f"row[{expected_index}].speedup").items()
        },
    }


def _run_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    headline = [row for row in rows if row["headline_eligible"]]
    measured = headline or rows
    cpu_mhz = [row["lanes"]["cpu"]["metrics"]["native_mhz"]["median"] for row in measured]
    metal_mhz = [
        row["lanes"]["metal"]["metrics"]["native_mhz"]["median"] for row in measured
    ]
    speedups = [row["speedup"]["metal_native_mhz_speedup"] for row in measured]
    verified = sum(
        row["lanes"][lane]["proof"]["verified_samples"]
        for row in rows
        for lane in LANES
    )
    return {
        "rows": len(rows),
        "headline_rows": len(headline),
        "diagnostic_rows": len(rows) - len(headline),
        "verified_proofs": verified,
        "median_cpu_mhz": statistics.median(cpu_mhz),
        "median_metal_mhz": statistics.median(metal_mhz),
        "median_metal_speedup": statistics.median(speedups),
        "peak_cpu_mhz": max(cpu_mhz),
        "peak_metal_mhz": max(metal_mhz),
        "metal_wins": sum(speedup > 1 for speedup in speedups),
    }


def _normalize_run(
    run_id: str,
    entry: dict[str, Any],
    report: dict[str, Any],
    report_sha256: str,
) -> dict[str, Any]:
    configuration = _object(report.get("configuration"), f"{run_id}.configuration")
    provenance = _object(configuration.get("provenance"), f"{run_id}.provenance")
    host = _object(configuration.get("host_environment"), f"{run_id}.host_environment")
    hardware = _object(host.get("hardware"), f"{run_id}.hardware")
    platform = _object(host.get("platform"), f"{run_id}.platform")
    toolchain = _object(host.get("toolchain"), f"{run_id}.toolchain")
    rows = [
        _normalize_row(row, index)
        for index, row in enumerate(_array(report.get("rows"), f"{run_id}.rows"))
    ]
    if not rows:
        raise CatalogError(f"{run_id} has no benchmark rows")
    commit = _text(provenance.get("git_commit"), f"{run_id}.git_commit")
    if not COMMIT_RE.fullmatch(commit):
        raise CatalogError(f"{run_id} measurement commit is invalid")
    source = _object(entry.get("report"), f"{run_id}.report")
    return {
        "id": run_id,
        "captured_at": _utc_timestamp(report.get("generated_at"), f"{run_id}.generated_at"),
        "source": {
            "path": _text(source.get("path"), f"{run_id}.report.path"),
            "sha256": report_sha256,
            "bytes": int(_number(source.get("bytes"), f"{run_id}.report.bytes")),
            "protocol": _text(report.get("protocol"), f"{run_id}.protocol"),
            "schema_version": int(
                _number(report.get("schema_version"), f"{run_id}.schema_version")
            ),
        },
        "revision": {
            "git_commit": commit,
            "git_dirty": False,
            "optimization": _text(
                provenance.get("optimization"), f"{run_id}.optimization"
            ),
            "target": f"{provenance.get('target_arch')}-{provenance.get('target_os')}",
            "thread_parallelism_enabled": provenance.get("thread_parallelism_enabled") is True,
            "simd_pack_width": int(
                _number(provenance.get("simd_pack_width"), f"{run_id}.simd_pack_width")
            ),
        },
        "machine": {
            "name": _text(hardware.get("machine_name"), f"{run_id}.machine_name"),
            "model": _text(hardware.get("machine_model"), f"{run_id}.machine_model"),
            "chip": _text(hardware.get("chip"), f"{run_id}.chip"),
            "logical_cpu_count": int(
                _number(hardware.get("logical_cpu_count"), f"{run_id}.logical_cpu_count")
            ),
            "physical_memory": _text(
                hardware.get("physical_memory"), f"{run_id}.physical_memory"
            ),
            "gpu": _object(host.get("metal_device"), f"{run_id}.metal_device"),
            "platform": platform,
        },
        "toolchain": toolchain,
        "settings": {
            "proof_protocol": configuration.get("proof_protocol"),
            "metal_runtime": configuration.get("metal_runtime"),
            "blake2_backend": configuration.get("blake2_backend"),
            "execution": configuration.get("execution"),
            "samples_per_lane": configuration.get("samples_per_lane"),
            "warmups_per_lane": configuration.get("warmups_per_lane"),
            "cooldown_seconds": configuration.get("cooldown_seconds"),
        },
        "summary": _run_summary(rows),
        "rows": rows,
    }


def build_catalog(history_dir: Path) -> dict[str, Any]:
    history_dir = history_dir.resolve()
    index, index_raw = _load_json(history_dir / "index.json", "benchmark history index")
    if index.get("schema_version") != INDEX_SCHEMA_VERSION:
        raise CatalogError("benchmark history index schema is unsupported")
    _validate_archive_integrity(history_dir, index)
    run_entries = _object(index.get("runs"), "benchmark history runs")
    runs: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for run_id, raw_entry in run_entries.items():
        entry = _object(raw_entry, f"run {run_id}")
        publication = _publication_state(run_id, entry, run_entries)
        report_identity = _object(entry.get("report"), f"run {run_id}.report")
        report_path = _safe_path(history_dir, report_identity.get("path"), f"run {run_id}.path")
        report, report_raw = _load_json(report_path, f"run {run_id} report")
        actual_digest = _sha256(report_raw)
        expected_digest = report_identity.get("sha256")
        if not SHA256_RE.fullmatch(str(expected_digest)) or actual_digest != expected_digest:
            raise CatalogError(f"run {run_id} report digest mismatch")
        if len(report_raw) != report_identity.get("bytes"):
            raise CatalogError(f"run {run_id} report byte count mismatch")
        blockers = _formal_blockers(report)
        if publication["status"] != "active":
            blockers.insert(
                0,
                f"publication status is {publication['status']}: {publication['reason']}",
            )
        if blockers:
            excluded.append(
                {
                    "id": run_id,
                    "captured_at": report.get("generated_at"),
                    "git_commit": _object(
                        report.get("configuration", {}), f"run {run_id}.configuration"
                    ).get("provenance", {}).get("git_commit"),
                    "source_sha256": actual_digest,
                    "status": publication["status"],
                    "superseded_by": publication["superseded_by"],
                    "reasons": blockers,
                }
            )
            continue
        runs.append(_normalize_run(run_id, entry, report, actual_digest))
    runs.sort(key=lambda run: (run["captured_at"], run["id"]), reverse=True)
    excluded.sort(key=lambda run: (str(run.get("captured_at")), run["id"]), reverse=True)
    if not runs:
        raise CatalogError("benchmark history has no provenance-complete runs")
    return {
        "schema": CATALOG_SCHEMA,
        "source": {
            "index_path": "vectors/reports/benchmark_history/index.json",
            "index_sha256": _sha256(index_raw),
            "index_schema_version": INDEX_SCHEMA_VERSION,
        },
        "publication_policy": {
            "formal_runs_require_clean_commit": True,
            "formal_runs_require_complete_machine": True,
            "formal_rows_require_cpu_metal_proof_parity": True,
            "formal_rows_require_pinned_rust_oracle": True,
            "legacy_runs_are_excluded_not_deleted": True,
            "invalidated_and_superseded_runs_are_excluded_not_deleted": True,
        },
        "latest_run_id": runs[0]["id"],
        "runs": runs,
        "excluded_runs": excluded,
    }
