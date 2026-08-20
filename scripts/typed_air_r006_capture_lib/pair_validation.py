"""Independent replay of a completed paired CPU/Metal R-006 bundle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .codec import canonical_bytes, content_digest, decode_strict, exact_object, sha256_file
from .controller import _journal, validate_bundle
from .model import PLAN_ATTEMPTS, UTC_RE, CaptureError
from .preflight import validate_host_preflight


def _read_root_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    value = decode_strict(raw)
    if type(value) is not dict or raw != canonical_bytes(value):
        raise CaptureError(f"paired bundle file is not canonical JSON: {path.name}")
    return value


def _lane_records(path: Path) -> list[dict[str, Any]]:
    records = _journal(path / "journal.ndjson")
    if len(records) != PLAN_ATTEMPTS + 1:
        raise CaptureError("paired lane journal attempt cardinality changed")
    return records[1:]


def validate_pair_bundle(repository: Path, bundle_path: Path) -> dict[str, Any]:
    # Imported at call time so the public ``pair`` facade can re-export this
    # leaf validator without making validation part of capture initialization.
    from .pair import (
        PAIR_ATTEMPTS,
        PAIR_BUNDLE_FIELDS,
        PAIR_BUNDLE_SCHEMA,
        PAIR_LANE_ORDER,
        PAIR_PROGRESS_HEADER_SCHEMA,
        PAIR_VALIDATION_SCHEMA,
        _completed_interleaving,
        validate_pair_plan,
    )

    root = bundle_path.resolve()
    if root.is_symlink() or not root.is_dir():
        raise CaptureError("paired R-006 bundle is not a regular directory")
    entries = {path.name: path for path in root.iterdir()}
    expected_entries = {
        "pair-plan.json",
        "pair-bundle.json",
        "pair-journal.ndjson",
        *PAIR_LANE_ORDER,
    }
    if set(entries) != expected_entries:
        raise CaptureError("paired R-006 root inventory changed")
    for lane in PAIR_LANE_ORDER:
        if entries[lane].is_symlink() or not entries[lane].is_dir():
            raise CaptureError("paired R-006 lane entry is not a regular directory")
    for name in ("pair-plan.json", "pair-bundle.json", "pair-journal.ndjson"):
        if entries[name].is_symlink() or not entries[name].is_file():
            raise CaptureError("paired R-006 root evidence is not a regular file")
    plan = _read_root_json(root / "pair-plan.json")
    validate_pair_plan(plan, repository=repository.resolve(), verify_local=False)
    manifest = exact_object(
        _read_root_json(root / "pair-bundle.json"),
        PAIR_BUNDLE_FIELDS,
        "paired R-006 bundle manifest",
    )
    if (
        manifest["schema"] != PAIR_BUNDLE_SCHEMA
        or manifest["schema_version"] != 1
        or manifest["session_id"] != plan["session_id"]
        or manifest["plan_sha256"] != plan["content_sha256"]
        or manifest["planned_attempts"] != PAIR_ATTEMPTS
        or manifest["recorded_attempts"] != PAIR_ATTEMPTS
        or manifest["content_sha256"] != content_digest(manifest)
    ):
        raise CaptureError("paired R-006 bundle manifest changed")
    for name in ("started_at_utc", "completed_at_utc"):
        if type(manifest[name]) is not str or UTC_RE.fullmatch(manifest[name]) is None:
            raise CaptureError(f"paired R-006 bundle {name} is not canonical UTC")
    if type(manifest["lanes"]) is not dict or tuple(manifest["lanes"]) != PAIR_LANE_ORDER:
        raise CaptureError("paired R-006 bundle lane summary order changed")
    validate_host_preflight(manifest["start_preflight"], require_admitted=True)
    validate_host_preflight(manifest["end_preflight"], require_admitted=True)
    if (
        manifest["start_preflight"]["host"] != plan["host_preflight"]["host"]
        or manifest["end_preflight"]["host"] != plan["host_preflight"]["host"]
    ):
        raise CaptureError("paired R-006 bundle host identity drifted")
    lane_validations: dict[str, dict[str, Any]] = {}
    lane_records: dict[str, list[dict[str, Any]]] = {}
    for lane in PAIR_LANE_ORDER:
        lane_validations[lane] = validate_bundle(repository.resolve(), root / lane)
        lane_records[lane] = _lane_records(root / lane)
        lane_manifest = _read_root_json(root / lane / "bundle.json")
        expected_lane_summary = {
            "path": lane,
            "plan_sha256": plan["lanes"][lane]["content_sha256"],
            "attempts": PLAN_ATTEMPTS,
            "verified_attempts": lane_manifest["verified_attempts"],
            "failed_attempts": lane_manifest["failed_attempts"],
            "journal": lane_manifest["journal"],
            "bundle_sha256": lane_manifest["content_sha256"],
        }
        if manifest["lanes"][lane] != expected_lane_summary:
            raise CaptureError("paired R-006 lane summary is not bundle-derived")
    expected_progress = _completed_interleaving(plan, lane_records)
    progress = _journal(root / "pair-journal.ndjson")
    if len(progress) != PAIR_ATTEMPTS + 1 or progress[1:] != expected_progress:
        raise CaptureError("paired R-006 progress journal is not lane-derived")
    progress_header = exact_object(
        progress[0],
        {
            "schema",
            "session_id",
            "plan_sha256",
            "planned_attempts",
            "started_at_utc",
            "content_sha256",
        },
        "paired progress header",
    )
    if (
        progress_header["schema"] != PAIR_PROGRESS_HEADER_SCHEMA
        or progress_header["session_id"] != plan["session_id"]
        or progress_header["plan_sha256"] != plan["content_sha256"]
        or progress_header["planned_attempts"] != PAIR_ATTEMPTS
        or progress_header["started_at_utc"] != manifest["started_at_utc"]
    ):
        raise CaptureError("paired R-006 progress header differs from the manifest")
    progress_size, progress_digest = sha256_file(root / "pair-journal.ndjson")
    if manifest["pair_journal"] != {
        "path": "pair-journal.ndjson",
        "bytes": progress_size,
        "sha256": progress_digest,
        "records": len(progress),
    }:
        raise CaptureError("paired R-006 progress identity changed")
    identities: dict[str, dict[str, Any]] = {}
    verified = failed = exact_work = independent = 0
    for lane in PAIR_LANE_ORDER:
        for attempt, record in zip(
            plan["lanes"][lane]["attempts"], lane_records[lane], strict=True
        ):
            if record["status"] != "verified":
                failed += 1
                continue
            verified += 1
            independent += record["independent_verification"]["status"] == "verified"
            exact_work += (
                record["metrics"] is not None
                and "work_disclosure" in record["metrics"]
            )
            workload = attempt["workload_id"]
            prior = identities.setdefault(workload, record["identity"])
            if prior != record["identity"]:
                raise CaptureError(
                    f"CPU/Metal proof identity changed for paired workload {workload}"
                )
    if (
        manifest["verified_attempts"] != verified
        or manifest["failed_attempts"] != failed
        or manifest["independent_verifier_attempts"] != independent
        or manifest["exact_work_v4_attempts"] != exact_work
        or manifest["cross_lane_identity_workloads"] != len(identities)
    ):
        raise CaptureError("paired R-006 raw-derived counters changed")
    expected_status = (
        "CAPTURE_COMPLETE_WITH_FAILURES"
        if failed
        else "CAPTURE_COMPLETE_AWAITING_STATISTICAL_RECEIPT"
    )
    if manifest["status"] != expected_status:
        raise CaptureError("paired R-006 status is not raw-derived")
    return {
        "schema": PAIR_VALIDATION_SCHEMA,
        "status": expected_status,
        "plan_sha256": plan["content_sha256"],
        "attempts": PAIR_ATTEMPTS,
        "verified_attempts": verified,
        "failed_attempts": failed,
        "exact_work_v4_attempts": exact_work,
        "independent_verifier_attempts": independent,
        "cross_lane_identity_workloads": len(identities),
        "lane_validations": lane_validations,
        "fixed_interleaving_valid": True,
        "resumable_journal_valid": True,
        "normative_scaling_capture": (
            failed == 0
            and verified == PAIR_ATTEMPTS
            and exact_work == PAIR_ATTEMPTS
            and independent == PAIR_ATTEMPTS
            and len(identities) == 4
        ),
        "normative_m7_receipt": False,
    }
