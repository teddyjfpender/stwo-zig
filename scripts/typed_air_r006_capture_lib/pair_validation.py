"""Independent replay of a completed paired CPU/Metal R-006 bundle."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .codec import canonical_bytes, content_digest, exact_object, sha256_bytes
from .controller import validate_bundle
from .model import PLAN_ATTEMPTS, UTC_RE, CaptureError
from . import exact_work_cells
from . import pair_durability as durability
from . import pair_identity
from . import pair_publication as publication


def _read_root_json(path: Path) -> dict[str, Any]:
    return durability.read_canonical_json_regular(
        path, f"paired bundle {path.name}"
    )


def _lane_records(path: Path) -> list[dict[str, Any]]:
    records = durability.read_journal_regular(
        path / "journal.ndjson", "paired lane journal"
    )
    if len(records) != PLAN_ATTEMPTS + 1:
        raise CaptureError("paired lane journal attempt cardinality changed")
    return records[1:]


def _snapshot_identity(
    root: Path, relative: str, expected: bytes
) -> dict[str, Any]:
    raw = durability.read_regular_bytes(
        root / relative, f"paired reduction snapshot {relative}"
    )
    if raw != expected:
        raise CaptureError(f"paired reduction source changed: {relative}")
    return {"bytes": len(raw), "sha256": sha256_bytes(raw)}


def assert_pair_snapshot_current(
    bundle_path: Path, snapshot: dict[str, Any]
) -> None:
    root = bundle_path.absolute()
    identities = snapshot.get("identities")
    if type(identities) is not dict:
        raise CaptureError("paired reduction snapshot identities are missing")
    for relative, expected in identities.items():
        raw = durability.read_regular_bytes(
            root / relative, f"paired reduction replay {relative}"
        )
        if (
            type(expected) is not dict
            or expected
            != {"bytes": len(raw), "sha256": sha256_bytes(raw)}
        ):
            raise CaptureError(f"paired reduction source changed: {relative}")


def validate_exact_work_authority(
    plan: dict[str, Any],
    lane_records: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Bind exact executed work only within identical plan-selected cells."""

    from .pair import PAIR_LANE_ORDER

    return exact_work_cells.validate_cell_authority(
        plan, lane_records, PAIR_LANE_ORDER
    )


def validate_pair_bundle(
    repository: Path,
    bundle_path: Path,
    *,
    include_snapshot: bool = False,
) -> dict[str, Any]:
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

    root = bundle_path.absolute()
    durability.require_regular_directory(root, "paired R-006 bundle")
    entries = {path.name: path for path in root.iterdir()}
    expected_entries = {
        "pair-plan.json",
        "pair-bundle.json",
        "pair-journal.ndjson",
        publication.PUBLICATION_JOURNAL_NAME,
        durability.BOUNDARY_JOURNAL_NAME,
        *PAIR_LANE_ORDER,
    }
    if set(entries) != expected_entries:
        raise CaptureError("paired R-006 root inventory changed")
    for lane in PAIR_LANE_ORDER:
        if entries[lane].is_symlink() or not entries[lane].is_dir():
            raise CaptureError("paired R-006 lane entry is not a regular directory")
    for name in (
        "pair-plan.json",
        "pair-bundle.json",
        "pair-journal.ndjson",
        publication.PUBLICATION_JOURNAL_NAME,
        durability.BOUNDARY_JOURNAL_NAME,
    ):
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
        or manifest["schema_version"] != 2
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
    lane_validations: dict[str, dict[str, Any]] = {}
    lane_records: dict[str, list[dict[str, Any]]] = {}
    lane_journal_records: dict[str, list[dict[str, Any]]] = {}
    lane_manifests: dict[str, dict[str, Any]] = {}
    for lane in PAIR_LANE_ORDER:
        lane_validation = validate_bundle(
            repository.resolve(), root / lane, include_snapshot=True
        )
        lane_snapshot = lane_validation.pop("_snapshot")
        lane_validations[lane] = lane_validation
        if lane_snapshot["plan"] != plan["lanes"][lane]:
            raise CaptureError("paired lane plan differs from root authority")
        lane_journal_records[lane] = lane_snapshot["records"]
        lane_records[lane] = lane_journal_records[lane][1:]
        lane_manifest = lane_snapshot["bundle"]
        lane_manifests[lane] = lane_manifest
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
    progress = durability.read_journal_regular(
        root / "pair-journal.ndjson", "paired progress journal"
    )
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
    if manifest["pair_journal"] != durability.journal_identity(
        progress, "pair-journal.ndjson"
    ):
        raise CaptureError("paired R-006 progress identity changed")
    publication_summary, publication_identity = publication.read_publication_journal(
        root / publication.PUBLICATION_JOURNAL_NAME,
        plan=plan,
        lane_records=lane_records,
        require_complete=True,
    )
    if manifest["attempt_publication_journal"] != publication_identity:
        raise CaptureError("paired attempt-publication identity changed")
    boundary_summary, boundary_identity = durability.read_boundary_journal(
        root / durability.BOUNDARY_JOURNAL_NAME,
        plan=plan,
        completed_attempts=PAIR_ATTEMPTS,
        require_complete=True,
        recovery_authorizations=publication_summary["authorizations"],
    )
    if manifest["preflight_boundary_journal"] != boundary_identity:
        raise CaptureError("paired preflight boundary identity changed")
    if (
        manifest["start_preflight"] != boundary_summary["first_preflight"]
        or manifest["end_preflight"] != boundary_summary["final_preflight"]
        or manifest["completed_at_utc"]
        != boundary_summary["final_preflight"]["captured_at_utc"]
    ):
        raise CaptureError("paired manifest is not boundary-journal derived")
    for lane in PAIR_LANE_ORDER:
        if (
            lane_manifests[lane]["started_at_utc"] != progress_header["started_at_utc"]
            or lane_manifests[lane]["completed_at_utc"] != manifest["completed_at_utc"]
        ):
            raise CaptureError("paired lane timestamps are not journal-derived")
    exact_work_authority = validate_exact_work_authority(plan, lane_records)
    identities = pair_identity.validate_pair_identity_authority(
        plan, lane_records, PAIR_LANE_ORDER
    )
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
    result = {
        "schema": PAIR_VALIDATION_SCHEMA,
        "schema_version": 3,
        "status": expected_status,
        "plan_sha256": plan["content_sha256"],
        "attempts": PAIR_ATTEMPTS,
        "verified_attempts": verified,
        "failed_attempts": failed,
        "exact_work_v4_attempts": exact_work,
        "independent_verifier_attempts": independent,
        "cross_lane_identity_workloads": len(identities),
        "exact_work_authority": exact_work_authority,
        "lane_validations": lane_validations,
        "fixed_interleaving_valid": True,
        "resumable_journal_valid": True,
        "attempt_publication_journal_valid": (
            publication_summary["committed_attempts"] == PAIR_ATTEMPTS
        ),
        "preflight_boundary_journal_valid": True,
        "recovery_disclosure": publication_summary["recovery_disclosure"],
        "normative_scaling_capture": (
            failed == 0
            and verified == PAIR_ATTEMPTS
            and exact_work == PAIR_ATTEMPTS
            and independent == PAIR_ATTEMPTS
            and len(identities) == 4
            and exact_work_authority["every_attempt_complete_exact_work"]
            and exact_work_authority["every_cell_deterministic"]
            and not publication_summary["authorizations"]
        ),
        "operator_authorized_scaling_capture": (
            failed == 0
            and verified == PAIR_ATTEMPTS
            and exact_work == PAIR_ATTEMPTS
            and independent == PAIR_ATTEMPTS
            and len(identities) == 4
            and exact_work_authority["every_attempt_complete_exact_work"]
            and exact_work_authority["every_cell_deterministic"]
        ),
        "normative_m7_receipt": False,
    }
    if include_snapshot:
        expected_bytes = {
            "pair-plan.json": canonical_bytes(plan),
            "pair-bundle.json": canonical_bytes(manifest),
            **{
                f"{lane}/journal.ndjson": b"".join(
                    canonical_bytes(record) for record in lane_journal_records[lane]
                )
                for lane in PAIR_LANE_ORDER
            },
        }
        identities = {
            relative: _snapshot_identity(root, relative, raw)
            for relative, raw in expected_bytes.items()
        }
        result["_snapshot"] = {
            "plan": plan,
            "bundle": manifest,
            "lane_records": lane_records,
            "identities": identities,
        }
    return result
