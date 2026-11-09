"""Authenticate a resumable, complete-comparison prefix of paired R-006.

The frozen plan remains immutable.  This authority validates every retained
attempt, selects only statistically complete 80-attempt comparison blocks,
and binds append-only journal prefixes so a receipt remains replayable after
the capture grows.  It never represents a prefix as the complete 2,080-run
matrix or as an M7 promotion receipt.
"""

from __future__ import annotations

import copy
import os
import stat
from pathlib import Path
from typing import Any, Mapping

from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    sha256_bytes,
)
from .controller import FileInventory, JOURNAL_HEADER_SCHEMA, _validate_record
from .model import (
    ATTEMPTS_PER_COMPARISON,
    PLAN_ATTEMPTS,
    WORKLOAD_IDS,
    CaptureError,
)
from .pair import (
    PAIR_ATTEMPTS,
    PAIR_LANE_ORDER,
    validate_pair_plan,
)
from . import exact_work_cells
from . import pair_durability as durability
from . import pair_identity
from . import pair_publication as publication
from .reduction import SCALING_COMPARISONS


PREFIX_AUTHORITY_SCHEMA = "stwo.typed-air.r006-complete-block-prefix-authority.v1"
PREFIX_VALIDATION_SCHEMA = "stwo.typed-air.r006-complete-block-prefix-validation.v1"


def _root_entries(root: Path) -> None:
    required_files = {
        "pair-plan.json",
        "pair-journal.ndjson",
        publication.PUBLICATION_JOURNAL_NAME,
        durability.BOUNDARY_JOURNAL_NAME,
    }
    optional_files = {"pair-bundle.json"}
    expected_directories = set(PAIR_LANE_ORDER)
    files: set[str] = set()
    directories: set[str] = set()
    try:
        entries = list(root.iterdir())
    except OSError as error:
        raise CaptureError("cannot enumerate paired prefix bundle") from error
    for entry in entries:
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise CaptureError("cannot inspect paired prefix entry") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise CaptureError("paired prefix bundle contains a symlink")
        if stat.S_ISREG(metadata.st_mode):
            files.add(entry.name)
        elif stat.S_ISDIR(metadata.st_mode):
            directories.add(entry.name)
        else:
            raise CaptureError("paired prefix bundle contains a special file")
    if (
        not required_files.issubset(files)
        or files - required_files - optional_files
        or directories != expected_directories
    ):
        raise CaptureError("paired prefix root inventory changed")


def _plan(root: Path, repository: Path) -> tuple[dict[str, Any], bytes]:
    raw = durability.read_regular_bytes(root / "pair-plan.json", "paired prefix plan")
    value = decode_strict(raw)
    if type(value) is not dict or raw != canonical_bytes(value):
        raise CaptureError("paired prefix plan is not canonical JSON")
    return (
        validate_pair_plan(value, repository=repository, verify_local=True),
        raw,
    )


def _lane_records(
    root: Path,
    lane: str,
    lane_plan: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    lane_root = root / lane
    inventory = FileInventory(lane_root)
    if inventory.root_file("plan.json") != canonical_bytes(lane_plan):
        raise CaptureError(f"paired prefix {lane} plan bytes changed")
    journal_raw = inventory.root_file("journal.ndjson")
    journal = durability.read_journal_regular(
        lane_root / "journal.ndjson", f"paired prefix {lane} journal"
    )
    if journal_raw != b"".join(canonical_bytes(record) for record in journal):
        raise CaptureError(f"paired prefix {lane} journal bytes changed")
    if not journal:
        raise CaptureError(f"paired prefix {lane} journal is empty")
    header = exact_object(
        journal[0],
        {
            "schema",
            "session_id",
            "plan_sha256",
            "planned_attempts",
            "content_sha256",
        },
        f"paired prefix {lane} journal header",
    )
    if (
        header["schema"] != JOURNAL_HEADER_SCHEMA
        or header["session_id"] != lane_plan["session_id"]
        or header["plan_sha256"] != lane_plan["content_sha256"]
        or header["planned_attempts"] != PLAN_ATTEMPTS
        or len(journal) - 1 > PLAN_ATTEMPTS
    ):
        raise CaptureError(f"paired prefix {lane} journal header changed")
    records = journal[1:]
    for attempt, record in zip(lane_plan["attempts"], records, strict=False):
        _validate_record(record, plan=lane_plan, attempt=attempt, inventory=inventory)
    manifest = lane_root / "bundle.json"
    if os.path.lexists(manifest):
        raw = inventory.root_file("bundle.json")
        value = decode_strict(raw)
        if type(value) is not dict or raw != canonical_bytes(value):
            raise CaptureError(f"paired prefix {lane} manifest is not canonical")
    inventory.finish()
    return records, journal


def _trim_plan(
    plan: dict[str, Any], lane_counts: Mapping[str, int]
) -> dict[str, Any]:
    result = copy.deepcopy(plan)
    for lane in PAIR_LANE_ORDER:
        result["lanes"][lane]["attempts"] = result["lanes"][lane]["attempts"][
            : lane_counts[lane]
        ]
    return result


def _blocks(lane_plan: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    attempts = lane_plan["attempts"]
    start = 0
    while start < len(attempts):
        first = attempts[start]
        key = (first["workload_id"], first["comparison_id"])
        end = start + 1
        while end < len(attempts):
            current = attempts[end]
            if (current["workload_id"], current["comparison_id"]) != key:
                break
            end += 1
        if end - start != ATTEMPTS_PER_COMPARISON:
            raise CaptureError("paired plan comparison block geometry changed")
        result.append(
            {
                "workload_id": key[0],
                "comparison_id": key[1],
                "start": start,
                "end": end,
            }
        )
        start = end
    return result


def select_complete_blocks(
    plan: dict[str, Any], lane_counts: Mapping[str, int]
) -> dict[str, Any]:
    """Select calibration plus whole three-comparison workload matrices."""

    if set(lane_counts) != set(PAIR_LANE_ORDER):
        raise CaptureError("paired prefix lane-count authority changed")
    for lane, count in lane_counts.items():
        if type(count) is not int or not 0 <= count <= PLAN_ATTEMPTS:
            raise CaptureError(f"paired prefix {lane} count is invalid")
    reference = _blocks(plan["lanes"][PAIR_LANE_ORDER[0]])
    for lane in PAIR_LANE_ORDER[1:]:
        if _blocks(plan["lanes"][lane]) != reference:
            raise CaptureError("paired lanes disagree on comparison blocks")
    common = min(lane_counts.values())
    complete = [block for block in reference if block["end"] <= common]
    complete_keys = {
        (block["workload_id"], block["comparison_id"]): block for block in complete
    }
    calibration = complete_keys.get(("multi_shard_addi", "aa-calibration"))
    if calibration is None or calibration["start"] != 0:
        raise CaptureError("paired prefix lacks its complete A/A calibration")
    included: list[str] = []
    statistical_end = calibration["end"]
    for workload in WORKLOAD_IDS:
        workload_blocks = [
            complete_keys.get((workload, comparison))
            for comparison in SCALING_COMPARISONS
        ]
        if any(block is None for block in workload_blocks):
            break
        blocks = [block for block in workload_blocks if block is not None]
        if blocks[0]["start"] != statistical_end:
            raise CaptureError("paired prefix complete blocks are not contiguous")
        statistical_end = blocks[-1]["end"]
        included.append(workload)
    if len(included) < 2:
        raise CaptureError("paired prefix needs at least two complete workload matrices")
    retained = sum(lane_counts.values())
    statistical = statistical_end * len(PAIR_LANE_ORDER)
    return {
        "comparison_attempts": ATTEMPTS_PER_COMPARISON,
        "complete_comparison_blocks_per_lane": statistical_end
        // ATTEMPTS_PER_COMPARISON,
        "statistical_attempts_per_lane": statistical_end,
        "statistical_attempts": statistical,
        "included_workloads": included,
        "omitted_workloads": [item for item in WORKLOAD_IDS if item not in included],
        "retained_but_unscored_attempts": retained - statistical,
        "unscored_planned_attempts": PAIR_ATTEMPTS - statistical,
        "not_executed_attempts": PAIR_ATTEMPTS - retained,
    }


def _publication_cut(records: list[dict[str, Any]], attempts: int) -> int:
    if attempts == 0:
        return 1
    committed = 0
    for index, record in enumerate(records[1:], start=1):
        if record.get("phase") == "committed":
            committed += 1
            if committed == attempts:
                return index + 1
    raise CaptureError("attempt-publication journal omits the bound prefix")


def _identity(
    records: list[dict[str, Any]], count: int, relative: str
) -> dict[str, Any]:
    if type(count) is not int or not 0 < count <= len(records):
        raise CaptureError(f"paired prefix {relative} record bound is invalid")
    return durability.journal_identity(records[:count], relative)


def _expected_count(expected: Any, name: str, maximum: int) -> int:
    if type(expected) is not dict:
        raise CaptureError("paired prefix expected authority is not an object")
    value = expected.get("journal_prefixes", {}).get(name, {}).get("records")
    if type(value) is not int or not 0 < value <= maximum:
        raise CaptureError(f"paired prefix {name} identity is invalid")
    return value


def validate_pair_prefix(
    repository: Path,
    bundle_path: Path,
    *,
    expected_authority: dict[str, Any] | None = None,
    include_snapshot: bool = False,
) -> dict[str, Any]:
    repository = repository.resolve()
    root = bundle_path.absolute()
    durability.require_regular_directory(root, "paired prefix bundle")
    _root_entries(root)
    plan, plan_raw = _plan(root, repository)
    lane_records: dict[str, list[dict[str, Any]]] = {}
    lane_journals: dict[str, list[dict[str, Any]]] = {}
    for lane in PAIR_LANE_ORDER:
        lane_records[lane], lane_journals[lane] = _lane_records(
            root, lane, plan["lanes"][lane]
        )

    current_progress = durability.completed_interleaving(plan, lane_records)
    progress = durability.read_journal_regular(
        root / "pair-journal.ndjson", "paired prefix progress journal"
    )
    if len(progress) != len(current_progress) + 1 or progress[1:] != current_progress:
        raise CaptureError("paired prefix progress journal is not lane-derived")
    current_publication, _ = publication.read_publication_journal(
        root / publication.PUBLICATION_JOURNAL_NAME,
        plan=plan,
        lane_records=lane_records,
        require_complete=False,
    )
    if current_publication["pending"] is not None:
        raise CaptureError("paired prefix cannot snapshot a pending attempt")
    current_attempts = len(current_progress)
    if current_publication["committed_attempts"] != current_attempts:
        raise CaptureError("paired prefix publication count changed")
    publication_records = durability.read_journal_regular(
        root / publication.PUBLICATION_JOURNAL_NAME,
        "paired prefix publication journal",
    )
    boundary_records = durability.read_journal_regular(
        root / durability.BOUNDARY_JOURNAL_NAME,
        "paired prefix boundary journal",
    )

    if expected_authority is None:
        bound_counts = {lane: len(lane_records[lane]) for lane in PAIR_LANE_ORDER}
        bound_attempts = current_attempts
        publication_count = _publication_cut(publication_records, bound_attempts)
        boundary_count = len(boundary_records)
    else:
        if (
            expected_authority.get("schema") != PREFIX_AUTHORITY_SCHEMA
            or expected_authority.get("plan_sha256") != plan["content_sha256"]
        ):
            raise CaptureError("paired prefix expected authority changed")
        bound_counts = expected_authority.get("retained_attempts_by_lane")
        if type(bound_counts) is not dict or set(bound_counts) != set(PAIR_LANE_ORDER):
            raise CaptureError("paired prefix expected lane counts changed")
        for lane in PAIR_LANE_ORDER:
            if (
                type(bound_counts[lane]) is not int
                or not 0 <= bound_counts[lane] <= len(lane_records[lane])
            ):
                raise CaptureError("paired prefix expected lane count exceeds evidence")
        bound_attempts = sum(bound_counts.values())
        publication_count = _expected_count(
            expected_authority, publication.PUBLICATION_JOURNAL_NAME, len(publication_records)
        )
        boundary_count = _expected_count(
            expected_authority, durability.BOUNDARY_JOURNAL_NAME, len(boundary_records)
        )

    bound_records = {
        lane: lane_records[lane][: bound_counts[lane]] for lane in PAIR_LANE_ORDER
    }
    bound_progress = durability.completed_interleaving(plan, bound_records)
    if len(bound_progress) != bound_attempts or progress[1 : bound_attempts + 1] != bound_progress:
        raise CaptureError("paired prefix bound progress changed")
    publication_prefix = publication_records[:publication_count]
    publication_summary = publication.validate_publication_records(
        publication_prefix,
        plan=plan,
        lane_records=bound_records,
        require_complete=False,
    )
    if (
        publication_summary["committed_attempts"] != bound_attempts
        or publication_summary["pending"] is not None
    ):
        raise CaptureError("paired prefix bound publication is incomplete")
    boundary_prefix = boundary_records[:boundary_count]
    boundary_summary = durability.validate_boundary_records(
        boundary_prefix,
        plan=plan,
        completed_attempts=bound_attempts,
        require_complete=False,
        recovery_authorizations=publication_summary["authorizations"],
    )
    selection = select_complete_blocks(plan, bound_counts)
    retained_plan = _trim_plan(plan, bound_counts)
    statistical_counts = {
        lane: selection["statistical_attempts_per_lane"] for lane in PAIR_LANE_ORDER
    }
    statistical_plan = _trim_plan(plan, statistical_counts)
    statistical_records = {
        lane: bound_records[lane][: statistical_counts[lane]] for lane in PAIR_LANE_ORDER
    }
    retained_work = exact_work_cells.validate_cell_authority(
        retained_plan, bound_records, PAIR_LANE_ORDER
    )
    statistical_work = exact_work_cells.validate_cell_authority(
        statistical_plan, statistical_records, PAIR_LANE_ORDER
    )
    retained_identities = pair_identity.validate_pair_identity_authority(
        retained_plan, bound_records, PAIR_LANE_ORDER
    )
    statistical_identities = pair_identity.validate_pair_identity_authority(
        statistical_plan, statistical_records, PAIR_LANE_ORDER
    )
    verified = sum(
        record["status"] == "verified"
        for lane in PAIR_LANE_ORDER
        for record in bound_records[lane]
    )
    failed = bound_attempts - verified
    independent = sum(
        record["status"] == "verified"
        and record["independent_verification"]["status"] == "verified"
        for lane in PAIR_LANE_ORDER
        for record in bound_records[lane]
    )
    journal_prefixes = {
        "pair-plan.json": {
            "path": "pair-plan.json",
            "bytes": len(plan_raw),
            "sha256": sha256_bytes(plan_raw),
            "records": 1,
        },
        **{
            f"{lane}/journal.ndjson": _identity(
                lane_journals[lane], bound_counts[lane] + 1, f"{lane}/journal.ndjson"
            )
            for lane in PAIR_LANE_ORDER
        },
        "pair-journal.ndjson": _identity(
            progress, bound_attempts + 1, "pair-journal.ndjson"
        ),
        publication.PUBLICATION_JOURNAL_NAME: _identity(
            publication_records,
            publication_count,
            publication.PUBLICATION_JOURNAL_NAME,
        ),
        durability.BOUNDARY_JOURNAL_NAME: _identity(
            boundary_records, boundary_count, durability.BOUNDARY_JOURNAL_NAME
        ),
    }
    authority: dict[str, Any] = {
        "schema": PREFIX_AUTHORITY_SCHEMA,
        "schema_version": 1,
        "classification": "append-compatible-complete-comparison-prefix",
        "plan_sha256": plan["content_sha256"],
        "planned_attempts": PAIR_ATTEMPTS,
        "retained_attempts": bound_attempts,
        "retained_attempts_by_lane": dict(bound_counts),
        **selection,
        "journal_prefixes": journal_prefixes,
        "capture_state": {
            "attempt_pending": False,
            "boundary_open": boundary_summary["open_start"] is not None,
            "boundary_closed_prefix": boundary_summary["closed_prefix"],
            "capture_resumable": True,
        },
    }
    authority["content_sha256"] = content_digest(authority)
    if expected_authority is not None and authority != expected_authority:
        raise CaptureError("paired prefix no longer matches its bound authority")
    result: dict[str, Any] = {
        "schema": PREFIX_VALIDATION_SCHEMA,
        "schema_version": 1,
        "status": "VALID_COMPLETE_BLOCK_PREFIX" if not failed else "VALID_PREFIX_WITH_FAILURES",
        "prefix_authority": authority,
        "verified_attempts": verified,
        "failed_attempts": failed,
        "independent_verifier_attempts": independent,
        "all_retained_raw_attempts_valid": True,
        "all_retained_attempts_complete_exact_work": retained_work[
            "every_attempt_complete_exact_work"
        ],
        "all_statistical_attempts_complete_exact_work": statistical_work[
            "every_attempt_complete_exact_work"
        ],
        "retained_exact_work_authority": retained_work,
        "statistical_exact_work_authority": statistical_work,
        "retained_semantic_identity_workloads": sorted(retained_identities),
        "statistical_semantic_identity_workloads": sorted(statistical_identities),
        "recovery_disclosure": publication_summary["recovery_disclosure"],
        "normative_full_matrix": False,
        "m7_promotion_receipt": False,
    }
    result["content_sha256"] = content_digest(result)
    if include_snapshot:
        result["_snapshot"] = {
            "plan": statistical_plan,
            "lane_records": statistical_records,
        }
    return result
