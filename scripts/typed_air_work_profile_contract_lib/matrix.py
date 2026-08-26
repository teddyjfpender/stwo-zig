"""Canonical P-003 family matrix and typed-site inventory validation.

This module is deliberately dependency-neutral.  P-003 blocker production and
R-006 planning both consume it, so neither evidence command has to import the
other command boundary or inherit its runtime policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


MATRIX_SCHEMA = "stwo.typed-air.p003-work-profile-closure-matrix.v1"
SCHEMA_VERSION = 1
MATRIX_PATH = "design/typed-air/artifacts/p003-work-profile-closure-v1/matrix-v1.json"
COUNTER_PARTITION = (
    "witness_materialization_and_native_prover_included__"
    "guest_execution_serialization_and_native_verification_excluded__"
    "blake2s_shell_included_as_zero_v1"
)
INVENTORY_PATH = "src/prover_api/work_profile_inventory.zig"
INVENTORY_SCHEMA_VERSION = 9

FAMILY_IDS = (
    "cold_m31_twiddle_construction",
    "column_interpolation",
    "remaining_forward_circle_fft",
    "secure_composition_interpolation",
    "main_witness_field_work",
    "sparse_memory_and_guest_poseidon_witness",
    "relation_challenges_and_interaction_traces",
    "air_composition_on_domain",
    "oods_point_masks_and_point_composition",
    "sampled_committed_column_evaluation",
    "quotient_sample_preparation",
    "quotient_row_execution",
    "fri_circle_to_line_fold",
    "fri_line_folds",
    "fri_last_layer_interpolation",
    "transcript_pcs_merkle_pow_decommitment_and_encoding",
)

SITE_IDS = (
    "column_passthrough_fft",
    "column_interpolate_only_fft",
    "column_interpolate_for_extension_fft",
    "column_extension_fft",
    "column_combined_fft",
    "polynomial_commit_forward_fft",
    "secure_composition_interpolation_fft",
    "commitment_tree_merkle",
    "streaming_commitment_merkle",
    "fri_protocol",
    "main_witness_field",
    "cold_twiddle_construction",
    "sampled_value_coefficient_evaluation",
    "sampled_value_barycentric_evaluation",
    "oods_seed_to_point",
    "oods_mask_points",
    "oods_constraint_evaluation",
    "sparse_memory_and_guest_poseidon_witness",
    "relation_challenges_and_interaction_traces",
    "quotient_sample_preparation",
    "quotient_row_execution",
    "air_composition_on_domain",
    "pcs_transcript_shell",
)

STATUSES = ("complete", "partial", "absent")
STATUS_RANK = {status: index for index, status in enumerate(STATUSES)}
MATRIX_FIELDS = {
    "counter_partition",
    "families",
    "inventory",
    "schema",
    "schema_version",
}
FAMILY_FIELDS = {"authority_paths", "cpu", "id", "metal", "typed_sites"}
LANE_FIELDS = {"blockers", "status"}
INVENTORY_FIELDS = {"path", "schema_version", "site_count"}


class MatrixContractError(ValueError):
    """The source-level whole-prover work authority is malformed."""


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MatrixContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise MatrixContractError(f"non-finite JSON number is forbidden: {value}")


def _load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
        if not raw:
            raise MatrixContractError("P-003 closure matrix is empty")
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MatrixContractError(
            f"cannot read P-003 closure matrix {path}: {error}"
        ) from error


def _exact_object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise MatrixContractError(f"{label} must be an object")
    actual = set(value)
    if actual != fields:
        raise MatrixContractError(
            f"{label} fields drifted; missing={sorted(fields - actual)}, "
            f"unknown={sorted(actual - fields)}"
        )
    return value


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise MatrixContractError("matrix is not canonical-JSON encodable") from error


def _text_list(value: Any, label: str, *, allow_empty: bool = True) -> list[str]:
    if type(value) is not list or (not allow_empty and not value):
        qualifier = "nonempty " if not allow_empty else ""
        raise MatrixContractError(f"{label} must be a {qualifier}list")
    if any(type(item) is not str or not item for item in value):
        raise MatrixContractError(f"{label} entries must be nonempty strings")
    if len(value) != len(set(value)):
        raise MatrixContractError(f"{label} contains duplicates")
    return value


def _repository_path(repository: Path, value: str, label: str) -> Path:
    if "\\" in value:
        raise MatrixContractError(f"{label} must be a POSIX repository-relative path")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or value != relative.as_posix()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise MatrixContractError(f"{label} must be a normalized repository-relative path")
    root = repository.resolve()
    path = root.joinpath(*relative.parts)
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise MatrixContractError(f"{label} escapes the repository") from error
    if path.is_symlink() or not resolved.is_file():
        raise MatrixContractError(
            f"{label} is not a regular non-symlink file: {value}"
        )
    return resolved


def _sha256_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
    except OSError as error:
        raise MatrixContractError(f"cannot hash typed-site inventory: {path}") from error
    return size, digest.hexdigest()


def inventory_authority(path: Path) -> dict[str, Any]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise MatrixContractError(f"cannot read typed-site inventory: {error}") from error
    version_match = re.search(
        r"(?m)^pub const SCHEMA_VERSION: u16 = ([0-9]+);$", source
    )
    enum_match = re.search(
        r"pub const Site = enum\(u8\) \{(?P<body>.*?)\n\};",
        source,
        re.DOTALL,
    )
    specs_match = re.search(
        r"pub const SITES = \[_\]Spec\{(?P<body>.*?)\n\};",
        source,
        re.DOTALL,
    )
    if version_match is None or enum_match is None or specs_match is None:
        raise MatrixContractError("typed-site inventory syntax authority changed")
    enum_entries = re.findall(
        r"(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([0-9]+),\s*$",
        enum_match.group("body"),
    )
    names = tuple(name for name, _ in enum_entries)
    values = tuple(int(value) for _, value in enum_entries)
    spec_names = tuple(
        re.findall(
            r"\.site\s*=\s*\.([A-Za-z_][A-Za-z0-9_]*)",
            specs_match.group("body"),
        )
    )
    if (
        int(version_match.group(1)) != INVENTORY_SCHEMA_VERSION
        or names != SITE_IDS
        or values != tuple(range(len(SITE_IDS)))
        or spec_names != SITE_IDS
    ):
        raise MatrixContractError(
            "typed-site inventory schema, order, or total mapping drifted"
        )
    size, digest = _sha256_file(path)
    return {
        "path": INVENTORY_PATH,
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "site_count": len(SITE_IDS),
        "source_bytes": size,
        "source_sha256": digest,
    }


def _lane(value: Any, label: str) -> dict[str, Any]:
    lane = _exact_object(value, LANE_FIELDS, label)
    status = lane["status"]
    if status not in STATUSES:
        raise MatrixContractError(f"{label} status is unsupported")
    blockers = _text_list(lane["blockers"], f"{label} blockers")
    if (status == "complete") != (not blockers):
        raise MatrixContractError(
            f"{label} must have no blockers exactly when status is complete"
        )
    return {"status": status, "blockers": blockers}


def _status_counts(statuses: Sequence[str]) -> dict[str, int]:
    return {status: statuses.count(status) for status in STATUSES}


def validate_matrix(repository: Path, path: Path | None = None) -> dict[str, Any]:
    """Validate and normalize the complete P-003 source authority."""

    root = repository.resolve()
    matrix_path = (root / MATRIX_PATH) if path is None else path.resolve()
    raw = _load_json(matrix_path)
    matrix = _exact_object(raw, MATRIX_FIELDS, "P-003 closure matrix")
    if (
        matrix["schema"] != MATRIX_SCHEMA
        or matrix["schema_version"] != SCHEMA_VERSION
        or matrix["counter_partition"] != COUNTER_PARTITION
    ):
        raise MatrixContractError("P-003 closure matrix authority changed")
    inventory = _exact_object(matrix["inventory"], INVENTORY_FIELDS, "matrix inventory")
    if inventory != {
        "path": INVENTORY_PATH,
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "site_count": len(SITE_IDS),
    }:
        raise MatrixContractError("matrix typed-site inventory binding changed")
    inventory_report = inventory_authority(
        _repository_path(root, inventory["path"], "matrix inventory path")
    )

    families = matrix["families"]
    if type(families) is not list or len(families) != len(FAMILY_IDS):
        raise MatrixContractError("P-003 matrix must contain exactly sixteen families")
    typed_site_union: set[str] = set()
    normalized_families: list[dict[str, Any]] = []
    for index, raw_family in enumerate(families):
        family = _exact_object(raw_family, FAMILY_FIELDS, f"family {index}")
        family_id = family["id"]
        if family_id != FAMILY_IDS[index]:
            raise MatrixContractError("P-003 family order or identity changed")
        paths = _text_list(
            family["authority_paths"],
            f"family {family_id} authority paths",
            allow_empty=False,
        )
        if paths != sorted(paths):
            raise MatrixContractError(
                f"family {family_id} authority paths are not sorted"
            )
        for authority_path in paths:
            _repository_path(root, authority_path, f"family {family_id} authority path")
        typed_sites = _text_list(
            family["typed_sites"], f"family {family_id} typed sites"
        )
        unknown_sites = set(typed_sites) - set(SITE_IDS)
        if unknown_sites:
            raise MatrixContractError(
                f"family {family_id} names unknown typed sites: {sorted(unknown_sites)}"
            )
        typed_site_union.update(typed_sites)
        cpu = _lane(family["cpu"], f"family {family_id} CPU lane")
        metal = _lane(family["metal"], f"family {family_id} Metal lane")
        joint = max((cpu["status"], metal["status"]), key=STATUS_RANK.__getitem__)
        normalized_families.append(
            {
                "id": family_id,
                "cpu": cpu["status"],
                "metal": metal["status"],
                "joint": joint,
            }
        )
    if typed_site_union != set(SITE_IDS):
        raise MatrixContractError(
            "P-003 family matrix does not cover the full typed-site inventory"
        )

    cpu_statuses = [family["cpu"] for family in normalized_families]
    metal_statuses = [family["metal"] for family in normalized_families]
    joint_statuses = [family["joint"] for family in normalized_families]
    return {
        "matrix": matrix,
        "matrix_path": matrix_path,
        "matrix_sha256": hashlib.sha256(_canonical_bytes(matrix)).hexdigest(),
        "inventory": inventory_report,
        "coverage": {
            "cpu": _status_counts(cpu_statuses),
            "metal": _status_counts(metal_statuses),
            "joint": _status_counts(joint_statuses),
            "family_count": len(FAMILY_IDS),
            "families": normalized_families,
            "whole_prover_exact": all(
                status == "complete" for status in joint_statuses
            ),
        },
    }
