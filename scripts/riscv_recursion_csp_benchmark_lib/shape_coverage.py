"""Proof-independent fixed-profile coverage for canonical CSP workloads.

Coverage is produced by the ReleaseFast Zig inspector from the exact
production commitment-witness and statement-geometry builders.  No dimension
is inferred from cycles, proof size, or a timing cohort.
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from scripts.riscv_csp_benchmark_lib.contract import (
    MANIFEST,
    BenchmarkError,
    validate_manifest,
)

from .codec import EvidenceError, load_json, seal_document, verify_document_seal
from .contract import exact_object, expect_commit, expect_digest, expect_positive_int


INSPECTION_SCHEMA = "stwo.riscv.recursion-shape-inspection.v2"
AUDIT_SCHEMA = "stwo.riscv.recursion-csp-shape-audit.v2"
PROFILE_REGISTRY_SCHEMA = "stwo.riscv.recursion-csp-profile-registry.v1"
DEFAULT_AUDIT = MANIFEST.parent / "recursion-shape-audit-v2.json"

AUDITED_SOURCES = (
    "src/tools/riscv/recursive_csp_shape_inspector/main.zig",
    "src/tools/riscv/recursive_csp_producer/profile_registry.zig",
    "src/frontends/riscv/prover/statement_shape_inspection.zig",
    "src/frontends/riscv/prover/commitment_witness.zig",
    "src/frontends/riscv/prover/statement_geometry.zig",
    "src/frontends/riscv/prover/statement_validation.zig",
    "src/frontends/riscv/air/statement.zig",
    "src/frontends/riscv/recursion/segment_profile.zig",
)

INSPECTION_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "classification",
        "source",
        "producer",
        "method",
        "facts",
        "profile_registry",
        "selected_profile",
    }
)
SOURCE_KEYS = frozenset(
    {
        "elf_path",
        "elf_sha256",
        "input_path",
        "input_sha256",
        "observed_output_hex",
        "execution_cycles",
    }
)
PRODUCER_KEYS = frozenset(
    {
        "name",
        "optimization_mode",
        "implementation_commit",
        "implementation_dirty",
        "product_identity_sha256",
    }
)
METHOD_KEYS = frozenset(
    {
        "statement_authority",
        "proof_constructed",
        "trace_columns_constructed",
        "dimensions_inferred_from_cycles",
        "max_steps",
    }
)
FACT_KEYS = frozenset(
    {
        "component_count",
        "infrastructure_count",
        "preprocessed_column_count",
        "main_column_count",
        "interaction_column_count",
        "maximum_column_log_degree",
        "expected_preprocessed_column_count",
        "expected_main_column_count",
        "expected_interaction_column_count",
        "expected_maximum_column_log_degree",
        "admission",
        "fixed_profile_admissible",
    }
)
AUDIT_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "classification",
        "manifest",
        "inspector",
        "method",
        "fixed_profile",
        "profile_registry",
        "profile_matrix",
        "source_evidence",
        "coverage",
        "cases",
        "limitations",
        "canonical_digest",
    }
)
AUDIT_CASE_KEYS = frozenset(
    {
        "target",
        "input_size",
        "guest_sha256",
        "input_sha256",
        "expected_output_digest",
        "expected_cycles",
        "facts",
        "selected_profile",
        "status",
    }
)

REGISTRY_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "registry_sha256",
        "profile_count",
        "canonical_case_count",
    }
)
SELECTED_PROFILE_KEYS = frozenset(
    {
        "profile_id",
        "profile_shape_sha256",
        "canonical_case_count",
        "implementation_status",
        "outer_executable",
    }
)
PROFILE_MATRIX_KEYS = frozenset(
    {
        "profile_id",
        "profile_shape_sha256",
        "shape",
        "expected_canonical_case_count",
        "observed_canonical_case_count",
        "implementation_status",
        "outer_executable",
        "workloads",
    }
)
PROFILE_SHAPE_FIELD_ORDER = (
    "component_count",
    "infrastructure_count",
    "preprocessed_column_count",
    "main_column_count",
    "interaction_column_count",
    "maximum_column_log_degree",
)
PROFILE_SHAPE_KEYS = frozenset(PROFILE_SHAPE_FIELD_ORDER)

# Independent decoder for the Zig registry's stable byte-level seals.  Keeping
# this small verifier here means a self-consistent but forged inspector report
# cannot relabel one exact shape as another.
PROFILE_SPECS: tuple[tuple[str, int, tuple[int, ...], int], ...] = (
    ("hash_compact", 1, (12, 11, 54, 916, 444, 20), 8),
    ("sha256_2048", 2, (13, 11, 56, 951, 480, 20), 1),
    ("keccak_2048", 3, (14, 11, 58, 999, 512, 20), 1),
    ("poseidon2_2", 4, (13, 11, 56, 953, 468, 20), 1),
    ("poseidon2_4", 5, (14, 11, 58, 988, 504, 20), 1),
    ("poseidon2_8", 6, (15, 11, 60, 1023, 540, 20), 1),
    ("poseidon2_12", 7, (18, 11, 66, 1144, 644, 20), 1),
    ("poseidon2_16", 8, (21, 11, 72, 1271, 740, 20), 1),
    ("ecdsa_secp256k1_32", 9, (94, 11, 218, 4444, 3624, 20), 1),
)
PROFILE_BY_ID = {spec[0]: spec for spec in PROFILE_SPECS}


def _shape_object(values: tuple[int, ...]) -> dict[str, int]:
    return dict(zip(PROFILE_SHAPE_FIELD_ORDER, values, strict=True))


def _profile_shape_sha256(profile_id: str) -> str:
    _, numeric_id, values, _ = PROFILE_BY_ID[profile_id]
    preimage = bytearray(b"stwo-zig/riscv/recursive-csp-profile-shape/v1\x00")
    preimage += struct.pack("<HHH", 1, numeric_id, len(profile_id))
    preimage += profile_id.encode("ascii")
    preimage += struct.pack("<6I", *values)
    return hashlib.sha256(preimage).hexdigest()


def _registry_sha256() -> str:
    preimage = bytearray(b"stwo-zig/riscv/recursive-csp-profile-registry/v1\x00")
    preimage += struct.pack("<HH", 1, len(PROFILE_SPECS))
    for profile_id, _, _, case_count in PROFILE_SPECS:
        preimage += bytes.fromhex(_profile_shape_sha256(profile_id))
        preimage += struct.pack("<BH", 0, case_count)
    return hashlib.sha256(preimage).hexdigest()


EXPECTED_REGISTRY = {
    "schema": PROFILE_REGISTRY_SCHEMA,
    "schema_version": 1,
    "registry_sha256": _registry_sha256(),
    "profile_count": len(PROFILE_SPECS),
    "canonical_case_count": sum(spec[3] for spec in PROFILE_SPECS),
}


def _validate_selected_profile(
    value: Any, facts: dict[str, Any], *, label: str
) -> dict[str, Any]:
    selected = exact_object(value, SELECTED_PROFILE_KEYS, label)
    profile_id = selected["profile_id"]
    if profile_id not in PROFILE_BY_ID:
        raise EvidenceError(f"{label} names an unknown recursion profile")
    _, _, expected_shape_values, expected_case_count = PROFILE_BY_ID[profile_id]
    observed_shape = {key: facts[key] for key in PROFILE_SHAPE_FIELD_ORDER}
    if observed_shape != _shape_object(expected_shape_values):
        raise EvidenceError(f"{label} does not match exact statement facts")
    expected = {
        "profile_id": profile_id,
        "profile_shape_sha256": _profile_shape_sha256(profile_id),
        "canonical_case_count": expected_case_count,
        "implementation_status": "catalogued_outer_not_wired",
        "outer_executable": False,
    }
    if selected != expected:
        raise EvidenceError(f"{label} identity drifted")
    return selected


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise EvidenceError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def _source_evidence(repo_root: Path) -> list[dict[str, str]]:
    evidence = []
    for relative in AUDITED_SOURCES:
        path = repo_root / relative
        if not path.is_file():
            raise EvidenceError(f"recursion shape authority source is missing: {relative}")
        evidence.append({"path": relative, "sha256": _sha256_file(path)})
    return evidence


def _validate_inspection(
    inspection: dict[str, Any],
    *,
    case: Any,
    repo_root: Path,
    producer_identity: dict[str, Any] | None,
) -> dict[str, Any]:
    exact_object(inspection, INSPECTION_KEYS, "shape inspection")
    if (
        inspection["schema"] != INSPECTION_SCHEMA
        or inspection["schema_version"] != 2
        or inspection["classification"]
        != "proof_independent_shape_evidence_not_performance_evidence"
    ):
        raise EvidenceError("shape inspection schema/classification drifted")
    source = exact_object(inspection["source"], SOURCE_KEYS, "shape inspection.source")
    expected_source = {
        "elf_path": case.guest_path.relative_to(repo_root).as_posix(),
        "elf_sha256": case.guest_sha256,
        "input_path": case.input_path.relative_to(repo_root).as_posix(),
        "input_sha256": case.input_sha256,
        "observed_output_hex": case.expected_digest,
        "execution_cycles": case.expected_cycles,
    }
    if source != expected_source:
        raise EvidenceError("shape inspection differs from the canonical workload")
    producer = exact_object(
        inspection["producer"], PRODUCER_KEYS, "shape inspection.producer"
    )
    if (
        producer["name"] != "stwo-zig-riscv-recursion-shape-inspector"
        or producer["optimization_mode"] != "ReleaseFast"
        or type(producer["implementation_dirty"]) is not bool
    ):
        raise EvidenceError("shape inspector product identity drifted")
    expect_commit(producer["implementation_commit"], "shape inspector commit")
    expect_digest(producer["product_identity_sha256"], "shape inspector identity")
    if producer_identity is not None and producer != producer_identity:
        raise EvidenceError("shape audit mixed inspector products")
    method = exact_object(inspection["method"], METHOD_KEYS, "shape inspection.method")
    if method != {
        "statement_authority": "production_commitment_witness_and_statement_geometry",
        "proof_constructed": False,
        "trace_columns_constructed": False,
        "dimensions_inferred_from_cycles": False,
        "max_steps": 10_000_000,
    }:
        raise EvidenceError("shape inspection method drifted")
    facts = exact_object(inspection["facts"], FACT_KEYS, "shape inspection.facts")
    for key in FACT_KEYS - {"admission", "fixed_profile_admissible"}:
        expect_positive_int(facts[key], f"shape inspection.facts.{key}", allow_zero=True)
    counts_match = (
        facts["preprocessed_column_count"]
        == facts["expected_preprocessed_column_count"]
        and facts["main_column_count"] == facts["expected_main_column_count"]
        and facts["interaction_column_count"]
        == facts["expected_interaction_column_count"]
    )
    log_matches = (
        facts["maximum_column_log_degree"]
        == facts["expected_maximum_column_log_degree"]
    )
    admitted = counts_match and log_matches
    expected_admission = (
        "admitted"
        if admitted
        else "column_counts_and_log_degree_mismatch"
        if not counts_match and not log_matches
        else "column_counts_mismatch"
        if not counts_match
        else "column_log_degree_mismatch"
    )
    if (
        facts["admission"] != expected_admission
        or facts["fixed_profile_admissible"] is not admitted
    ):
        raise EvidenceError("shape inspection admission contradicts its exact facts")
    registry = exact_object(
        inspection["profile_registry"], REGISTRY_KEYS, "shape inspection.profile_registry"
    )
    if registry != EXPECTED_REGISTRY:
        raise EvidenceError("shape inspection profile-registry seal drifted")
    selected = _validate_selected_profile(
        inspection["selected_profile"],
        facts,
        label="shape inspection.selected_profile",
    )
    return {
        "producer": producer,
        "method": method,
        "facts": facts,
        "profile_registry": registry,
        "selected_profile": selected,
    }


def collect_shape_audit(
    *,
    repo_root: Path,
    manifest_path: Path = MANIFEST,
    inspector: Path,
    timeout_seconds: int = 120,
) -> dict[str, Any]:
    """Inspect every canonical case without constructing a proof or timing cohort."""

    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise EvidenceError("shape-inspection timeout must be positive")
    try:
        _, cases, _ = validate_manifest(manifest_path.resolve())
    except (BenchmarkError, OSError, ValueError) as error:
        raise EvidenceError(f"canonical CSP manifest is invalid: {error}") from error
    inspector = inspector.resolve(strict=True)
    if not inspector.is_file() or not os.access(inspector, os.X_OK):
        raise EvidenceError("recursion shape inspector is not executable")

    producer_identity: dict[str, Any] | None = None
    method: dict[str, Any] | None = None
    registry: dict[str, Any] | None = None
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="stwo-recursion-shape-audit-") as temporary:
        output_root = Path(temporary)
        for ordinal, case in enumerate(cases):
            output = output_root / f"{ordinal:03d}.json"
            completed = subprocess.run(
                [
                    os.fspath(inspector),
                    "--elf",
                    case.guest_path.relative_to(repo_root).as_posix(),
                    "--input",
                    case.input_path.relative_to(repo_root).as_posix(),
                    "--report-out",
                    os.fspath(output),
                ],
                cwd=repo_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
            if completed.returncode != 0 or completed.stdout or not output.is_file():
                raise EvidenceError(
                    f"shape inspector failed for {case.target}/{case.input_size}: "
                    f"return={completed.returncode} stdout_bytes={len(completed.stdout)} "
                    f"stderr_sha256={hashlib.sha256(completed.stderr).hexdigest()}"
                )
            inspection, _ = load_json(output)
            validated = _validate_inspection(
                inspection,
                case=case,
                repo_root=repo_root,
                producer_identity=producer_identity,
            )
            producer_identity = validated["producer"]
            if method is not None and validated["method"] != method:
                raise EvidenceError("shape audit mixed inspection methods")
            method = validated["method"]
            if registry is not None and validated["profile_registry"] != registry:
                raise EvidenceError("shape audit mixed profile registries")
            registry = validated["profile_registry"]
            facts = validated["facts"]
            selected = validated["selected_profile"]
            rows.append(
                {
                    "target": case.target,
                    "input_size": case.input_size,
                    "guest_sha256": case.guest_sha256,
                    "input_sha256": case.input_sha256,
                    "expected_output_digest": case.expected_digest,
                    "expected_cycles": case.expected_cycles,
                    "facts": facts,
                    "selected_profile": selected,
                    "status": "outer_executable"
                    if selected["outer_executable"]
                    else "profile_catalogued_outer_unavailable",
                }
            )
    if producer_identity is None or method is None or registry is None:
        raise EvidenceError("canonical CSP manifest contains no shape cases")
    first = rows[0]["facts"]
    fixed_profile = {
        "preprocessed_column_count": first["expected_preprocessed_column_count"],
        "main_column_count": first["expected_main_column_count"],
        "interaction_column_count": first["expected_interaction_column_count"],
        "maximum_column_log_degree": first["expected_maximum_column_log_degree"],
    }
    for row in rows:
        facts = row["facts"]
        observed = {
            "preprocessed_column_count": facts["expected_preprocessed_column_count"],
            "main_column_count": facts["expected_main_column_count"],
            "interaction_column_count": facts["expected_interaction_column_count"],
            "maximum_column_log_degree": facts["expected_maximum_column_log_degree"],
        }
        if observed != fixed_profile:
            raise EvidenceError("shape inspections disagree on the fixed profile")
    fixed_profile_admissible = sum(
        row["facts"]["fixed_profile_admissible"] for row in rows
    )
    outer_executable = sum(row["status"] == "outer_executable" for row in rows)
    profile_matrix = []
    for profile_id, _, shape_values, expected_case_count in PROFILE_SPECS:
        matching = [
            row
            for row in rows
            if row["selected_profile"]["profile_id"] == profile_id
        ]
        if len(matching) != expected_case_count:
            raise EvidenceError(
                f"profile {profile_id} covers {len(matching)} cases, expected "
                f"{expected_case_count}"
            )
        profile_matrix.append(
            {
                "profile_id": profile_id,
                "profile_shape_sha256": _profile_shape_sha256(profile_id),
                "shape": _shape_object(shape_values),
                "expected_canonical_case_count": expected_case_count,
                "observed_canonical_case_count": len(matching),
                "implementation_status": "catalogued_outer_not_wired",
                "outer_executable": False,
                "workloads": [
                    {"target": row["target"], "input_size": row["input_size"]}
                    for row in matching
                ],
            }
        )
    return seal_document(
        {
            "schema": AUDIT_SCHEMA,
            "schema_version": 2,
            "classification": "proof_independent_shape_coverage_not_performance_evidence",
            "manifest": {
                "path": manifest_path.resolve().relative_to(repo_root.resolve()).as_posix(),
                "sha256": _sha256_file(manifest_path),
            },
            "inspector": {
                "path": inspector.relative_to(repo_root.resolve()).as_posix(),
                "sha256": _sha256_file(inspector),
                **producer_identity,
            },
            "method": method,
            "fixed_profile": fixed_profile,
            "profile_registry": registry,
            "profile_matrix": profile_matrix,
            "source_evidence": _source_evidence(repo_root),
            "coverage": {
                "case_count": len(rows),
                "admissible_count": outer_executable,
                "incompatible_count": len(rows) - outer_executable,
                "all_canonical_cases_admissible": outer_executable == len(rows),
                "fixed_profile_admissible_count": fixed_profile_admissible,
                "fixed_profile_incompatible_count": len(rows)
                - fixed_profile_admissible,
                "profile_registry_matched_count": len(rows),
                "profile_registry_unknown_count": 0,
                "outer_executable_count": outer_executable,
                "outer_unavailable_count": len(rows) - outer_executable,
                "all_canonical_cases_registry_matched": True,
                "all_canonical_cases_outer_executable": outer_executable
                == len(rows),
            },
            "cases": rows,
            "limitations": [
                "This audit constructs no proof and records no performance timing.",
                "Admission is exact equality with the frozen segment profile, not a capacity estimate.",
                "All canonical shapes are registry-selected, but no registry profile is yet instantiated by the outer circuit.",
            ],
        }
    )


def validate_shape_audit(
    audit: dict[str, Any],
    *,
    repo_root: Path | None = None,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    exact_object(audit, AUDIT_KEYS, "recursion shape audit")
    if (
        audit["schema"] != AUDIT_SCHEMA
        or audit["schema_version"] != 2
        or audit["classification"]
        != "proof_independent_shape_coverage_not_performance_evidence"
    ):
        raise EvidenceError("recursion shape audit schema/classification drifted")
    verify_document_seal(audit, label="recursion shape audit")
    manifest = audit["manifest"]
    if type(manifest) is not dict:
        raise EvidenceError("recursion shape audit manifest is missing")
    manifest_sha = expect_digest(manifest.get("sha256"), "shape audit manifest")
    if expected_manifest_sha256 is not None and manifest_sha != expected_manifest_sha256:
        raise EvidenceError("shape audit binds a different CSP manifest")
    if repo_root is not None:
        manifest_path = repo_root / manifest.get("path", "")
        if not manifest_path.is_file() or _sha256_file(manifest_path) != manifest_sha:
            raise EvidenceError("shape audit CSP manifest source is stale")
        expected_evidence = _source_evidence(repo_root)
        if audit["source_evidence"] != expected_evidence:
            raise EvidenceError("shape audit implementation source boundary is stale")
    profile = audit["fixed_profile"]
    if type(profile) is not dict or set(profile) != {
        "preprocessed_column_count",
        "main_column_count",
        "interaction_column_count",
        "maximum_column_log_degree",
    }:
        raise EvidenceError("shape audit fixed profile is malformed")
    for key, value in profile.items():
        expect_positive_int(value, f"shape audit.fixed_profile.{key}")
    registry = exact_object(
        audit["profile_registry"], REGISTRY_KEYS, "shape audit.profile_registry"
    )
    if registry != EXPECTED_REGISTRY:
        raise EvidenceError("shape audit profile-registry seal drifted")
    cases = audit["cases"]
    if type(cases) is not list or not cases:
        raise EvidenceError("shape audit cases are missing")
    seen: set[tuple[str, int]] = set()
    fixed_profile_admissible = 0
    outer_executable = 0
    selected_counts = {profile_id: 0 for profile_id in PROFILE_BY_ID}
    for index, raw in enumerate(cases):
        case = exact_object(raw, AUDIT_CASE_KEYS, f"shape audit.cases[{index}]")
        if (
            type(case["target"]) is not str
            or not case["target"]
            or type(case["input_size"]) is not int
            or case["input_size"] <= 0
        ):
            raise EvidenceError("shape audit case target/size is invalid")
        key = (case["target"], case["input_size"])
        if key in seen:
            raise EvidenceError("shape audit duplicates a workload")
        seen.add(key)
        expect_digest(case["guest_sha256"], f"shape audit.cases[{index}].guest")
        expect_digest(case["input_sha256"], f"shape audit.cases[{index}].input")
        expect_digest(case["expected_output_digest"], f"shape audit.cases[{index}].output")
        expect_positive_int(case["expected_cycles"], f"shape audit.cases[{index}].cycles")
        facts = exact_object(case["facts"], FACT_KEYS, f"shape audit.cases[{index}].facts")
        for fact_name in FACT_KEYS - {"admission", "fixed_profile_admissible"}:
            expect_positive_int(
                facts[fact_name],
                f"shape audit.cases[{index}].facts.{fact_name}",
                allow_zero=True,
            )
        if {
            "preprocessed_column_count": facts[
                "expected_preprocessed_column_count"
            ],
            "main_column_count": facts["expected_main_column_count"],
            "interaction_column_count": facts[
                "expected_interaction_column_count"
            ],
            "maximum_column_log_degree": facts[
                "expected_maximum_column_log_degree"
            ],
        } != profile:
            raise EvidenceError("shape audit case uses a different fixed profile")
        counts_match = (
            facts["preprocessed_column_count"]
            == facts["expected_preprocessed_column_count"]
            and facts["main_column_count"] == facts["expected_main_column_count"]
            and facts["interaction_column_count"]
            == facts["expected_interaction_column_count"]
        )
        log_matches = (
            facts["maximum_column_log_degree"]
            == facts["expected_maximum_column_log_degree"]
        )
        admitted = counts_match and log_matches
        expected_admission = (
            "admitted"
            if admitted
            else "column_counts_and_log_degree_mismatch"
            if not counts_match and not log_matches
            else "column_counts_mismatch"
            if not counts_match
            else "column_log_degree_mismatch"
        )
        if (
            facts["admission"] != expected_admission
            or facts["fixed_profile_admissible"] is not admitted
        ):
            raise EvidenceError("shape audit case admission contradicts exact geometry")
        selected = _validate_selected_profile(
            case["selected_profile"],
            facts,
            label=f"shape audit.cases[{index}].selected_profile",
        )
        selected_counts[selected["profile_id"]] += 1
        expected_status = (
            "outer_executable"
            if selected["outer_executable"]
            else "profile_catalogued_outer_unavailable"
        )
        if case["status"] != expected_status:
            raise EvidenceError("shape audit case status contradicts profile readiness")
        fixed_profile_admissible += int(admitted)
        outer_executable += int(selected["outer_executable"])

    matrix = audit["profile_matrix"]
    if type(matrix) is not list or len(matrix) != len(PROFILE_SPECS):
        raise EvidenceError("shape audit profile matrix is incomplete")
    expected_matrix = []
    for profile_id, _, shape_values, expected_case_count in PROFILE_SPECS:
        workloads = [
            {"target": case["target"], "input_size": case["input_size"]}
            for case in cases
            if case["selected_profile"]["profile_id"] == profile_id
        ]
        expected_matrix.append(
            {
                "profile_id": profile_id,
                "profile_shape_sha256": _profile_shape_sha256(profile_id),
                "shape": _shape_object(shape_values),
                "expected_canonical_case_count": expected_case_count,
                "observed_canonical_case_count": selected_counts[profile_id],
                "implementation_status": "catalogued_outer_not_wired",
                "outer_executable": False,
                "workloads": workloads,
            }
        )
    for index, row in enumerate(matrix):
        exact_object(row, PROFILE_MATRIX_KEYS, f"shape audit.profile_matrix[{index}]")
    if matrix != expected_matrix:
        raise EvidenceError("shape audit profile matrix contradicts canonical cases")
    coverage = audit["coverage"]
    expected_coverage = {
        "case_count": len(cases),
        "admissible_count": outer_executable,
        "incompatible_count": len(cases) - outer_executable,
        "all_canonical_cases_admissible": outer_executable == len(cases),
        "fixed_profile_admissible_count": fixed_profile_admissible,
        "fixed_profile_incompatible_count": len(cases)
        - fixed_profile_admissible,
        "profile_registry_matched_count": len(cases),
        "profile_registry_unknown_count": 0,
        "outer_executable_count": outer_executable,
        "outer_unavailable_count": len(cases) - outer_executable,
        "all_canonical_cases_registry_matched": True,
        "all_canonical_cases_outer_executable": outer_executable == len(cases),
    }
    if coverage != expected_coverage:
        raise EvidenceError("shape audit coverage summary is contradictory")
    return audit


def project_plan_shape_coverage(
    native_samples: list[dict[str, Any]],
    *,
    repo_root: Path,
    expected_manifest_sha256: str,
    audit_path: Path | None = None,
) -> dict[str, Any]:
    """Project the sealed audit onto a plan, or return explicit zero coverage."""

    root = repo_root.resolve()
    source = (
        audit_path.resolve()
        if audit_path is not None
        else root / "vectors/riscv_csp/recursion-shape-audit-v2.json"
    )
    if not source.is_file():
        return {
            "audit_status": "unavailable",
            "audit_path": None,
            "audit_sha256": None,
            "audit_canonical_digest": None,
            "fixed_profile": None,
            "profile_registry": None,
            "profile_matrix": [],
            "canonical_case_count": 0,
            "planned_case_count": len(native_samples),
            "admissible_count": 0,
            "incompatible_count": len(native_samples),
            "profile_registry_matched_count": 0,
            "profile_registry_unknown_count": len(native_samples),
            "outer_executable_count": 0,
            "outer_unavailable_count": len(native_samples),
            "all_planned_workloads_registry_matched": False,
            "all_planned_workloads_admissible": False,
            "cases": [
                {
                    "workload_id": sample["workload_id"],
                    "target": sample["workload"]["target"],
                    "input_size": sample["workload"]["input_size"],
                    "status": "unaudited",
                    "facts": None,
                    "selected_profile": None,
                }
                for sample in native_samples
            ],
            "blocking_reason": (
                "the sealed proof-independent canonical shape audit is unavailable; "
                "no recursive workload may be launched"
            ),
        }
    try:
        relative = source.relative_to(root).as_posix()
    except ValueError as error:
        raise EvidenceError("shape audit must be inside the repository") from error
    audit, raw = load_json(source)
    validate_shape_audit(
        audit,
        repo_root=root,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    indexed = {
        (case["target"], case["input_size"]): case for case in audit["cases"]
    }
    projected = []
    eligible = 0
    registry_matched = 0
    for native in native_samples:
        workload = native["workload"]
        key = (workload["target"], workload["input_size"])
        audited = indexed.get(key)
        if audited is None:
            status = "unaudited"
            facts = None
            selected_profile = None
        else:
            expected_identity = {
                "guest_sha256": workload["guest_sha256"],
                "input_sha256": workload["input_sha256"],
                "expected_output_digest": workload["expected_output_digest"],
                "expected_cycles": native["evidence"]["cycles"],
            }
            observed_identity = {
                key: audited[key] for key in expected_identity
            }
            if observed_identity != expected_identity:
                raise EvidenceError(
                    f"shape audit identity differs for {key[0]}/{key[1]}"
                )
            status = audited["status"]
            facts = audited["facts"]
            selected_profile = audited["selected_profile"]
            registry_matched += 1
        eligible += int(status == "outer_executable")
        projected.append(
            {
                "workload_id": native["workload_id"],
                "target": key[0],
                "input_size": key[1],
                "status": status,
                "facts": facts,
                "selected_profile": selected_profile,
            }
        )
    all_admitted = eligible == len(projected) and bool(projected)
    return {
        "audit_status": "available",
        "audit_path": relative,
        "audit_sha256": hashlib.sha256(raw).hexdigest(),
        "audit_canonical_digest": audit["canonical_digest"],
        "fixed_profile": audit["fixed_profile"],
        "profile_registry": audit["profile_registry"],
        "profile_matrix": audit["profile_matrix"],
        "canonical_case_count": audit["coverage"]["case_count"],
        "planned_case_count": len(projected),
        "admissible_count": eligible,
        "incompatible_count": len(projected) - eligible,
        "profile_registry_matched_count": registry_matched,
        "profile_registry_unknown_count": len(projected) - registry_matched,
        "outer_executable_count": eligible,
        "outer_unavailable_count": len(projected) - eligible,
        "all_planned_workloads_registry_matched": registry_matched
        == len(projected)
        and bool(projected),
        "all_planned_workloads_admissible": all_admitted,
        "cases": projected,
        "blocking_reason": (
            None
            if all_admitted
            else (
                "one or more planned shapes is absent from the bounded exact "
                "profile registry; no recursive benchmark cohort may be launched"
                if registry_matched != len(projected)
                else "all planned shapes are registry-selected, but one or more "
                "exact profiles is not outer-circuit executable; no recursive "
                "benchmark cohort may be launched"
            )
        ),
    }
