#!/usr/bin/env python3
"""Validate the fail-closed Cairo / RISC-V CSP comparison plan.

This driver is intentionally cheap.  It authenticates the retained RISC-V
suite, inputs, outputs, and proof evidence, then classifies Cairo rows.  It does
not run a near-match when an exact Cairo fixture is absent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from scripts import cairo_csp_comparison_support as _support
except ModuleNotFoundError:
    import cairo_csp_comparison_support as _support


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "vectors/cairo/csp/comparison-manifest-v1.json"
SCHEMA = "stwo_cairo_riscv_csp_comparison_manifest_v1"
PUBLIC_STATEMENT_SCHEMA = _support.PUBLIC_STATEMENT_SCHEMA
STATUSES = ("exact_runnable", "pending_exact_cairo_fixture")
PUBLIC_BINDINGS = (
    "program_sha256",
    "logical_input_encoding",
    "logical_input_size",
    "logical_input_sha256",
    "canonical_output_encoding",
    "canonical_output_hex",
)
EXPECTED_ROWS = (
    ("sha256_2048_bytes", "sha256", 2048),
    ("keccak256_2048_bytes", "keccak", 2048),
    ("poseidon2_m31_16_elements", "poseidon2_m31", 16),
    ("ecdsa_secp256k1_32_byte_digest", "ecdsa_secp256k1", 32),
)
CORELIB_ENTRYPOINTS = {
    "sha256": ("sha256", "compute_sha256_byte_array"),
    "keccak": ("keccak", "compute_keccak_byte_array"),
    "poseidon2_m31": ("poseidon", "poseidon_hash_span"),
    "ecdsa_secp256k1": ("ecdsa", "check_ecdsa_signature"),
}
CONSTRAINED_HASH_BASES = {
    "sha256": ("sha2", "finalize_sha256"),
    "keccak": ("sha3", "finalize_keccak"),
}
PREPARED_HASH_RELATIONSHIP = "exact_constrained_source_prepared_proof_pending"

ComparisonError = _support.ComparisonError
load_json = _support.load_json
sha256_file = _support.sha256_file
_authenticate_file = _support._authenticate_file
_decode_logical_input = _support._decode_logical_input
_expect_keys = _support._expect_keys
_expect_object = _support._expect_object
_find_report_measurement = _support._find_report_measurement
_find_riscv_case = _support._find_riscv_case
_require_commit = _support._require_commit
_require_int = _support._require_int
_require_sha256 = _support._require_sha256
_require_text = _support._require_text
_validate_artifact_descriptor = _support._validate_artifact_descriptor
_validate_expected_output = _support._validate_expected_output
_validate_fixture_state = _support._validate_fixture_state
_validate_negative_gate = _support._validate_negative_gate
_validate_report_evidence = _support._validate_report_evidence
audit_corelib_checkout = _support.audit_corelib_checkout


def validate_manifest(
    manifest: Mapping[str, Any],
    *,
    root: Path = ROOT,
    corelib_checkout: Path | None = None,
) -> dict[str, Any]:
    """Authenticate a manifest and return its executable comparison plan."""

    root = root.resolve()
    _expect_keys(
        manifest,
        (
            "schema",
            "note",
            "riscv_authority",
            "cairo_authority",
            "comparison_contract",
            "rows",
        ),
        "manifest",
    )
    if manifest.get("schema") != SCHEMA:
        raise ComparisonError(f"unsupported manifest schema {manifest.get('schema')!r}")
    _require_text(manifest.get("note"), "manifest.note")

    riscv_authority = _expect_object(
        manifest.get("riscv_authority"), "manifest.riscv_authority"
    )
    _expect_keys(
        riscv_authority,
        (
            "manifest_path",
            "manifest_sha256",
            "manifest_schema",
            "upstream_commit",
            "retained_report",
        ),
        "manifest.riscv_authority",
    )
    suite_path = _authenticate_file(
        root,
        riscv_authority,
        "manifest.riscv_authority",
        path_key="manifest_path",
        sha_key="manifest_sha256",
    )
    suite = load_json(suite_path)
    if suite.get("schema") != riscv_authority.get("manifest_schema"):
        raise ComparisonError("RISC-V suite schema drifted")
    upstream = _expect_object(suite.get("upstream"), "RISC-V suite.upstream")
    if upstream.get("commit") != riscv_authority.get("upstream_commit"):
        raise ComparisonError("RISC-V CSP upstream commit drifted")

    report_descriptor = _expect_object(
        riscv_authority.get("retained_report"),
        "manifest.riscv_authority.retained_report",
    )
    _expect_keys(
        report_descriptor,
        ("path", "sha256", "schema", "measurement_commit", "use"),
        "manifest.riscv_authority.retained_report",
    )
    report_path = _authenticate_file(
        root, report_descriptor, "manifest.riscv_authority.retained_report"
    )
    report = load_json(report_path)
    if report.get("schema") != report_descriptor.get("schema"):
        raise ComparisonError("retained RISC-V report schema drifted")
    if report.get("measurement_commit") != report_descriptor.get("measurement_commit"):
        raise ComparisonError("retained RISC-V report commit drifted")
    if report.get("suite_manifest_sha256") != riscv_authority.get("manifest_sha256"):
        raise ComparisonError("retained RISC-V report does not bind the suite manifest")
    _require_text(report_descriptor.get("use"), "retained_report.use")

    cairo_authority = _expect_object(
        manifest.get("cairo_authority"), "manifest.cairo_authority"
    )
    _expect_keys(
        cairo_authority,
        (
            "corelib",
            "pr171_fixture_assessment",
            "exact_hash_fixture_preparation",
        ),
        "manifest.cairo_authority",
    )
    corelib = _expect_object(cairo_authority.get("corelib"), "cairo_authority.corelib")
    _expect_keys(
        corelib,
        (
            "repository",
            "commit",
            "proof_soundness_role",
            "proof_soundness_limit",
            "sources",
        ),
        "cairo_authority.corelib",
    )
    _require_text(corelib.get("repository"), "corelib.repository")
    _require_commit(corelib.get("commit"), "corelib.commit")
    if corelib.get("proof_soundness_role") != "semantic_source_reference_only":
        raise ComparisonError("modern corelib was promoted beyond semantic reference")
    _require_text(corelib.get("proof_soundness_limit"), "corelib.proof_soundness_limit")
    sources = _expect_object(corelib.get("sources"), "corelib.sources")
    if set(sources) != {"sha256", "keccak", "poseidon", "ecdsa"}:
        raise ComparisonError("corelib source inventory drifted")
    for name, raw_descriptor in sources.items():
        descriptor = _expect_object(raw_descriptor, f"corelib.sources.{name}")
        _expect_keys(descriptor, ("path", "bytes", "sha256"), f"corelib.sources.{name}")
        _require_text(descriptor.get("path"), f"corelib.sources.{name}.path")
        _require_int(descriptor.get("bytes"), f"corelib.sources.{name}.bytes", positive=True)
        _require_sha256(descriptor.get("sha256"), f"corelib.sources.{name}.sha256")
    if corelib_checkout is not None:
        audit_corelib_checkout(corelib_checkout, corelib)

    assessment = _expect_object(
        cairo_authority.get("pr171_fixture_assessment"),
        "cairo_authority.pr171_fixture_assessment",
    )
    _expect_keys(
        assessment,
        (
            "provenance_path",
            "provenance_sha256",
            "schema",
            "program_input_key",
            "assessed_programs",
            "required_finalizers",
            "publishes_digest_output",
            "proof_sound_role",
            "verdict",
            "reason",
        ),
        "cairo_authority.pr171_fixture_assessment",
    )
    corpus_path = _authenticate_file(
        root,
        assessment,
        "cairo_authority.pr171_fixture_assessment",
        path_key="provenance_path",
        sha_key="provenance_sha256",
    )
    corpus = load_json(corpus_path)
    if corpus.get("schema") != assessment.get("schema"):
        raise ComparisonError("PR 171 fixture corpus schema drifted")
    compiler = _expect_object(corpus.get("compiler"), "PR 171 fixture compiler")
    if compiler.get("program_input_key") != assessment.get("program_input_key"):
        raise ComparisonError("PR 171 fixture input contract drifted")
    assessed_programs = assessment.get("assessed_programs")
    if assessed_programs != ["sha2", "sha3"]:
        raise ComparisonError("PR 171 assessed program inventory drifted")
    programs = _expect_object(corpus.get("programs"), "PR 171 fixture programs")
    if any(name not in programs for name in assessed_programs):
        raise ComparisonError("PR 171 assessed program is absent")
    if assessment.get("required_finalizers") != {
        "sha2": "finalize_sha256",
        "sha3": "finalize_keccak",
    }:
        raise ComparisonError("PR 171 required-finalizer contract drifted")
    if assessment.get("publishes_digest_output") != {"sha2": False, "sha3": False}:
        raise ComparisonError("PR 171 public-output assessment drifted")
    if assessment.get("proof_sound_role") != "constrained_adaptation_base_only":
        raise ComparisonError("PR 171 programs were promoted beyond their assessed role")
    if assessment.get("verdict") != "not_exact_csp_input":
        raise ComparisonError("PR 171 fixture assessment must remain fail-closed")
    _require_text(assessment.get("reason"), "PR 171 fixture assessment.reason")

    preparation = _expect_object(
        cairo_authority.get("exact_hash_fixture_preparation"),
        "cairo_authority.exact_hash_fixture_preparation",
    )
    _expect_keys(
        preparation,
        (
            "provenance_path",
            "provenance_sha256",
            "schema",
            "prepared_fixtures",
            "required_status",
            "proof_sound_role",
            "verdict",
            "reason",
        ),
        "cairo_authority.exact_hash_fixture_preparation",
    )
    preparation_path = _authenticate_file(
        root,
        preparation,
        "cairo_authority.exact_hash_fixture_preparation",
        path_key="provenance_path",
        sha_key="provenance_sha256",
    )
    prepared = load_json(preparation_path)
    if prepared.get("schema") != preparation.get("schema"):
        raise ComparisonError("exact hash fixture preparation schema drifted")
    prepared_names = ["sha256_2048_bytes", "keccak256_2048_bytes"]
    if preparation.get("prepared_fixtures") != prepared_names:
        raise ComparisonError("prepared exact hash fixture inventory drifted")
    if preparation.get("required_status") != "source_ready_compilation_pending":
        raise ComparisonError("prepared exact hash fixture status drifted")
    if preparation.get("proof_sound_role") != PREPARED_HASH_RELATIONSHIP:
        raise ComparisonError("prepared exact hash source role drifted")
    if preparation.get("verdict") != (
        "not_runnable_until_compiled_derived_proved_and_verified"
    ):
        raise ComparisonError("prepared exact hash fixture was promoted without evidence")
    _require_text(preparation.get("reason"), "exact hash fixture preparation.reason")
    prepared_fixtures = _expect_object(
        prepared.get("fixtures"), "exact hash fixture provenance.fixtures"
    )
    if set(prepared_fixtures) != set(prepared_names):
        raise ComparisonError("exact hash fixture provenance inventory drifted")
    for name, finalizer in (
        ("sha256_2048_bytes", "finalize_sha256"),
        ("keccak256_2048_bytes", "finalize_keccak"),
    ):
        fixture = _expect_object(
            prepared_fixtures.get(name), f"exact hash fixture {name}"
        )
        if (
            fixture.get("comparison_row") != name
            or fixture.get("status") != preparation.get("required_status")
            or fixture.get("required_finalizer") != finalizer
        ):
            raise ComparisonError(f"prepared exact hash fixture {name} state drifted")
        _validate_artifact_descriptor(
            root, fixture.get("source"), f"exact hash fixture {name}.source"
        )
        _validate_artifact_descriptor(
            root, fixture.get("arguments"), f"exact hash fixture {name}.arguments"
        )
        for artifact in (
            "compiled_program",
            "prover_input",
            "expected_vm_steps",
            "public_statement",
            "proof",
            "verifier_receipt",
        ):
            if fixture.get(artifact) is not None:
                raise ComparisonError(
                    f"prepared exact hash fixture {name} carries unauthenticated "
                    f"{artifact}"
                )

    contract = _expect_object(
        manifest.get("comparison_contract"), "manifest.comparison_contract"
    )
    _expect_keys(
        contract,
        (
            "allowed_statuses",
            "logical_input_digest_definition",
            "timing_scope",
            "security_protocol",
            "public_statement_schema",
            "required_public_bindings",
            "output_requirement",
            "verifier_requirement",
        ),
        "manifest.comparison_contract",
    )
    if contract.get("allowed_statuses") != list(STATUSES):
        raise ComparisonError("comparison status vocabulary drifted")
    _require_text(
        contract.get("logical_input_digest_definition"),
        "comparison_contract.logical_input_digest_definition",
    )
    if contract.get("public_statement_schema") != PUBLIC_STATEMENT_SCHEMA:
        raise ComparisonError("comparison public statement schema drifted")
    if contract.get("required_public_bindings") != list(PUBLIC_BINDINGS):
        raise ComparisonError("comparison public bindings drifted")
    for name in ("timing_scope", "output_requirement", "verifier_requirement"):
        _require_text(contract.get(name), f"comparison_contract.{name}")
    security = _expect_object(
        contract.get("security_protocol"), "comparison_contract.security_protocol"
    )
    expected_security = {
        "name": "secure",
        "pow_bits": 26,
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 70,
        "fold_step": 1,
    }
    if security != expected_security:
        raise ComparisonError("comparison security protocol drifted")

    rows = manifest.get("rows")
    if not isinstance(rows, list):
        raise ComparisonError("manifest.rows must be a list")
    expected_ids = [item[0] for item in EXPECTED_ROWS]
    if [row.get("id") if isinstance(row, dict) else None for row in rows] != expected_ids:
        raise ComparisonError("comparison row inventory or order drifted")

    result_rows: list[dict[str, Any]] = []
    for raw_row, (expected_id, expected_target, expected_size) in zip(
        rows, EXPECTED_ROWS, strict=True
    ):
        row = _expect_object(raw_row, f"row {expected_id}")
        context = f"row {expected_id}"
        _expect_keys(
            row,
            (
                "id",
                "status",
                "relationship",
                "semantic_function",
                "riscv",
                "logical_input",
                "expected_output",
                "cairo_candidate",
                "public_statement",
                "cairo_fixture",
                "pending",
                "negative_gate",
            ),
            context,
        )
        if row.get("id") != expected_id or row.get("status") not in STATUSES:
            raise ComparisonError(f"{context}: identity or status drifted")
        _require_text(row.get("semantic_function"), f"{context}.semantic_function")

        riscv = _expect_object(row.get("riscv"), f"{context}.riscv")
        _expect_keys(
            riscv,
            (
                "target",
                "input_size",
                "input_size_unit",
                "input_path",
                "input_sha256",
                "input_encoding",
                "output_encoding",
                "expected_cycles",
                "report_public_values_sha256",
                "report_statement_sha256",
                "report_proof_sha256",
            ),
            f"{context}.riscv",
        )
        if riscv.get("target") != expected_target or riscv.get("input_size") != expected_size:
            raise ComparisonError(f"{context}: RISC-V target or size drifted")
        for key in (
            "input_sha256",
            "report_public_values_sha256",
            "report_statement_sha256",
            "report_proof_sha256",
        ):
            _require_sha256(riscv.get(key), f"{context}.riscv.{key}")
        _require_int(
            riscv.get("expected_cycles"),
            f"{context}.riscv.expected_cycles",
            positive=True,
        )

        target_record, suite_case = _find_riscv_case(suite, expected_target, expected_size)
        authority_checks = {
            "input_size_unit": target_record.get("input_size_unit"),
            "input_encoding": target_record.get("input_encoding"),
            "output_encoding": target_record.get("output_encoding"),
            "input_path": suite_case.get("input_path"),
            "input_sha256": suite_case.get("input_sha256"),
            "expected_cycles": suite_case.get("expected_cycles"),
        }
        for key, expected in authority_checks.items():
            if riscv.get(key) != expected:
                raise ComparisonError(f"{context}: RISC-V {key} disagrees with suite authority")
        input_path = _authenticate_file(
            root,
            {"path": riscv["input_path"], "sha256": riscv["input_sha256"]},
            f"{context}.riscv input",
        )
        try:
            encoded_input = input_path.read_bytes()
        except OSError as error:
            raise ComparisonError(f"cannot read {input_path}: {error}") from error

        logical = _expect_object(row.get("logical_input"), f"{context}.logical_input")
        _expect_keys(
            logical,
            (
                "container_encoding",
                "value_encoding",
                "value_size",
                "logical_input_sha256",
                "exact_value",
            ),
            f"{context}.logical_input",
        )
        logical_bytes = _decode_logical_input(
            expected_target, encoded_input, logical, f"{context}.logical_input"
        )
        logical_sha = _require_sha256(
            logical.get("logical_input_sha256"),
            f"{context}.logical_input.logical_input_sha256",
        )
        if hashlib.sha256(logical_bytes).hexdigest() != logical_sha:
            raise ComparisonError(f"{context}: logical input digest drifted")

        output = _expect_object(row.get("expected_output"), f"{context}.expected_output")
        output_hex = _validate_expected_output(
            expected_target, logical_bytes, logical, output, context
        )
        if suite_case.get("expected_digest") != output_hex:
            raise ComparisonError(f"{context}: output disagrees with RISC-V suite authority")
        report_row = _find_report_measurement(report, expected_target, expected_size)
        _validate_report_evidence(report_row, riscv, output_hex)

        candidate = _expect_object(row.get("cairo_candidate"), f"{context}.cairo_candidate")
        _expect_keys(
            candidate,
            (
                "corelib_source",
                "entrypoint",
                "relationship",
                "semantic_gap",
                "proof_sound_path",
                "required_implementation",
            ),
            f"{context}.cairo_candidate",
        )
        expected_source, expected_entrypoint = CORELIB_ENTRYPOINTS[expected_target]
        if (
            candidate.get("corelib_source") != expected_source
            or candidate.get("entrypoint") != expected_entrypoint
        ):
            raise ComparisonError(f"{context}: Cairo corelib candidate drifted")
        _require_text(
            candidate.get("required_implementation"),
            f"{context}.cairo_candidate.required_implementation",
        )
        if row.get("status") == "exact_runnable":
            if row.get("relationship") != "exact_equivalent":
                raise ComparisonError(f"{context}: runnable row is not exact-equivalent")
            if candidate.get("relationship") != "exact_equivalent_candidate":
                raise ComparisonError(f"{context}: runnable Cairo path is not exact")
            if candidate.get("semantic_gap") is not None:
                raise ComparisonError(f"{context}: runnable Cairo path has a semantic gap")
        elif expected_target in CONSTRAINED_HASH_BASES:
            if row.get("relationship") != PREPARED_HASH_RELATIONSHIP:
                raise ComparisonError(f"{context}: constrained hash path drifted")
            if candidate.get("relationship") != "analogy_only":
                raise ComparisonError(
                    f"{context}: unconstrained syscall reference was relabelled exact"
                )
            _require_text(
                candidate.get("semantic_gap"), f"{context}.cairo_candidate.semantic_gap"
            )
        else:
            if row.get("relationship") != "analogy_only":
                raise ComparisonError(f"{context}: near-match was relabelled as exact")
            if candidate.get("relationship") != "analogy_only":
                raise ComparisonError(f"{context}: Cairo near-match was relabelled as exact")
            _require_text(
                candidate.get("semantic_gap"), f"{context}.cairo_candidate.semantic_gap"
            )

        proof_sound_path = candidate.get("proof_sound_path")
        if expected_target in CONSTRAINED_HASH_BASES:
            path = _expect_object(
                proof_sound_path, f"{context}.cairo_candidate.proof_sound_path"
            )
            _expect_keys(
                path,
                (
                    "base_program",
                    "required_finalizer",
                    "requires_public_digest_output",
                ),
                f"{context}.cairo_candidate.proof_sound_path",
            )
            base_program, finalizer = CONSTRAINED_HASH_BASES[expected_target]
            if path != {
                "base_program": base_program,
                "required_finalizer": finalizer,
                "requires_public_digest_output": True,
            }:
                raise ComparisonError(f"{context}: constrained hash proof path drifted")
            if assessment["required_finalizers"].get(base_program) != finalizer:
                raise ComparisonError(f"{context}: finalizer disagrees with PR 171 authority")
            if assessment["publishes_digest_output"].get(base_program) is not False:
                raise ComparisonError(f"{context}: PR 171 output assessment drifted")
        elif proof_sound_path is not None:
            raise ComparisonError(f"{context}: unsupported near-match has a proof-sound path")

        _validate_fixture_state(root, row, PUBLIC_BINDINGS, context)
        _validate_negative_gate(
            root,
            suite,
            report,
            expected_target,
            row.get("negative_gate"),
            context,
        )
        result_rows.append(
            {
                "id": expected_id,
                "status": row["status"],
                "relationship": row["relationship"],
                "target": expected_target,
                "input_size": expected_size,
                "logical_input_sha256": logical_sha,
                "expected_output_hex": output_hex,
            }
        )

    runnable = sum(row["status"] == "exact_runnable" for row in result_rows)
    pending = sum(
        row["status"] == "pending_exact_cairo_fixture" for row in result_rows
    )
    return {
        "schema": "stwo_cairo_riscv_csp_comparison_plan_v1",
        "manifest_schema": SCHEMA,
        "runnable_rows": runnable,
        "pending_rows": pending,
        "rows": result_rows,
    }


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--audit-corelib-source",
        type=Path,
        help="also authenticate a checkout at the pinned Cairo corelib commit",
    )
    parser.add_argument("--require-runnable", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.root.resolve()
    manifest_path = args.manifest
    if not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    try:
        manifest = load_json(manifest_path)
        plan = validate_manifest(
            manifest,
            root=root,
            corelib_checkout=args.audit_corelib_source,
        )
        plan["manifest_path"] = os.fspath(manifest_path.resolve().relative_to(root))
        plan["manifest_sha256"] = sha256_file(manifest_path)
        if args.require_runnable and plan["runnable_rows"] == 0:
            raise ComparisonError(
                "no exact_runnable Cairo rows; refusing to time pending near-matches"
            )
    except (ComparisonError, ValueError) as error:
        print(f"cairo CSP comparison error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        print(
            "validated Cairo/RISC-V CSP plan: "
            f"{plan['runnable_rows']} exact runnable, {plan['pending_rows']} pending"
        )
        for row in plan["rows"]:
            print(f"{row['status']:>27}  {row['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
