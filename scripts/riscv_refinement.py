#!/usr/bin/env python3
"""Generate and check manifest-wide RV32IM AIR-to-Sail refinement evidence."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The library is named exactly once, so it has exactly one module identity.
#
# This used to be a two-spelling fallback: ``scripts.riscv_refinement_lib`` first,
# bare ``riscv_refinement_lib`` second, with a comment explaining that the order
# mattered. It did, and relying on it was the defect. Direct execution
# (``python3 scripts/riscv_refinement.py``) puts ``scripts/`` on ``sys.path``
# instead of the repository root, so the qualified import failed and the fallback
# imported the same files again under a second name -- giving ``RefinementError``
# two distinct classes. A test that catches one cannot catch the other, and
# ``except RefinementError`` in this module would not catch what the library
# raised: the failure is silent in the fail-open direction, since an
# ``assertRaises`` that can never see its exception simply reports the *other*
# escape path as untested rather than reporting anything at all.
#
# Repairing ``sys.path`` and importing the one spelling removes the second name
# from the file, so no import order can reintroduce the second identity.
if __package__ in (None, ""):  # direct execution; the repository root is absent
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts import (
    riscv_opcode_coverage,
    riscv_refinement_receipt_build as receipt_build,
    riscv_refinement_receipt_constants as receipt_constants,
    riscv_refinement_receipt_identity as receipt_identity,
    riscv_refinement_receipt_validate as receipt_validate,
    riscv_team_a,
    riscv_team_b,
)
from scripts.riscv_refinement_lib import (
    air_program,
    air_program_contract,
    audited_inventory,
    codec,
    negative,
    render,
    sail,
)
from scripts.riscv_refinement_lib.model import (
    FULL_OPCODE_COUNT,
    PILOT_OPCODES,
    SCHEMA_VERSION,
    Paths,
    RefinementError,
    repository_root,
)
from scripts.riscv_refinement_lib.process import _run

AUDITED_THEOREMS = audited_inventory.AUDITED_THEOREMS
AUDITED_THEOREMS_BLOCK = audited_inventory.AUDITED_THEOREMS_BLOCK
_render_audited_theorems = audited_inventory.render
_rewrite_audited_theorems = audited_inventory.rewrite

APPROVED_LEAN_AXIOMS = receipt_constants.APPROVED_LEAN_AXIOMS
RECEIPT_SCHEMA_VERSION = receipt_constants.RECEIPT_SCHEMA_VERSION
RECEIPT_TIER = receipt_constants.RECEIPT_TIER
RECEIPT_CLAIM_BOUNDARY = receipt_constants.RECEIPT_CLAIM_BOUNDARY
TEAM_A_INDEX_RELATIVE = receipt_constants.TEAM_A_INDEX_RELATIVE
TEAM_B_INDEX_RELATIVE = receipt_constants.TEAM_B_INDEX_RELATIVE
OPCODE_INDEX_RELATIVE = receipt_constants.OPCODE_INDEX_RELATIVE
MUTATION_THEOREMS = receipt_constants.MUTATION_THEOREMS
NEGATIVE_CONTROLS = receipt_constants.NEGATIVE_CONTROLS
LIVE_SAIL_OPTIONS = receipt_constants.LIVE_SAIL_OPTIONS
AUDIT_COMMAND = receipt_constants.AUDIT_COMMAND
AUDITED_THEOREMS_REFRESH = receipt_constants.AUDITED_THEOREMS_REFRESH

FV_CLAIM_SUMMARY = (
    "46/46 normalized retirements, 46/46 publication implications; "
    "whole_frontend_verified=false; proof_system_soundness=false"
)

_production_inputs = receipt_build._production_inputs
_sail_inputs = receipt_build._sail_inputs
_theorem_axiom_index = receipt_build._theorem_axiom_index
_build_receipt_payload = receipt_build._build_receipt_payload

_tool = receipt_identity._tool
_toolchain = receipt_identity._toolchain
_repository_state = receipt_identity._repository_state
_strict_identity = receipt_identity._strict_identity
_sha256_identity = receipt_identity._sha256_identity
_payload_identity = receipt_identity._payload_identity
_validate_payload_identity = receipt_identity._validate_payload_identity
_certificate_index_identities = receipt_identity._certificate_index_identities
_validate_certificate_mappings = receipt_identity._validate_certificate_mappings
_fixed_table_schemas = receipt_identity._fixed_table_schemas
_opcode_mutations = receipt_identity._opcode_mutations
_team_a_proof_time_diagnostics = receipt_identity._team_a_proof_time_diagnostics
_generated_manifest_identity = receipt_identity._generated_manifest_identity

_receipt_revision_matches = receipt_validate._receipt_revision_matches
_validate_receipt_theorem_axioms = (
    receipt_validate._validate_receipt_theorem_axioms
)
_validate_receipt_numeric_identity = (
    receipt_validate._validate_receipt_numeric_identity
)
_validate_theorem_axiom_index = receipt_validate._validate_theorem_axiom_index
_validate_production_inputs = receipt_validate._validate_production_inputs
_validate_production_certificate_bindings = (
    receipt_validate._validate_production_certificate_bindings
)
_validate_sail_inputs = receipt_validate._validate_sail_inputs
_validate_certificate_sail_bindings = (
    receipt_validate._validate_certificate_sail_bindings
)
_validate_receipt_structure = receipt_validate._validate_receipt_structure


@dataclass(frozen=True)
class Verification:
    theorem_axioms: dict[str, list[str]]


def common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sail-riscv-dir", type=Path)
    parser.add_argument("--sail-bin", type=Path)
    parser.add_argument("--sail-generated-file", type=Path)
    parser.add_argument(
        "--no-export-air",
        action="store_true",
        help="consume an already exported AIR directory",
    )
    parser.add_argument(
        "--air-ir-dir",
        type=Path,
        help="exact AIR directory supplied by an upstream exporter",
    )
    parser.add_argument(
        "--air-program-ir-dir",
        type=Path,
        help="exact production AIR IR v2 directory supplied by an upstream exporter",
    )
    parser.add_argument(
        "--reuse-committed-sail-evidence",
        action="store_true",
        help=(
            "rebuild the Sail evidence from the committed manifest provenance "
            "instead of a live Sail toolchain; refuses unless every Sail input "
            "is byte-identical and the Sail artifacts are reproduced exactly"
        ),
    )


def reuses_committed_sail_evidence(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "reuse_committed_sail_evidence", False))


def evidence(args: argparse.Namespace, paths: Paths) -> sail.SailEvidence:
    if reuses_committed_sail_evidence(args):
        supplied = sorted(
            option for option in LIVE_SAIL_OPTIONS if getattr(args, option, None)
        )
        if supplied:
            raise RefinementError(
                "--reuse-committed-sail-evidence consumes no live Sail "
                "toolchain; drop "
                + ", ".join(f"--{option.replace('_', '-')}" for option in supplied)
            )
        return sail.carried_evidence(paths)
    return sail.collect_evidence(
        paths.root,
        args.sail_riscv_dir,
        args.sail_bin,
        args.sail_generated_file,
    )


def prepared_outputs(
    args: argparse.Namespace,
    paths: Paths,
) -> dict[Path, bytes]:
    if not args.no_export_air:
        render.export_air(paths)
    else:
        render.validate_air_export(paths.uniqueness_ir)
        render.validate_air_program_export(paths.air_program_ir)
    return render.artifacts(paths, evidence(args, paths))


def generate(args: argparse.Namespace, paths: Paths) -> None:
    outputs = prepared_outputs(args, paths)
    render.write_artifacts(paths, outputs)
    print(f"generated {len(outputs)} refinement artifacts")


def capture_sail_translation(
    args: argparse.Namespace,
    paths: Paths,
) -> None:
    """Bootstrap checked slices and Lean bridge from a manifest-bound backend."""
    if args.reuse_committed_sail_evidence:
        raise RefinementError(
            "capture-sail-translation does not accept "
            "--reuse-committed-sail-evidence"
        )
    if args.sail_riscv_dir is not None or args.sail_bin is not None:
        raise RefinementError(
            "capture-sail-translation consumes only --sail-generated-file"
        )
    if args.sail_generated_file is None:
        raise RefinementError(
            "capture-sail-translation requires --sail-generated-file"
        )
    if not args.no_export_air:
        render.export_air(paths)
    else:
        render.validate_air_export(paths.uniqueness_ir)
        render.validate_air_program_export(paths.air_program_ir)
    evidence = sail.capture_pinned_generated_evidence(
        paths,
        args.sail_generated_file,
    )
    outputs = render.artifacts(paths, evidence)
    render.write_artifacts(paths, outputs)
    print(
        "captured pinned generated-Sail translation/monad receipts: "
        f"{evidence.translation_receipt['canonical_digest']} / "
        f"{evidence.monad_bridge_receipt['canonical_digest']}"
    )


def check_generated(args: argparse.Namespace, paths: Paths) -> None:
    outputs = prepared_outputs(args, paths)
    render.check_artifacts(paths, outputs)
    print(f"checked {len(outputs)} byte-identical refinement artifacts")


def opcode_manifest(paths: Paths) -> tuple[str, ...]:
    source = (
        paths.root / "src" / "frontends" / "riscv" / "opcode_manifest.zig"
    ).read_text(encoding="utf-8")
    names = tuple(re.findall(r'proof\(\.[^,]+,\s*"([^"]+)"', source))
    if len(names) != FULL_OPCODE_COUNT or len(set(names)) != len(names):
        raise RefinementError(
            f"opcode manifest yielded {len(names)} unique proof entries, "
            f"expected {FULL_OPCODE_COUNT}"
        )
    return names


def coverage(paths: Paths, require_full: bool = False) -> None:
    manifest = codec.load_json(paths.manifest)
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("kind")
        != "stwo-riscv-refinement-generated-manifest"
        or manifest.get("tier") != "level-1-normalized-pilot"
        or manifest.get("canonical_digest")
        != render.manifest_content_digest(manifest)
    ):
        raise RefinementError("generated refinement manifest identity is invalid")
    entries = manifest.get("opcodes")
    if not isinstance(entries, list) or len(entries) != len(PILOT_OPCODES):
        raise RefinementError("generated refinement opcode mapping is malformed")
    expected_theorems = {
        "lui": (
            35,
            "RiscvRefinement.Opcodes.lui_refines",
            "RiscvRefinement.NonVacuity.lui_exists",
        ),
        "addi": (
            10,
            "RiscvRefinement.Opcodes.addi_refines",
            "RiscvRefinement.NonVacuity.addi_exists",
        ),
    }
    covered_names: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "air_digest",
            "coverage_kind",
            "id",
            "mnemonic",
            "non_vacuity_theorem",
            "refinement_theorem",
        }:
            raise RefinementError("generated refinement opcode entry drifted")
        mnemonic = entry["mnemonic"]
        if not isinstance(mnemonic, str) or mnemonic not in expected_theorems:
            raise RefinementError("generated refinement opcode name drifted")
        opcode_id, theorem, non_vacuity = expected_theorems[mnemonic]
        if (
            entry["id"] != opcode_id
            or entry["coverage_kind"] != "normalized-predicate"
            or entry["refinement_theorem"] != theorem
            or entry["non_vacuity_theorem"] != non_vacuity
            or not isinstance(entry["air_digest"], str)
            or len(entry["air_digest"]) != 64
        ):
            raise RefinementError(
                f"generated refinement mapping for {mnemonic} drifted"
            )
        covered_names.append(mnemonic)
    covered = tuple(covered_names)
    available = opcode_manifest(paths)
    if covered != PILOT_OPCODES:
        raise RefinementError(
            f"pilot coverage is {covered!r}, expected {PILOT_OPCODES!r}"
        )
    unknown = sorted(set(covered) - set(available))
    if unknown:
        raise RefinementError(f"proof coverage names unknown opcodes: {unknown}")
    if require_full and set(covered) != set(available):
        missing = sorted(set(available) - set(covered))
        raise RefinementError(
            "full refinement coverage is incomplete: " + ", ".join(missing)
        )
    print(
        f"refinement coverage: {len(covered)}/{len(available)} opcodes "
        f"({', '.join(covered)}); tier=level-1-normalized-pilot"
    )


def negative_controls(paths: Paths) -> None:
    results = negative.run(paths.uniqueness_ir)
    print(
        "negative controls: "
        + ", ".join(f"{item['name']}={item['status']}" for item in results)
    )




def _blank_span(rendered: list[str], text: str, start: int, end: int) -> int:
    """Overwrite ``text[start:end]`` with spaces, preserving every whitespace char."""
    for position in range(start, end):
        if not text[position].isspace():
            rendered[position] = " "
    return end


def _skip_lean_string(text: str, start: int) -> int:
    """Return the index after the Lean string literal opened at ``start``.

    The caller skips a literal without blanking it, so nothing inside a literal is
    ever hidden from the scan. What skipping buys is that a ``--`` or ``/-`` inside
    a literal opens no comment. Both branches below exist because of what happens
    when the skip ends in the wrong place, and they fail in opposite directions.

    ``\\`` escapes the next character, which also carries a Lean string gap over a
    newline. Without it a ``\\"`` would end the literal early and drop the scanner
    back into code mode *inside the literal's own text*, where a ``/-`` opens a
    block comment that blanks real code up to the next ``-/`` -- so a forbidden
    term after the literal is hidden and the scan reports a clean sweep. That is
    the fail-open direction, and the only one this function has.

    An unterminated literal recovers at the newline, which bounds a stray quote to
    its own line and keeps comment stripping working on the lines after it.
    Without that the skip would run to the next quote anywhere in the file, or to
    end of file, leaving every ``--`` and ``/- -/`` in between unblanked; prose
    naming a forbidden term would then be read as code. That direction fails
    closed -- a false breach report, not a missed one.
    """
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
        elif char == '"':
            return index + 1
        elif char == "\n":
            return index
        else:
            index += 1
    return len(text)


def _strip_lean_comments(text: str) -> str:
    """Return ``text`` with Lean ``--`` and nesting ``/- -/`` comments blanked.

    Splitting on ``--`` alone is wrong in both directions. It leaves ``/-! -/``
    block comments intact, so prose naming a forbidden term fails the scan, and
    it truncates at a ``--`` inside a string literal, so real code after
    ``"a--b"`` is never scanned at all. Comment characters become spaces rather
    than disappearing, so line numbers and columns still address the source.

    An unterminated block comment would blank the rest of the file, which is the
    one way this function could hide a forbidden term, so it fails closed instead.
    """
    rendered = list(text)
    index = 0
    depth = 0
    while index < len(text):
        if depth:
            if text.startswith("/-", index):
                depth += 1
                index = _blank_span(rendered, text, index, index + 2)
            elif text.startswith("-/", index):
                depth -= 1
                index = _blank_span(rendered, text, index, index + 2)
            else:
                index = _blank_span(rendered, text, index, index + 1)
        elif text[index] == '"':
            index = _skip_lean_string(text, index)
        elif text.startswith("/-", index):
            depth = 1
            index = _blank_span(rendered, text, index, index + 2)
        elif text.startswith("--", index):
            end = text.find("\n", index)
            index = _blank_span(rendered, text, index, len(text) if end < 0 else end)
        else:
            index += 1
    if depth:
        raise RefinementError("unterminated Lean block comment")
    return "".join(rendered)


def _scan_forbidden_proof_terms(paths: Paths) -> None:
    forbidden = re.compile(r"\b(sorry|admit|axiom|unsafe|native_decide)\b")
    errors: list[str] = []
    sources = [
        paths.formal / "RiscvRefinement.lean",
        *sorted((paths.formal / "RiscvRefinement").rglob("*.lean")),
    ]
    for source in sources:
        relative = source.relative_to(paths.root)
        try:
            code = _strip_lean_comments(source.read_text(encoding="utf-8"))
        except RefinementError as error:
            raise RefinementError(f"{relative}: {error}") from error
        for number, line in enumerate(code.splitlines(), 1):
            if forbidden.search(line):
                errors.append(f"{relative}:{number}")
    if errors:
        raise RefinementError(
            "forbidden proof escape appears at " + ", ".join(errors)
        )


def _parse_audit_records(output: str) -> dict[str, list[str]]:
    """Read the Lean audit transcript without deciding which theorems belong."""
    theorem_pattern = re.compile(
        r"^REFINEMENT_THEOREM (?P<theorem>RiscvRefinement\.[^\s]+)$"
    )
    axiom_pattern = re.compile(
        r"^REFINEMENT_AXIOM "
        r"(?P<theorem>RiscvRefinement\.[^\s]+) "
        r"(?P<axiom>[^\s]+)$"
    )
    report: dict[str, list[str]] = {}
    for line in output.splitlines():
        stripped = line.strip()
        match = theorem_pattern.fullmatch(stripped)
        if match is not None:
            theorem = match.group("theorem")
            if theorem in report:
                raise RefinementError(
                    f"axiom audit repeated theorem record {theorem}"
                )
            report[theorem] = []
            continue
        if stripped.startswith("REFINEMENT_THEOREM"):
            raise RefinementError(
                f"axiom audit emitted a malformed theorem record: {stripped}"
            )
        match = axiom_pattern.fullmatch(stripped)
        if match is not None:
            theorem = match.group("theorem")
            axiom = match.group("axiom")
            if theorem not in report:
                raise RefinementError(
                    f"axiom audit reported an undeclared theorem {theorem}"
                )
            if axiom in report[theorem]:
                raise RefinementError(
                    f"axiom audit repeated axiom {axiom} for {theorem}"
                )
            report[theorem].append(axiom)
            continue
        if stripped.startswith("REFINEMENT_AXIOM"):
            raise RefinementError(
                f"axiom audit emitted a malformed axiom record: {stripped}"
            )
    return report


def _audit_axioms(output: str) -> dict[str, list[str]]:
    report = _parse_audit_records(output)
    missing = sorted(set(AUDITED_THEOREMS) - set(report))
    extra = sorted(set(report) - set(AUDITED_THEOREMS))
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise RefinementError(
            "axiom audit declaration coverage drifted: "
            + "; ".join(details)
            + f"; {AUDITED_THEOREMS_REFRESH}"
        )
    unexpected = {
        axiom
        for axioms in report.values()
        for axiom in axioms
        if axiom not in APPROVED_LEAN_AXIOMS
    }
    if unexpected:
        raise RefinementError(
            "exported theorem has unapproved axioms: "
            + ", ".join(sorted(unexpected))
        )
    return {
        theorem: sorted(report[theorem])
        for theorem in sorted(report)
    }


def _live_audited_theorems(
    args: argparse.Namespace,
    paths: Paths,
) -> tuple[str, ...]:
    if args.audit_output is not None:
        try:
            output = args.audit_output.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RefinementError(
                f"{args.audit_output}: unreadable axiom audit transcript"
            ) from exc
    else:
        _run(["lake", "build"], paths.formal)
        output = _run(list(AUDIT_COMMAND), paths.formal)
    return tuple(sorted(_parse_audit_records(output)))


def audited_theorems(args: argparse.Namespace, paths: Paths) -> None:
    """Refresh or check the pinned theorem set; never relax the equality gate."""
    live = _live_audited_theorems(args, paths)
    pinned = tuple(AUDITED_THEOREMS)
    missing = sorted(set(pinned) - set(live))
    extra = sorted(set(live) - set(pinned))
    if not args.write:
        if not missing and not extra:
            print(f"audited theorems pinned exactly: {len(live)} theorems")
            return
        details: list[str] = []
        if extra:
            details.append("unpinned " + ", ".join(extra))
        if missing:
            details.append("retired " + ", ".join(missing))
        raise RefinementError(
            "pinned audited theorem set differs from the live Lean environment: "
            + "; ".join(details)
            + f"; {AUDITED_THEOREMS_REFRESH}"
        )
    source = args.pin_file or (
        paths.root
        / "scripts"
        / "riscv_refinement_lib"
        / "audited_inventory.py"
    )
    _rewrite_audited_theorems(source, live)
    print(
        f"repinned {len(live)} audited theorems in "
        f"{source} (+{len(extra)}, -{len(missing)}); review the diff"
    )




def verify(args: argparse.Namespace, paths: Paths) -> Verification:
    check_generated(args, paths)
    coverage(paths)
    negative_controls(paths)
    _scan_forbidden_proof_terms(paths)
    _run(
        [
            sys.executable,
            "scripts/riscv_team_b.py",
            "check",
            "--air-ir-dir",
            str(paths.uniqueness_ir),
        ],
        paths.root,
    )
    _run(
        [
            sys.executable,
            "scripts/riscv_team_b_witnesses.py",
            "--air-ir-dir",
            str(paths.uniqueness_ir),
        ],
        paths.root,
    )
    _run(
        [sys.executable, "scripts/riscv_team_a.py", "check"],
        paths.root,
    )
    _run(
        [sys.executable, "scripts/riscv_opcode_coverage.py", "check"],
        paths.root,
    )
    _run(
        [
            sys.executable,
            "-m",
            "unittest",
            "scripts.tests.test_riscv_refinement",
            "scripts.tests.test_riscv_air_program_layout",
            "scripts.tests.test_riscv_air_ir_equivalence",
            "scripts.tests.test_riscv_team_b",
            "scripts.tests.test_riscv_team_b_witnesses",
            "scripts.tests.test_riscv_team_a",
            "scripts.tests.test_sail_translation",
            "scripts.tests.test_sail_air_composition_contract",
            "scripts.tests.test_riscv_refinement_publication",
        ],
        paths.root,
    )
    _run(["lake", "build"], paths.formal)
    audit_output = _run(list(AUDIT_COMMAND), paths.formal)
    axiom_report = _audit_axioms(audit_output)
    try:
        print(riscv_team_a.check_axiom_bindings(axiom_report))
    except riscv_team_a.TeamAError as exc:
        raise RefinementError(str(exc)) from exc
    missing_mutations = sorted(
        set(MUTATION_THEOREMS.values()) - set(axiom_report)
    )
    if missing_mutations:
        raise RefinementError(
            "Lean mutation theorem coverage is incomplete: "
            + ", ".join(missing_mutations)
        )
    print(
        "refinement verified: fresh artifacts, exact 24/24 production-AIR "
        "and 46/46 certificate coverage, negative controls, unit tests, "
        f"Lean build, and axiom audit; {FV_CLAIM_SUMMARY}"
    )
    return Verification(theorem_axioms=axiom_report)


def receipt(args: argparse.Namespace, paths: Paths) -> None:
    if args.no_export_air:
        raise RefinementError(
            "release receipts require a fresh production AIR export; "
            "--no-export-air is forbidden"
        )
    if reuses_committed_sail_evidence(args):
        raise RefinementError(
            "release receipts require live Sail toolchain evidence; "
            "--reuse-committed-sail-evidence is forbidden"
        )
    verification = verify(args, paths)
    sail_evidence = evidence(args, paths)
    revision, dirty_paths = _repository_state(paths)
    if dirty_paths:
        raise RefinementError(
            "release receipt requires a clean repository; dirty paths: "
            + ", ".join(dirty_paths)
        )
    payload = _build_receipt_payload(
        paths,
        verification,
        sail_evidence,
        revision,
    )
    codec.atomic_write(paths.receipt, codec.pretty_bytes(payload))
    print(
        "refinement receipt: "
        f"{payload['canonical_digest']} "
        f"(24/24 production AIR; {FV_CLAIM_SUMMARY})"
    )


def verify_receipt(args: argparse.Namespace, paths: Paths) -> None:
    if args.no_export_air:
        raise RefinementError(
            "receipt verification requires a fresh production AIR export; "
            "--no-export-air is forbidden"
        )
    if reuses_committed_sail_evidence(args):
        raise RefinementError(
            "receipt verification requires live Sail toolchain evidence; "
            "--reuse-committed-sail-evidence is forbidden"
        )
    payload = codec.load_json(paths.receipt)
    _validate_receipt_structure(payload)
    _receipt_revision_matches(paths, payload["repository_revision"])
    verification = verify(args, paths)
    sail_evidence = evidence(args, paths)
    expected = _build_receipt_payload(
        paths,
        verification,
        sail_evidence,
        payload["repository_revision"],
    )
    if payload != expected:
        raise RefinementError(
            "refinement receipt does not bind the current A5 evidence"
        )
    unexpected = {
        axiom
        for axioms in payload["theorem_axiom_index"]["entries"].values()
        for axiom in axioms
        if axiom not in APPROVED_LEAN_AXIOMS
    }
    if unexpected:
        raise RefinementError(
            "receipt contains unapproved axioms: " + ", ".join(sorted(unexpected))
        )
    print(f"refinement receipt verified: {payload['canonical_digest']}")


def prepare_sail(args: argparse.Namespace, paths: Paths) -> None:
    prepared = sail.prepare_exact_backend(
        paths.root,
        args.sail_riscv_dir,
        args.sail_bin,
        args.force,
    )
    print(
        "prepared exact RV32IM Sail theorem backend: "
        f"{prepared.generated_file_sha256}"
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("generate", "check-generated", "verify", "receipt"):
        command = commands.add_parser(name)
        common_arguments(command)
    capture_parser = commands.add_parser("capture-sail-translation")
    common_arguments(capture_parser)
    prepare_parser = commands.add_parser("prepare-sail")
    prepare_parser.add_argument("--sail-riscv-dir", type=Path)
    prepare_parser.add_argument("--sail-bin", type=Path)
    prepare_parser.add_argument("--force", action="store_true")
    coverage_parser = commands.add_parser("coverage")
    coverage_parser.add_argument("--require-full", action="store_true")
    audited_parser = commands.add_parser("audited-theorems")
    audited_parser.add_argument(
        "--write",
        action="store_true",
        help="repin AUDITED_THEOREMS from the live Lean environment",
    )
    audited_parser.add_argument(
        "--audit-output",
        type=Path,
        help="replay a captured axiom-audit transcript instead of running Lean",
    )
    audited_parser.add_argument(
        "--pin-file",
        type=Path,
        help="source file holding the AUDITED_THEOREMS pin",
    )
    commands.add_parser("negative-controls")
    verify_receipt_parser = commands.add_parser("verify-receipt")
    common_arguments(verify_receipt_parser)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    root = repository_root()
    air_ir_dir = getattr(args, "air_ir_dir", None)
    air_program_ir_dir = getattr(args, "air_program_ir_dir", None)
    paths = Paths(root, air_ir_dir, air_program_ir_dir)
    try:
        if (
            air_ir_dir is not None or air_program_ir_dir is not None
        ) and not getattr(args, "no_export_air", False):
            raise RefinementError(
                "--air-ir-dir and --air-program-ir-dir require --no-export-air"
            )
        if args.command == "generate":
            generate(args, paths)
        elif args.command == "capture-sail-translation":
            capture_sail_translation(args, paths)
        elif args.command == "check-generated":
            check_generated(args, paths)
        elif args.command == "coverage":
            coverage(paths, args.require_full)
        elif args.command == "audited-theorems":
            audited_theorems(args, paths)
        elif args.command == "negative-controls":
            negative_controls(paths)
        elif args.command == "prepare-sail":
            prepare_sail(args, paths)
        elif args.command == "verify":
            verify(args, paths)
        elif args.command == "receipt":
            receipt(args, paths)
        elif args.command == "verify-receipt":
            verify_receipt(args, paths)
        else:
            raise AssertionError(args.command)
    except RefinementError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
