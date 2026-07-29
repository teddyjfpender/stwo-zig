#!/usr/bin/env python3
"""Generate and check the LUI/ADDI Universal AIR-to-Sail Lean pilot."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from riscv_refinement_lib import codec, negative, render, sail
    from riscv_refinement_lib.model import (
        FULL_OPCODE_COUNT,
        PILOT_OPCODES,
        SCHEMA_VERSION,
        Paths,
        RefinementError,
        repository_root,
    )
except ModuleNotFoundError:
    from scripts.riscv_refinement_lib import codec, negative, render, sail
    from scripts.riscv_refinement_lib.model import (
        FULL_OPCODE_COUNT,
        PILOT_OPCODES,
        SCHEMA_VERSION,
        Paths,
        RefinementError,
        repository_root,
)

AUDITED_THEOREMS = (
    "RiscvRefinement.WordBytes.value_lt",
    "RiscvRefinement.WordBytes.word_toNat",
    "RiscvRefinement.WordBytes.zero_word",
    "RiscvRefinement.WordBytes.eq_of_limbs",
    "RiscvRefinement.toNat_append_arith",
    "RiscvRefinement.architecturalWrite_zero",
    "RiscvRefinement.architecturalValue_zero",
    "RiscvRefinement.architecturalWrite_value",
    "RiscvRefinement.Decode.encode_lui_is_canonical",
    "RiscvRefinement.Decode.encode_addi_is_canonical",
    "RiscvRefinement.Opcodes.lui_value_refines",
    "RiscvRefinement.Opcodes.lui_result_bytes_refine",
    "RiscvRefinement.Opcodes.lui_destination_from_constraints",
    "RiscvRefinement.Opcodes.lui_refines",
    "RiscvRefinement.Opcodes.addi_immediate_refines",
    "RiscvRefinement.Opcodes.addi_immediate_value_lt",
    "RiscvRefinement.Opcodes.addi_source_from_constraints",
    "RiscvRefinement.Opcodes.addi_arithmetic_from_constraints",
    "RiscvRefinement.Opcodes.addi_destination_from_constraints",
    "RiscvRefinement.Opcodes.addi_value_refines",
    "RiscvRefinement.Opcodes.addi_refines",
    "RiscvRefinement.NonVacuity.honest_lui_holds",
    "RiscvRefinement.NonVacuity.lui_exists",
    "RiscvRefinement.NonVacuity.honest_addi_holds",
    "RiscvRefinement.NonVacuity.addi_exists",
    "RiscvRefinement.Coverage.pilot_coverage_exact",
)
APPROVED_LEAN_AXIOMS = frozenset(
    {
        "propext",
        "Classical.choice",
        "Quot.sound",
    }
)
CLAIM_BOUNDARY = (
    "kernel-checked normalized LUI/ADDI AIR predicate to reviewed "
    "Sail expression capsule; serialized-M31 and generated-monad "
    "normalization theorems remain open"
)
NEGATIVE_CONTROLS = (
    "lui-free-low-limb",
    "addi-free-high-carry",
)
LIVE_SAIL_OPTIONS = (
    "sail_riscv_dir",
    "sail_bin",
    "sail_generated_file",
)
AUDIT_COMMAND = ("lake", "env", "lean", "RiscvRefinement/AxiomAudit.lean")
AUDITED_THEOREMS_BLOCK = re.compile(
    r"^AUDITED_THEOREMS = \(\n(?:    \"[^\"\\\n]+\",\n)+\)$",
    re.MULTILINE,
)
AUDITED_THEOREMS_REFRESH = (
    "refresh the pin with "
    "'python3 scripts/riscv_refinement.py audited-theorems --write' "
    "and review the diff"
)


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
    return render.artifacts(paths, evidence(args, paths))


def generate(args: argparse.Namespace, paths: Paths) -> None:
    outputs = prepared_outputs(args, paths)
    render.write_artifacts(paths, outputs)
    print(f"generated {len(outputs)} refinement artifacts")


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
        or manifest.get("canonical_digest") != codec.content_digest(manifest)
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


def _run(argv: list[str], cwd: Path, timeout: int = 600) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        output = exc.stdout.strip() if isinstance(exc, subprocess.CalledProcessError) else ""
        if len(output) > 8000:
            output = "... " + output[-8000:]
        raise RefinementError(
            f"command failed: {' '.join(argv)}" + (f"\n{output}" if output else "")
        ) from exc
    return completed.stdout


def _scan_forbidden_proof_terms(paths: Paths) -> None:
    forbidden = re.compile(r"\b(sorry|admit|axiom|unsafe|native_decide)\b")
    errors: list[str] = []
    sources = [
        paths.formal / "RiscvRefinement.lean",
        *sorted((paths.formal / "RiscvRefinement").rglob("*.lean")),
    ]
    for source in sources:
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("--", 1)[0]
            if forbidden.search(code):
                errors.append(f"{source.relative_to(paths.root)}:{number}")
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


def _render_audited_theorems(theorems: tuple[str, ...]) -> str:
    if not theorems:
        raise RefinementError("the axiom audit reported no refinement theorems")
    unquotable = sorted(
        theorem
        for theorem in theorems
        if not theorem or set(theorem) & set('"\\\n')
    )
    if unquotable:
        raise RefinementError(
            "audited theorem name cannot be pinned as a source literal: "
            + ", ".join(unquotable)
        )
    body = "".join(f'    "{theorem}",\n' for theorem in theorems)
    return f"AUDITED_THEOREMS = (\n{body})"


def _rewrite_audited_theorems(
    source: Path,
    theorems: tuple[str, ...],
) -> None:
    """Repin the audited theorem list in source, keeping it a reviewable diff."""
    text = source.read_text(encoding="utf-8")
    replacement = _render_audited_theorems(theorems)
    updated, count = AUDITED_THEOREMS_BLOCK.subn(
        lambda _: replacement,
        text,
        count=1,
    )
    if count != 1:
        raise RefinementError(
            f"{source}: the AUDITED_THEOREMS pin is not in its expected shape"
        )
    codec.atomic_write(source, updated.encode("utf-8"))


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
    source = args.pin_file or (paths.root / "scripts" / "riscv_refinement.py")
    _rewrite_audited_theorems(source, live)
    print(
        f"repinned {len(live)} audited theorems in "
        f"{source} (+{len(extra)}, -{len(missing)}); review the diff"
    )


@dataclass(frozen=True)
class Verification:
    theorem_axioms: dict[str, list[str]]


def verify(args: argparse.Namespace, paths: Paths) -> Verification:
    check_generated(args, paths)
    coverage(paths)
    negative_controls(paths)
    _scan_forbidden_proof_terms(paths)
    _run(
        [
            sys.executable,
            "-m",
            "unittest",
            "scripts.tests.test_riscv_refinement",
        ],
        paths.root,
    )
    _run(["lake", "build"], paths.formal)
    axiom_report = _audit_axioms(_run(list(AUDIT_COMMAND), paths.formal))
    print(
        "refinement pilot verified: fresh artifacts, 2/46 coverage, "
        "negative controls, unit tests, Lean build, and axiom audit"
    )
    return Verification(theorem_axioms=axiom_report)


def _tool(
    name: str,
    version_argv: list[str],
    cwd: Path,
) -> dict[str, str]:
    found = shutil.which(name)
    if found is None:
        raise RefinementError(f"required tool {name!r} is not on PATH")
    binary = Path(found).resolve()
    version = _run([str(binary), *version_argv], cwd).strip().splitlines()[0]
    return {
        "sha256": codec.sha256_file(binary),
        "version": version,
    }


def _toolchain(paths: Paths) -> dict[str, dict[str, str]]:
    python = Path(sys.executable).resolve()
    lean_path = Path(
        _run(["lake", "env", "which", "lean"], paths.formal).strip()
    ).resolve()
    if not lean_path.is_file():
        raise RefinementError("pinned Lean executable could not be resolved")
    return {
        "python": {
            "sha256": codec.sha256_file(python),
            "version": sys.version.split()[0],
        },
        "zig": _tool("zig", ["version"], paths.root),
        "lake": _tool("lake", ["--version"], paths.formal),
        "lean": {
            "sha256": codec.sha256_file(lean_path),
            "version": _run(
                [str(lean_path), "--version"],
                paths.formal,
            ).strip().splitlines()[0],
        },
    }


def _repository_state(paths: Paths) -> tuple[str, list[str]]:
    revision = _run(["git", "rev-parse", "HEAD"], paths.root).strip()
    status = _run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        paths.root,
    )
    receipt_path = paths.receipt.relative_to(paths.root).as_posix()
    dirty_paths = sorted(
        line[3:]
        for line in status.splitlines()
        if line and line[3:] != receipt_path
    )
    return revision, dirty_paths


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
    manifest = codec.load_json(paths.manifest)
    revision, dirty_paths = _repository_state(paths)
    if dirty_paths:
        raise RefinementError(
            "release receipt requires a clean repository; dirty paths: "
            + ", ".join(dirty_paths)
        )
    payload = {
        "schema_version": 1,
        "kind": "stwo-riscv-refinement-receipt",
        "tier": "level-1-normalized-pilot",
        "claim_boundary": CLAIM_BOUNDARY,
        "repository_revision": revision,
        "repository_dirty": bool(dirty_paths),
        "repository_dirty_paths": dirty_paths,
        "generated_manifest_digest": manifest["canonical_digest"],
        "opcodes": list(PILOT_OPCODES),
        "lean_build": "passed",
        "coverage": {
            "proved_normalized_opcodes": len(PILOT_OPCODES),
            "production_opcodes": FULL_OPCODE_COUNT,
        },
        "negative_controls": list(NEGATIVE_CONTROLS),
        "approved_lean_axioms": sorted(APPROVED_LEAN_AXIOMS),
        "theorem_axioms": verification.theorem_axioms,
        "proof_escape_scan": "passed",
        "toolchain": _toolchain(paths),
        "semantic_toolchain": sail.toolchain(sail_evidence),
    }
    payload["canonical_digest"] = codec.content_digest(payload)
    codec.atomic_write(paths.receipt, codec.pretty_bytes(payload))
    print(
        "refinement receipt: "
        f"{payload['canonical_digest']} "
        "(Level-1 LUI/ADDI, no unapproved axioms)"
    )


def _receipt_revision_matches(paths: Paths, revision: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise RefinementError("refinement receipt repository revision is invalid")
    current, dirty_paths = _repository_state(paths)
    if dirty_paths:
        raise RefinementError(
            "receipt verification requires a clean repository; dirty paths: "
            + ", ".join(dirty_paths)
        )
    if current == revision:
        return
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, current],
            cwd=paths.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        unchanged = subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                revision,
                current,
                "--",
                ".",
                f":(exclude){paths.receipt.relative_to(paths.root).as_posix()}",
            ],
            cwd=paths.root,
            check=False,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RefinementError(
            "could not validate refinement receipt repository revision"
        ) from exc
    if unchanged.returncode != 0:
        raise RefinementError(
            "repository changed beyond the committed refinement receipt"
        )


def _validate_receipt_theorem_axioms(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != set(AUDITED_THEOREMS)
    ):
        raise RefinementError("refinement receipt theorem set is invalid")
    for theorem, axioms in value.items():
        if (
            not isinstance(theorem, str)
            or not isinstance(axioms, list)
            or any(not isinstance(axiom, str) for axiom in axioms)
        ):
            raise RefinementError(
                "refinement receipt theorem-axiom schema is invalid"
            )


def _validate_receipt_numeric_identity(payload: dict[str, object]) -> None:
    coverage_value = payload.get("coverage")
    expected_coverage = {
        "proved_normalized_opcodes": len(PILOT_OPCODES),
        "production_opcodes": FULL_OPCODE_COUNT,
    }
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
        or not isinstance(coverage_value, dict)
        or set(coverage_value) != set(expected_coverage)
        or any(
            type(coverage_value[key]) is not int
            or coverage_value[key] != expected
            for key, expected in expected_coverage.items()
        )
    ):
        raise RefinementError(
            "refinement receipt numeric identity is invalid"
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
    required = {
        "approved_lean_axioms",
        "canonical_digest",
        "claim_boundary",
        "coverage",
        "generated_manifest_digest",
        "kind",
        "lean_build",
        "negative_controls",
        "opcodes",
        "proof_escape_scan",
        "repository_dirty",
        "repository_dirty_paths",
        "repository_revision",
        "schema_version",
        "semantic_toolchain",
        "theorem_axioms",
        "tier",
        "toolchain",
    }
    if set(payload) != required:
        raise RefinementError("refinement receipt schema drifted")
    _validate_receipt_numeric_identity(payload)
    _validate_receipt_theorem_axioms(payload["theorem_axioms"])
    verification = verify(args, paths)
    if (
        payload["kind"] != "stwo-riscv-refinement-receipt"
        or payload["tier"] != "level-1-normalized-pilot"
        or payload["claim_boundary"] != CLAIM_BOUNDARY
        or payload["canonical_digest"] != codec.content_digest(payload)
        or payload["opcodes"] != list(PILOT_OPCODES)
        or payload["negative_controls"] != list(NEGATIVE_CONTROLS)
        or payload["lean_build"] != "passed"
        or payload["proof_escape_scan"] != "passed"
        or payload["repository_dirty"] is not False
        or payload["repository_dirty_paths"] != []
        or payload["approved_lean_axioms"] != sorted(APPROVED_LEAN_AXIOMS)
        or payload["theorem_axioms"] != verification.theorem_axioms
    ):
        raise RefinementError("refinement receipt identity or theorem set is invalid")
    manifest = codec.load_json(paths.manifest)
    render.validate_committed_manifest(paths, manifest)
    coverage(paths)
    if (
        payload["generated_manifest_digest"] != manifest["canonical_digest"]
        or manifest.get("sail") != sail.provenance(evidence(args, paths))
    ):
        raise RefinementError("refinement receipt does not bind the current manifest")
    if payload["toolchain"] != _toolchain(paths):
        raise RefinementError(
            "refinement receipt does not bind the current proof toolchain"
        )
    if payload["semantic_toolchain"] != sail.toolchain(evidence(args, paths)):
        raise RefinementError(
            "refinement receipt does not bind the current Sail toolchain"
        )
    _receipt_revision_matches(paths, payload["repository_revision"])
    unexpected = {
        axiom
        for axioms in payload["theorem_axioms"].values()
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
    paths = Paths(root, air_ir_dir)
    try:
        if air_ir_dir is not None and not getattr(args, "no_export_air", False):
            raise RefinementError("--air-ir-dir requires --no-export-air")
        if args.command == "generate":
            generate(args, paths)
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
