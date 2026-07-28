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


def common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sail-riscv-dir", type=Path)
    parser.add_argument("--sail-bin", type=Path)
    parser.add_argument("--sail-generated-file", type=Path)
    parser.add_argument(
        "--no-export-air",
        action="store_true",
        help="reuse zig-out/uniqueness-ir instead of invoking the Zig extractor",
    )


def evidence(args: argparse.Namespace, paths: Paths) -> sail.SailEvidence:
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
    for source in sorted((paths.formal / "RiscvRefinement").rglob("*.lean")):
        for number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            code = line.split("--", 1)[0]
            if forbidden.search(code):
                errors.append(f"{source.relative_to(paths.root)}:{number}")
    if errors:
        raise RefinementError(
            "forbidden proof escape appears at " + ", ".join(errors)
        )


def _audit_axioms(output: str) -> dict[str, list[str]]:
    dependency_pattern = re.compile(
        r"^'(?P<theorem>[^']+)' depends on axioms: "
        r"\[(?P<axioms>[^\]]*)\]$"
    )
    empty_pattern = re.compile(
        r"^'(?P<theorem>[^']+)' does not depend on any axioms$"
    )
    report: dict[str, list[str]] = {}
    for line in output.splitlines():
        stripped = line.strip()
        match = dependency_pattern.fullmatch(stripped)
        if match is not None:
            theorem = match.group("theorem")
            axioms = [
                axiom.strip()
                for axiom in match.group("axioms").split(",")
                if axiom.strip()
            ]
            report[theorem] = axioms
            continue
        match = empty_pattern.fullmatch(stripped)
        if match is not None:
            report[match.group("theorem")] = []
    missing = sorted(set(AUDITED_THEOREMS) - set(report))
    extra = sorted(set(report) - set(AUDITED_THEOREMS))
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise RefinementError("axiom audit coverage drifted: " + "; ".join(details))
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
    return {theorem: report[theorem] for theorem in AUDITED_THEOREMS}


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
    audit_output = _run(
        [
            "lake",
            "env",
            "lean",
            "RiscvRefinement/AxiomAudit.lean",
        ],
        paths.formal,
    )
    axiom_report = _audit_axioms(audit_output)
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
    verification = verify(args, paths)
    manifest = codec.load_json(paths.manifest)
    revision, dirty_paths = _repository_state(paths)
    payload = {
        "schema_version": 1,
        "kind": "stwo-riscv-refinement-receipt",
        "tier": "level-1-normalized-pilot",
        "claim_boundary": (
            "kernel-checked normalized LUI/ADDI AIR predicate to reviewed "
            "Sail expression capsule; serialized-M31 and generated-monad "
            "normalization theorems remain open"
        ),
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
        "negative_controls": [
            "lui-free-low-limb",
            "addi-free-high-carry",
        ],
        "approved_lean_axioms": sorted(APPROVED_LEAN_AXIOMS),
        "theorem_axioms": verification.theorem_axioms,
        "proof_escape_scan": "passed",
        "toolchain": _toolchain(paths),
    }
    payload["canonical_digest"] = codec.content_digest(payload)
    codec.atomic_write(paths.receipt, codec.pretty_bytes(payload))
    print(
        "refinement receipt: "
        f"{payload['canonical_digest']} "
        "(Level-1 LUI/ADDI, no unapproved axioms)"
    )


def verify_receipt(paths: Paths) -> None:
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
        "theorem_axioms",
        "tier",
        "toolchain",
    }
    if set(payload) != required:
        raise RefinementError("refinement receipt schema drifted")
    if (
        payload["kind"] != "stwo-riscv-refinement-receipt"
        or payload["schema_version"] != 1
        or payload["tier"] != "level-1-normalized-pilot"
        or payload["canonical_digest"] != codec.content_digest(payload)
        or payload["opcodes"] != list(PILOT_OPCODES)
        or payload["approved_lean_axioms"] != sorted(APPROVED_LEAN_AXIOMS)
        or set(payload["theorem_axioms"]) != set(AUDITED_THEOREMS)
    ):
        raise RefinementError("refinement receipt identity or theorem set is invalid")
    manifest = codec.load_json(paths.manifest)
    if (
        manifest.get("tier") != "level-1-normalized-pilot"
        or payload["generated_manifest_digest"] != manifest["canonical_digest"]
    ):
        raise RefinementError("refinement receipt does not bind the current manifest")
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
    commands.add_parser("negative-controls")
    commands.add_parser("verify-receipt")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    paths = Paths(repository_root())
    try:
        if args.command == "generate":
            generate(args, paths)
        elif args.command == "check-generated":
            check_generated(args, paths)
        elif args.command == "coverage":
            coverage(paths, args.require_full)
        elif args.command == "negative-controls":
            negative_controls(paths)
        elif args.command == "prepare-sail":
            prepare_sail(args, paths)
        elif args.command == "verify":
            verify(args, paths)
        elif args.command == "receipt":
            receipt(args, paths)
        elif args.command == "verify-receipt":
            verify_receipt(paths)
        else:
            raise AssertionError(args.command)
    except RefinementError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
