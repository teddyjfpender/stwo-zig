"""Render deterministic AIR packages, Lean capsules, and their manifest."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from . import (
    air,
    air_program,
    air_program_lean as air_program_lean_source,
    air_program_registry_lean,
    codec,
    sail,
)
from .model import LEAN_TOOLCHAIN, PILOT_OPCODES, SCHEMA_VERSION, Paths, RefinementError

SOURCE_PATHS = (
    "build.zig",
    "build.zig.zon",
    "build_support/build.zig.zon",
    "build_support/graph/delegation.zig",
    "build_support/internal_build.zig",
    "build_support/products/catalog.zig",
    "build_support/products/matrix.zig",
    "build_support/products/package_dependencies.zig",
    "build_support/products/product_specs.zig",
    "build_support/products/riscv_cpu.zig",
    "build_support/products/riscv_refinement.zig",
    "build_support/products/riscv_test_filter.zig",
    "src/core/build.zig",
    "src/core/build.zig.zon",
    "src/core/mod.zig",
    "src/frontends/riscv/refinement_ir_export_test.zig",
    "src/frontends/riscv/refinement_program_export_test.zig",
)
SOURCE_TREES = (
    "build_support/graph",
    "src/core/fields",
    "src/frontends/riscv",
)

GENERATOR_PATHS = (
    "scripts/riscv_refinement.py",
    "scripts/riscv_refinement_lib/model.py",
    "scripts/riscv_refinement_lib/codec.py",
    "scripts/riscv_refinement_lib/air.py",
    "scripts/riscv_refinement_lib/air_program.py",
    "scripts/riscv_refinement_lib/air_program_contract.py",
    "scripts/riscv_refinement_lib/air_program_lean.py",
    "scripts/riscv_refinement_lib/air_program_registry_lean.py",
    "scripts/riscv_refinement_lib/sail.py",
    "scripts/riscv_refinement_lib/negative.py",
    "scripts/riscv_refinement_lib/render.py",
    "scripts/tests/test_riscv_refinement.py",
)

PROOF_PATHS = (
    "formal/riscv-refinement/README.md",
    "formal/riscv-refinement/lean-toolchain",
    "formal/riscv-refinement/lake-manifest.json",
    "formal/riscv-refinement/lakefile.toml",
    "formal/riscv-refinement/RiscvRefinement.lean",
    "formal/riscv-refinement/RiscvRefinement/Common.lean",
    "formal/riscv-refinement/RiscvRefinement/Air.lean",
    "formal/riscv-refinement/RiscvRefinement/Air/Decode.lean",
    "formal/riscv-refinement/RiscvRefinement/Air/Eval.lean",
    "formal/riscv-refinement/RiscvRefinement/Air/IR.lean",
    "formal/riscv-refinement/RiscvRefinement/Air/LocalEval.lean",
    "formal/riscv-refinement/RiscvRefinement/Air/Tests.lean",
    "formal/riscv-refinement/RiscvRefinement/Bridge/Decode.lean",
    "formal/riscv-refinement/RiscvRefinement/Field.lean",
    "formal/riscv-refinement/RiscvRefinement/Field/M31.lean",
    "formal/riscv-refinement/RiscvRefinement/Opcodes/Lui.lean",
    "formal/riscv-refinement/RiscvRefinement/Opcodes/Addi.lean",
    "formal/riscv-refinement/RiscvRefinement/NonVacuity.lean",
    "formal/riscv-refinement/RiscvRefinement/Coverage.lean",
    "formal/riscv-refinement/RiscvRefinement/AxiomAudit.lean",
    "formal/riscv-refinement/RiscvRefinement/Tables.lean",
    "formal/riscv-refinement/RiscvRefinement/Tables/Fixed.lean",
    "soundness/AIR_IR_V2_CONTRACT.md",
    "soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md",
    "soundness/air-ir-v2.schema.json",
)

EXPORTED_FAMILIES = frozenset(
    {
        "auipc",
        "base_alu_imm",
        "base_alu_reg",
        "branch_eq",
        "branch_lt",
        "div",
        "fence",
        "jal",
        "jalr",
        "load_store",
        "lt_imm",
        "lt_reg",
        "lui",
        "mul",
        "mulh",
        "shifts_imm",
        "shifts_reg",
    }
)
MANIFEST_ARTIFACTS = frozenset(
    {
        "RiscvRefinement/Air/Generated/Pilot.lean",
        "RiscvRefinement/Air/Generated/LuiProgram.lean",
        "RiscvRefinement/Air/Generated/Programs.lean",
        "RiscvRefinement/Sail/Generated/Pilot.lean",
        "generated/air/addi.json",
        "generated/air/lui.json",
        "generated/sail/rv32im-zkvm-v1.json",
        *(
            f"generated/air/{mnemonic}.air-ir-v2.json"
            for _, mnemonic, _ in air_program.OPCODES
        ),
    }
)

AIR_LEAN_TEMPLATE = """\
-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Regenerate: python3 scripts/riscv_refinement.py generate
-- Production binding: symbolic collector plus exact structural validation.
-- Boundary: normalized predicate; LUI AIR IR v2 is bound in LuiProgram.lean.

import RiscvRefinement.Common

namespace RiscvRefinement.Air.Generated

open RiscvRefinement

def luiAirDigest : String := "__LUI_DIGEST__"

def addiAirDigest : String := "__ADDI_DIGEST__"

def luiImmediate
    (imm0 : BitVec 4)
    (imm1 imm2 : BitVec 8) :
    BitVec 20 :=
  imm2.append (imm1.append imm0)

def luiResult
    (imm0 : BitVec 4)
    (imm1 imm2 : BitVec 8) :
    Word :=
  (luiImmediate imm0 imm1 imm2).append (BitVec.ofNat 12 0)

def luiResultBytes
    (imm0 : BitVec 4)
    (imm1 imm2 : BitVec 8) :
    WordBytes where
  limb0 := BitVec.ofNat 8 0
  limb1 := imm0.append (BitVec.ofNat 4 0)
  limb2 := imm1
  limb3 := imm2

structure LuiRow where
  pc : Word
  clock : Nat
  rd : RegisterIndex
  rdPreviousClock : Nat
  rdPrevious : WordBytes
  rdNext : WordBytes
  imm0 : BitVec 4
  imm1 : BitVec 8
  imm2 : BitVec 8
  rdNonzero : Bool
  claimedNextPc : Word
deriving DecidableEq, Repr

structure LuiHolds (row : LuiRow) : Prop where
  clockPositive : 0 < row.clock
  destinationClock :
    validPreviousClock
      row.rdPreviousClock
      (accessClock row.clock 1)
  destinationFlag :
    row.rdNonzero = decide (row.rd ≠ zeroRegister)
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.rdNonzero
      then (luiResultBytes row.imm0 row.imm1 row.imm2).limb0
      else WordBytes.zero.limb0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.rdNonzero
      then (luiResultBytes row.imm0 row.imm1 row.imm2).limb1
      else WordBytes.zero.limb1
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.rdNonzero
      then (luiResultBytes row.imm0 row.imm1 row.imm2).limb2
      else WordBytes.zero.limb2
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.rdNonzero
      then (luiResultBytes row.imm0 row.imm1 row.imm2).limb3
      else WordBytes.zero.limb3
  nextPcResult : row.claimedNextPc = nextPc row.pc

def luiRetirement (row : LuiRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.rd row.rdNext.word

def luiProgramTuple (row : LuiRow) : ProgramTuple where
  pc := row.pc
  opcodeId := 35
  rd := row.rd.toNat
  rs1 := (luiImmediate row.imm0 row.imm1 row.imm2).toNat
  operand := 0

structure LuiRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def luiRelations (row : LuiRow) : LuiRelations where
  program := luiProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  destinationConsume := {
    addr := row.rd
    clock := row.rdPreviousClock
    value := row.rdPrevious.word
  }
  destinationEmit := {
    addr := row.rd
    clock := accessClock row.clock 1
    value := row.rdNext.word
  }

def addiImmediate
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    BitVec 12 :=
  sign.append (imm1.append imm0)

def addiImmediateValue
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    Nat :=
  imm0.toNat +
    256 * (imm1.toNat + 248 * sign.toNat) +
    65536 * (255 * sign.toNat) +
    16777216 * (255 * sign.toNat)

def addiAirImmediate
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    Word :=
  BitVec.ofNat 32 (addiImmediateValue imm0 imm1 sign)

def addiResult
    (source : Word)
    (imm0 : BitVec 8)
    (imm1 : BitVec 3)
    (sign : BitVec 1) :
    Word :=
  source + addiAirImmediate imm0 imm1 sign

structure AddiRow where
  pc : Word
  clock : Nat
  rd : RegisterIndex
  rdPreviousClock : Nat
  rdPrevious : WordBytes
  rdNext : WordBytes
  rs1 : RegisterIndex
  rs1PreviousClock : Nat
  rs1Previous : WordBytes
  rs1Next : WordBytes
  imm0 : BitVec 8
  imm1 : BitVec 3
  immSign : BitVec 1
  result : WordBytes
  rdNonzero : Bool
  claimedNextPc : Word
deriving DecidableEq, Repr

structure AddiHolds (row : AddiRow) : Prop where
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock
      row.rs1PreviousClock
      (accessClock row.clock 1)
  destinationClock :
    validPreviousClock
      row.rdPreviousClock
      (accessClock row.clock 2)
  sourceLimb0 : row.rs1Next.limb0 = row.rs1Previous.limb0
  sourceLimb1 : row.rs1Next.limb1 = row.rs1Previous.limb1
  sourceLimb2 : row.rs1Next.limb2 = row.rs1Previous.limb2
  sourceLimb3 : row.rs1Next.limb3 = row.rs1Previous.limb3
  carryRecurrence :
    ∃ carry1 carry2 carry3 carry4 : BitVec 1,
      row.rs1Next.limb0.toNat + row.imm0.toNat =
          row.result.limb0.toNat + 256 * carry1.toNat ∧
      row.rs1Next.limb1.toNat +
            (row.imm1.toNat + 248 * row.immSign.toNat) +
            carry1.toNat =
          row.result.limb1.toNat + 256 * carry2.toNat ∧
      row.rs1Next.limb2.toNat +
            255 * row.immSign.toNat +
            carry2.toNat =
          row.result.limb2.toNat + 256 * carry3.toNat ∧
      row.rs1Next.limb3.toNat +
            255 * row.immSign.toNat +
            carry3.toNat =
          row.result.limb3.toNat + 256 * carry4.toNat
  destinationFlag :
    row.rdNonzero = decide (row.rd ≠ zeroRegister)
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.rdNonzero then row.result.limb0 else WordBytes.zero.limb0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.rdNonzero then row.result.limb1 else WordBytes.zero.limb1
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.rdNonzero then row.result.limb2 else WordBytes.zero.limb2
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.rdNonzero then row.result.limb3 else WordBytes.zero.limb3
  nextPcResult : row.claimedNextPc = nextPc row.pc

def addiRetirement (row : AddiRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.rd row.rdNext.word

def addiProgramTuple (row : AddiRow) : ProgramTuple where
  pc := row.pc
  opcodeId := 10
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := (addiImmediate row.imm0 row.imm1 row.immSign).toNat

structure AddiRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  sourceConsume : RegisterTuple
  sourceEmit : RegisterTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def addiRelations (row : AddiRow) : AddiRelations where
  program := addiProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  sourceConsume := {
    addr := row.rs1
    clock := row.rs1PreviousClock
    value := row.rs1Previous.word
  }
  sourceEmit := {
    addr := row.rs1
    clock := accessClock row.clock 1
    value := row.rs1Next.word
  }
  destinationConsume := {
    addr := row.rd
    clock := row.rdPreviousClock
    value := row.rdPrevious.word
  }
  destinationEmit := {
    addr := row.rd
    clock := accessClock row.clock 2
    value := row.rdNext.word
  }

end RiscvRefinement.Air.Generated
"""

SAIL_LEAN_TEMPLATE = """\
-- GENERATED FILE. DO NOT EDIT.
-- Generator: scripts/riscv_refinement.py
-- Regenerate: python3 scripts/riscv_refinement.py generate
-- Source: exact-profile Sail 0.20.2 theorem-backend definition slices.
-- Boundary: reviewed normalized capsule; no generated-monad theorem yet.

import RiscvRefinement.Common

namespace RiscvRefinement.Sail.Generated

open RiscvRefinement

def executeUtypeDefinitionDigest : String :=
  "__UTYPE_DIGEST__"

def executeItypeDefinitionDigest : String :=
  "__ITYPE_DIGEST__"

def executeLuiValue (imm : BitVec 20) : Word :=
  BitVec.signExtend 32 (imm.append (BitVec.ofNat 12 0))

def executeAddiValue (source : Word) (imm : BitVec 12) : Word :=
  source + BitVec.signExtend 32 imm

def executeLui
    (pc : Word)
    (rd : RegisterIndex)
    (imm : BitVec 20) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeLuiValue imm)

def executeAddi
    (pc : Word)
    (source : Word)
    (rd : RegisterIndex)
    (imm : BitVec 12) :
    Retirement where
  nextPc := nextPc pc
  write := architecturalWrite rd (executeAddiValue source imm)

end RiscvRefinement.Sail.Generated
"""


def _source_digests(paths: Paths) -> dict[str, str]:
    result: dict[str, str] = {}
    relatives = set(SOURCE_PATHS)
    for tree in SOURCE_TREES:
        root = paths.root / tree
        if not root.is_dir():
            raise RefinementError(f"missing production source tree {tree}")
        try:
            listed = subprocess.run(
                [
                    "git",
                    "ls-files",
                    "-z",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                    "--",
                    tree,
                ],
                cwd=paths.root,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RefinementError(
                f"could not enumerate version-controlled source tree {tree}"
            ) from exc
        try:
            relatives.update(
                entry.decode("utf-8")
                for entry in listed.split(b"\0")
                if entry
            )
        except UnicodeDecodeError as exc:
            raise RefinementError(
                f"source tree {tree} contains a non-UTF-8 path"
            ) from exc
    for relative in sorted(relatives):
        path = paths.root / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(f"missing production source {relative}")
        result[relative] = codec.sha256_file(path)
    return result


def _generator_digests(paths: Paths) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in GENERATOR_PATHS:
        path = paths.root / relative
        if not path.is_file():
            raise RefinementError(f"missing generator source {relative}")
        result[relative] = codec.sha256_file(path)
    return result


def _proof_digests(paths: Paths) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in PROOF_PATHS:
        path = paths.root / relative
        if not path.is_file():
            raise RefinementError(f"missing proof source {relative}")
        result[relative] = codec.sha256_file(path)
    return result


def validate_air_export(directory: Path) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise RefinementError(f"AIR export is not a directory: {directory}")
    entries = list(directory.iterdir())
    invalid = [
        path.name
        for path in entries
        if path.is_symlink() or not path.is_file() or path.suffix != ".json"
    ]
    if invalid:
        raise RefinementError(
            "production AIR export emitted unexpected entries: "
            + ", ".join(sorted(invalid))
        )
    actual = {path.stem for path in entries}
    if actual != EXPORTED_FAMILIES:
        missing = sorted(EXPORTED_FAMILIES - actual)
        extra = sorted(actual - EXPORTED_FAMILIES)
        raise RefinementError(
            "production AIR export coverage drifted: "
            f"missing={missing}, extra={extra}"
        )
    for family in EXPORTED_FAMILIES:
        artifact = directory / f"{family}.json"
        if artifact.stat().st_size == 0:
            raise RefinementError(
                f"production AIR export {artifact.name} is empty"
            )


def validate_air_program_export(directory: Path) -> dict[str, dict[str, Any]]:
    if directory.is_symlink() or not directory.is_dir():
        raise RefinementError(
            f"production AIR IR v2 export is not a directory: {directory}"
        )
    entries = list(directory.iterdir())
    expected_names = {
        f"{mnemonic}.unsigned.json"
        for _, mnemonic, _ in air_program.OPCODES
    }
    actual_names = {entry.name for entry in entries}
    if actual_names != expected_names or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        raise RefinementError(
            "production AIR IR v2 export coverage drifted: "
            f"missing={sorted(expected_names - actual_names)}, "
            f"extra={sorted(actual_names - expected_names)}"
        )
    result: dict[str, dict[str, Any]] = {}
    for manifest_id, mnemonic, family in air_program.OPCODES:
        artifact = directory / f"{mnemonic}.unsigned.json"
        payload = codec.load_json(artifact)
        if set(payload) != air_program.UNSIGNED_TOP_LEVEL_KEYS:
            raise RefinementError(
                f"{artifact.name}: unsigned semantic schema drifted"
            )
        if artifact.read_bytes() != codec.canonical_bytes(payload):
            raise RefinementError(
                f"{artifact.name}: unsigned semantic JSON is not canonical"
            )
        selector = payload.get("opcode_selector")
        if (
            payload.get("family") != family
            or not isinstance(selector, dict)
            or set(selector) != {"expression", "manifest_id", "mnemonic"}
            or selector.get("manifest_id") != manifest_id
            or selector.get("mnemonic") != mnemonic
        ):
            raise RefinementError(
                f"{artifact.name}: manifest/family selector drifted"
            )
        result[mnemonic] = payload
    return result


def export_air(paths: Paths) -> None:
    output_parent = paths.root / "zig-out"
    output_parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(
            prefix="riscv-refinement-ir.",
            dir=output_parent,
        )
    )
    program_staging = Path(
        tempfile.mkdtemp(
            prefix="riscv-air-program-ir.",
            dir=output_parent,
        )
    )
    try:
        subprocess.run(
            [
                "zig",
                "build",
                "riscv-refinement-ir",
                f"-Driscv-refinement-ir-dir={staging}",
                f"-Driscv-air-program-ir-dir={program_staging}",
            ],
            cwd=paths.root,
            check=True,
            timeout=600,
        )
        validate_air_export(staging)
        validate_air_program_export(program_staging)
        target = paths.uniqueness_ir
        program_target = paths.air_program_ir
        if target.resolve() == program_target.resolve():
            raise RefinementError("symbolic and AIR IR v2 targets must differ")
        if target.is_symlink():
            raise RefinementError(f"refusing symbolic-link AIR target {target}")
        if target.exists():
            if not target.is_dir():
                raise RefinementError(f"AIR target is not a directory: {target}")
            shutil.rmtree(target)
        if program_target.is_symlink():
            raise RefinementError(
                f"refusing symbolic-link AIR IR v2 target {program_target}"
            )
        if program_target.exists():
            if not program_target.is_dir():
                raise RefinementError(
                    f"AIR IR v2 target is not a directory: {program_target}"
                )
            shutil.rmtree(program_target)
        staging.replace(target)
        program_staging.replace(program_target)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise RefinementError("production AIR export failed") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging)
        if program_staging.exists():
            shutil.rmtree(program_staging)


def artifacts(paths: Paths, evidence: sail.SailEvidence) -> dict[Path, bytes]:
    source_digests = _source_digests(paths)
    unsigned_air_programs = validate_air_program_export(paths.air_program_ir)
    air_programs = {
        mnemonic: air_program.package_unsigned(payload, paths.root)
        for mnemonic, payload in unsigned_air_programs.items()
    }
    for mnemonic, payload in air_programs.items():
        air_program.verify_production_binding(
            payload,
            unsigned_air_programs[mnemonic],
            paths.root,
        )
    air_program_bytes = {
        mnemonic: codec.canonical_bytes(payload)
        for mnemonic, payload in air_programs.items()
    }
    packaged = {
        opcode: air.package_air(
            paths.uniqueness_ir
            / ("lui.json" if opcode == "lui" else "base_alu_imm.json"),
            opcode,
            source_digests,
        )
        for opcode in PILOT_OPCODES
    }
    air_outputs = {
        Path("generated/air") / f"{opcode}.json": codec.pretty_bytes(payload)
        for opcode, payload in packaged.items()
    }
    air_lean = (
        AIR_LEAN_TEMPLATE.replace(
            "__LUI_DIGEST__", packaged["lui"]["canonical_digest"]
        )
        .replace("__ADDI_DIGEST__", packaged["addi"]["canonical_digest"])
        .encode("utf-8")
    )
    air_program_lean = air_program_lean_source.AIR_PROGRAM_LEAN_TEMPLATE.replace(
        "__LUI_PROGRAM_JSON__",
        codec.canonical_bytes(air_program_bytes["lui"].decode("ascii")).decode(
            "ascii"
        ),
    ).encode("utf-8")
    air_program_registry = air_program_registry_lean.render(
        air_program_bytes,
        air_program.OPCODES,
    )
    sail_lean = (
        SAIL_LEAN_TEMPLATE.replace(
            "__UTYPE_DIGEST__",
            evidence.definition_hashes["execute_UTYPE"],
        )
        .replace(
            "__ITYPE_DIGEST__",
            evidence.definition_hashes["execute_ITYPE"],
        )
        .encode("utf-8")
    )
    outputs: dict[Path, bytes] = {
        **air_outputs,
        **{
            Path("generated/air") / f"{mnemonic}.air-ir-v2.json": data
            for mnemonic, data in air_program_bytes.items()
        },
        Path("generated/sail/rv32im-zkvm-v1.json"):
            evidence.exact_configuration,
        Path("RiscvRefinement/Air/Generated/Pilot.lean"): air_lean,
        Path("RiscvRefinement/Air/Generated/LuiProgram.lean"):
            air_program_lean,
        Path("RiscvRefinement/Air/Generated/Programs.lean"):
            air_program_registry,
        Path("RiscvRefinement/Sail/Generated/Pilot.lean"): sail_lean,
    }
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "stwo-riscv-refinement-generated-manifest",
        "tier": "level-1-normalized-pilot",
        "claim_boundary": {
            "lui_air_ir_v2_roundtrip": True,
            "lean_serialized_m31_air_interpreter": True,
            "lean_generated_sail_monad_normalization": False,
            "kernel_checked_normalized_refinement": True,
        },
        "lean_toolchain": LEAN_TOOLCHAIN,
        "opcodes": [
            {
                "id": 35 if opcode == "lui" else 10,
                "mnemonic": opcode,
                "coverage_kind": "normalized-predicate",
                "air_digest": packaged[opcode]["canonical_digest"],
                "refinement_theorem": (
                    "RiscvRefinement.Opcodes.lui_refines"
                    if opcode == "lui"
                    else "RiscvRefinement.Opcodes.addi_refines"
                ),
                "non_vacuity_theorem": (
                    "RiscvRefinement.NonVacuity.lui_exists"
                    if opcode == "lui"
                    else "RiscvRefinement.NonVacuity.addi_exists"
                ),
            }
            for opcode in PILOT_OPCODES
        ],
        "production_sources": source_digests,
        "generators": _generator_digests(paths),
        "proof_sources": _proof_digests(paths),
        "sail": sail.provenance(evidence),
        "artifacts": {
            relative.as_posix(): codec.sha256_bytes(data)
            for relative, data in sorted(
                outputs.items(), key=lambda item: item[0].as_posix()
            )
        },
    }
    manifest["canonical_digest"] = codec.content_digest(manifest)
    outputs[Path("generated-manifest.json")] = codec.pretty_bytes(manifest)
    return outputs


def write_artifacts(paths: Paths, outputs: dict[Path, bytes]) -> None:
    ordered = sorted(
        outputs.items(),
        key=lambda item: (
            item[0] == Path("generated-manifest.json"),
            item[0].as_posix(),
        ),
    )
    for relative, data in ordered:
        destination = paths.formal / relative
        if destination.is_file() and destination.read_bytes() == data:
            continue
        codec.atomic_write(destination, data)


def check_artifacts(paths: Paths, outputs: dict[Path, bytes]) -> None:
    errors: list[str] = []
    for relative, expected in outputs.items():
        destination = paths.formal / relative
        if not destination.is_file():
            errors.append(f"missing generated artifact {relative}")
        elif destination.read_bytes() != expected:
            errors.append(f"generated artifact drifted: {relative}")
    if errors:
        raise RefinementError("; ".join(errors))


def validate_committed_manifest(
    paths: Paths,
    manifest: dict[str, Any],
) -> None:
    if set(manifest) != {
        "artifacts",
        "canonical_digest",
        "claim_boundary",
        "generators",
        "kind",
        "lean_toolchain",
        "opcodes",
        "production_sources",
        "proof_sources",
        "sail",
        "schema_version",
        "tier",
    }:
        raise RefinementError("generated refinement manifest schema drifted")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("kind")
        != "stwo-riscv-refinement-generated-manifest"
        or manifest.get("tier") != "level-1-normalized-pilot"
        or manifest.get("lean_toolchain") != LEAN_TOOLCHAIN
        or manifest.get("claim_boundary")
        != {
            "lui_air_ir_v2_roundtrip": True,
            "lean_serialized_m31_air_interpreter": True,
            "lean_generated_sail_monad_normalization": False,
            "kernel_checked_normalized_refinement": True,
        }
        or manifest.get("canonical_digest") != codec.content_digest(manifest)
    ):
        raise RefinementError("generated refinement manifest identity is invalid")
    if manifest.get("production_sources") != _source_digests(paths):
        raise RefinementError(
            "generated refinement manifest production-source closure drifted"
        )
    if manifest.get("generators") != _generator_digests(paths):
        raise RefinementError(
            "generated refinement manifest generator closure drifted"
        )
    if manifest.get("proof_sources") != _proof_digests(paths):
        raise RefinementError(
            "generated refinement manifest proof-source closure drifted"
        )
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != MANIFEST_ARTIFACTS:
        raise RefinementError("generated refinement artifact closure drifted")
    for relative, expected in artifacts.items():
        if (
            not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
        ):
            raise RefinementError(
                f"generated refinement artifact digest is invalid: {relative}"
            )
        path = paths.formal / relative
        if path.is_symlink() or not path.is_file():
            raise RefinementError(
                f"generated refinement artifact is missing: {relative}"
            )
        if codec.sha256_file(path) != expected:
            raise RefinementError(
                f"generated refinement artifact digest drifted: {relative}"
            )
