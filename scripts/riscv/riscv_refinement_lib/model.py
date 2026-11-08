"""Pinned inputs and repository paths for the RISC-V refinement pilot."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 2
SAIL_REPOSITORY = "https://github.com/riscv/sail-riscv"
SAIL_REVISION = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f"
SAIL_VERSION = "0.20.2"
LEAN_TOOLCHAIN = "leanprover/lean4:v4.29.0"
M31_MODULUS = (1 << 31) - 1

PILOT_OPCODES = ("lui", "addi")
FULL_OPCODE_COUNT = 46


class RefinementError(RuntimeError):
    """A pinned input, generated artifact, or proof contract is invalid."""


@dataclass(frozen=True)
class Paths:
    root: Path
    uniqueness_ir_override: Path | None = None
    air_program_ir_override: Path | None = None

    @property
    def uniqueness_ir(self) -> Path:
        if self.uniqueness_ir_override is not None:
            if self.uniqueness_ir_override.is_absolute():
                return self.uniqueness_ir_override
            return self.root / self.uniqueness_ir_override
        return self.root / "zig-out" / "uniqueness-ir"

    @property
    def air_program_ir(self) -> Path:
        if self.air_program_ir_override is not None:
            if self.air_program_ir_override.is_absolute():
                return self.air_program_ir_override
            return self.root / self.air_program_ir_override
        return self.root / "zig-out" / "refinement-air-ir-v2"

    @property
    def formal(self) -> Path:
        return self.root / "formal" / "riscv-refinement"

    @property
    def generated_air(self) -> Path:
        return self.formal / "generated" / "air"

    @property
    def generated_lean_air(self) -> Path:
        return (
            self.formal
            / "RiscvRefinement"
            / "Air"
            / "Generated"
            / "Pilot.lean"
        )

    @property
    def generated_lean_sail(self) -> Path:
        return (
            self.formal
            / "RiscvRefinement"
            / "Sail"
            / "Generated"
            / "Pilot.lean"
        )

    @property
    def manifest(self) -> Path:
        return self.formal / "generated-manifest.json"

    @property
    def receipt(self) -> Path:
        return self.formal / "refinement-receipt.json"


def repository_root(start: Path | None = None) -> Path:
    candidate = (start or Path(__file__)).resolve()
    for parent in (candidate, *candidate.parents):
        if (parent / "build.zig").is_file() and (parent / ".git").exists():
            return parent
    raise RefinementError("could not locate the stwo-zig repository root")
