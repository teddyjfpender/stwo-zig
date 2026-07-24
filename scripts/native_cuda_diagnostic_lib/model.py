"""Fixed workloads and bounded settings for Native CUDA cold diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


SCHEMA = "native_cuda_cold_diagnostic_v3"
EVIDENCE_CLASS = "diagnostic_cold_process_plan_and_stage_attributed"
PRODUCT = "stwo-native-cuda"
BACKEND = "cuda"
APPLICATION = "wide_fibonacci"
PROTOCOL = "raw-stwo-wide-v1"
EXCHANGE_MODE = "proof_exchange_json_wire_v1"
UPSTREAM_COMMIT = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"

MIN_COLD_SAMPLES = 1
MAX_COLD_SAMPLES = 30
MAX_TIMEOUT_SECONDS = 7200.0
MAX_COOLDOWN_SECONDS = 300.0
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 4 * 1024 * 1024
MAX_PROOF_ARTIFACT_BYTES = 256 * 1024 * 1024


class DiagnosticError(RuntimeError):
    """A CUDA diagnostic input or product result violated the contract."""


@dataclass(frozen=True, order=True)
class Shape:
    log_n_rows: int
    sequence_len: int

    @property
    def trace_rows(self) -> int:
        return 1 << self.log_n_rows

    @property
    def trace_cells(self) -> int:
        return self.trace_rows * self.sequence_len

    @property
    def slug(self) -> str:
        return f"log{self.log_n_rows}-width{self.sequence_len}"

    def statement(self) -> dict[str, int]:
        return {
            "log_n_rows": self.log_n_rows,
            "sequence_len": self.sequence_len,
            "trace_rows": self.trace_rows,
            "trace_cells": self.trace_cells,
        }


DEFAULT_SHAPES = (
    Shape(14, 100),
    Shape(16, 100),
    Shape(18, 100),
    Shape(20, 100),
    Shape(22, 100),
    Shape(20, 128),
    Shape(21, 128),
    Shape(22, 128),
)


@dataclass(frozen=True)
class Settings:
    product_bin: Path
    output_path: Path
    repo_root: Path
    cold_samples: int
    cooldown_seconds: float
    timeout_seconds: float
    device_ordinal: str
    shapes: tuple[Shape, ...] = DEFAULT_SHAPES
    execution_mode: str = "graphs"

    @property
    def artifact_root(self) -> Path:
        return self.output_path.with_name(f"{self.output_path.stem}.artifacts")

    def validate(self) -> None:
        if not MIN_COLD_SAMPLES <= self.cold_samples <= MAX_COLD_SAMPLES:
            raise DiagnosticError(
                f"cold samples must be in [{MIN_COLD_SAMPLES}, {MAX_COLD_SAMPLES}]"
            )
        if not 0.0 <= self.cooldown_seconds <= MAX_COOLDOWN_SECONDS:
            raise DiagnosticError(
                f"cooldown must be in [0, {MAX_COOLDOWN_SECONDS}] seconds"
            )
        if not 0.0 < self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise DiagnosticError(
                f"timeout must be in (0, {MAX_TIMEOUT_SECONDS}] seconds"
            )
        if not self.device_ordinal.isdecimal():
            raise DiagnosticError("CUDA device ordinal must be a decimal integer")
        if self.execution_mode not in ("graphs", "direct"):
            raise DiagnosticError("CUDA execution mode must be graphs or direct")
        if not self.shapes or len(set(self.shapes)) != len(self.shapes):
            raise DiagnosticError("diagnostic shapes must be nonempty and unique")
        for shape in self.shapes:
            if not 3 <= shape.log_n_rows <= 22:
                raise DiagnosticError(f"unsupported log size: {shape.log_n_rows}")
            if not 3 <= shape.sequence_len <= 128:
                raise DiagnosticError(
                    f"unsupported sequence length: {shape.sequence_len}"
                )
