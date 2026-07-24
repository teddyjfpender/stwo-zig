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
XOR_APPLICATION = "xor"
XOR_PROTOCOL = "raw-stwo-xor-v1"
PLONK_APPLICATION = "plonk"
PLONK_PROTOCOL = "raw-stwo-plonk-v1"
BLAKE_APPLICATION = "blake"
BLAKE_PROTOCOL = "raw-stwo-blake-v1"
POSEIDON_APPLICATION = "poseidon"
POSEIDON_PROTOCOL = "raw-stwo-poseidon-v1"
STATE_MACHINE_APPLICATION = "state_machine"
STATE_MACHINE_PROTOCOL = "raw-stwo-state-machine-v1"
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

    @property
    def application(self) -> str:
        return APPLICATION

    @property
    def protocol(self) -> str:
        return PROTOCOL

    @property
    def artifact_statement_key(self) -> str:
        return "wide_fibonacci_statement"

    def artifact_statement(self) -> dict[str, int]:
        return {
            "log_n_rows": self.log_n_rows,
            "sequence_len": self.sequence_len,
        }

    def cli_shape_args(self) -> list[str]:
        return [
            "--log-n-rows",
            str(self.log_n_rows),
            "--sequence-len",
            str(self.sequence_len),
        ]

    def validate(self) -> None:
        if not 3 <= self.log_n_rows <= 22:
            raise DiagnosticError(f"unsupported log size: {self.log_n_rows}")
        if not 3 <= self.sequence_len <= 128:
            raise DiagnosticError(
                f"unsupported sequence length: {self.sequence_len}"
            )


@dataclass(frozen=True, order=True)
class XorShape:
    log_size: int
    log_step: int
    offset: int

    @property
    def trace_rows(self) -> int:
        return 1 << self.log_size

    @property
    def trace_cells(self) -> int:
        return self.trace_rows * 3

    @property
    def slug(self) -> str:
        return f"log{self.log_size}-step{self.log_step}-offset{self.offset}"

    @property
    def application(self) -> str:
        return XOR_APPLICATION

    @property
    def protocol(self) -> str:
        return XOR_PROTOCOL

    @property
    def artifact_statement_key(self) -> str:
        return "xor_statement"

    def artifact_statement(self) -> dict[str, int]:
        return {
            "log_size": self.log_size,
            "log_step": self.log_step,
            "offset": self.offset,
        }

    def statement(self) -> dict[str, int]:
        return {
            **self.artifact_statement(),
            "trace_rows": self.trace_rows,
            "trace_cells": self.trace_cells,
        }

    def cli_shape_args(self) -> list[str]:
        return [
            "--log-size",
            str(self.log_size),
            "--log-step",
            str(self.log_step),
            "--offset",
            str(self.offset),
        ]

    def validate(self) -> None:
        if not 1 <= self.log_size <= 22:
            raise DiagnosticError(f"unsupported XOR log size: {self.log_size}")
        if not 0 <= self.log_step <= self.log_size:
            raise DiagnosticError(
                f"unsupported XOR log step: {self.log_step}"
            )
        if not 0 <= self.offset < (1 << self.log_step):
            raise DiagnosticError(f"unsupported XOR offset: {self.offset}")


@dataclass(frozen=True, order=True)
class PlonkShape:
    log_n_rows: int

    @property
    def trace_rows(self) -> int:
        return 1 << self.log_n_rows

    @property
    def trace_cells(self) -> int:
        return self.trace_rows * 8

    @property
    def slug(self) -> str:
        return f"plonk-log{self.log_n_rows}"

    @property
    def application(self) -> str:
        return PLONK_APPLICATION

    @property
    def protocol(self) -> str:
        return PLONK_PROTOCOL

    @property
    def artifact_statement_key(self) -> str:
        return "plonk_statement"

    def artifact_statement(self) -> dict[str, int]:
        return {"log_n_rows": self.log_n_rows}

    def statement(self) -> dict[str, int]:
        return {
            **self.artifact_statement(),
            "trace_rows": self.trace_rows,
            "trace_cells": self.trace_cells,
        }

    def cli_shape_args(self) -> list[str]:
        return ["--log-n-rows", str(self.log_n_rows)]

    def validate(self) -> None:
        if not 1 <= self.log_n_rows <= 22:
            raise DiagnosticError(
                f"unsupported Plonk log size: {self.log_n_rows}"
            )


@dataclass(frozen=True, order=True)
class BlakeShape:
    log_n_rows: int
    n_rounds: int

    @property
    def trace_rows(self) -> int:
        return 1 << self.log_n_rows

    @property
    def trace_cells(self) -> int:
        return self.trace_rows * self.n_rounds * 96

    @property
    def slug(self) -> str:
        return f"log{self.log_n_rows}-rounds{self.n_rounds}"

    @property
    def application(self) -> str:
        return BLAKE_APPLICATION

    @property
    def protocol(self) -> str:
        return BLAKE_PROTOCOL

    @property
    def artifact_statement_key(self) -> str:
        return "blake_statement"

    def artifact_statement(self) -> dict[str, int]:
        return {
            "log_n_rows": self.log_n_rows,
            "n_rounds": self.n_rounds,
        }

    def statement(self) -> dict[str, int]:
        return {
            **self.artifact_statement(),
            "trace_rows": self.trace_rows,
            "trace_cells": self.trace_cells,
        }

    def cli_shape_args(self) -> list[str]:
        return [
            "--log-n-rows",
            str(self.log_n_rows),
            "--n-rounds",
            str(self.n_rounds),
        ]

    def validate(self) -> None:
        if not 1 <= self.log_n_rows <= 29:
            raise DiagnosticError(
                f"unsupported Blake log size: {self.log_n_rows}"
            )
        if not 1 <= self.n_rounds <= (2**32 - 1) // 96:
            raise DiagnosticError(
                f"unsupported Blake round count: {self.n_rounds}"
            )


@dataclass(frozen=True, order=True)
class PoseidonShape:
    log_n_instances: int

    @property
    def trace_rows(self) -> int:
        return 1 << (self.log_n_instances - 3)

    @property
    def trace_cells(self) -> int:
        return self.trace_rows * 1264

    @property
    def slug(self) -> str:
        return f"instances-log{self.log_n_instances}"

    @property
    def application(self) -> str:
        return POSEIDON_APPLICATION

    @property
    def protocol(self) -> str:
        return POSEIDON_PROTOCOL

    @property
    def artifact_statement_key(self) -> str:
        return "poseidon_statement"

    def artifact_statement(self) -> dict[str, int]:
        return {"log_n_instances": self.log_n_instances}

    def statement(self) -> dict[str, int]:
        return {
            **self.artifact_statement(),
            "trace_rows": self.trace_rows,
            "trace_cells": self.trace_cells,
        }

    def cli_shape_args(self) -> list[str]:
        return ["--log-n-instances", str(self.log_n_instances)]

    def validate(self) -> None:
        if not 3 <= self.log_n_instances <= 33:
            raise DiagnosticError(
                "unsupported Poseidon instance log: "
                f"{self.log_n_instances}"
            )


@dataclass(frozen=True, order=True)
class StateMachineShape:
    log_n_rows: int
    initial_x: int
    initial_y: int

    @property
    def trace_rows(self) -> int:
        return 1 << self.log_n_rows

    @property
    def trace_cells(self) -> int:
        return self.trace_rows * 3

    @property
    def slug(self) -> str:
        return (
            f"state-machine-log{self.log_n_rows}-"
            f"x{self.initial_x}-y{self.initial_y}"
        )

    @property
    def application(self) -> str:
        return STATE_MACHINE_APPLICATION

    @property
    def protocol(self) -> str:
        return STATE_MACHINE_PROTOCOL

    @property
    def artifact_statement_key(self) -> str:
        return "state_machine_statement"

    def artifact_statement(self) -> dict[str, object]:
        rows = self.trace_rows
        return {
            "public_input": [
                [self.initial_x, self.initial_y],
                [self.initial_x + rows, self.initial_y + rows // 2],
            ],
            "stmt0": {
                "m": self.log_n_rows - 1,
                "n": self.log_n_rows,
            },
        }

    def statement(self) -> dict[str, int]:
        return {
            "log_n_rows": self.log_n_rows,
            "initial_x": self.initial_x,
            "initial_y": self.initial_y,
            "trace_rows": self.trace_rows,
            "trace_cells": self.trace_cells,
        }

    def cli_shape_args(self) -> list[str]:
        return [
            "--log-n-rows",
            str(self.log_n_rows),
            "--initial-x",
            str(self.initial_x),
            "--initial-y",
            str(self.initial_y),
        ]

    def validate(self) -> None:
        if not 1 <= self.log_n_rows <= 29:
            raise DiagnosticError(
                f"unsupported state-machine log size: {self.log_n_rows}"
            )
        modulus = (1 << 31) - 1
        if not 0 <= self.initial_x < modulus:
            raise DiagnosticError("state-machine initial x is not canonical M31")
        if not 0 <= self.initial_y < modulus:
            raise DiagnosticError("state-machine initial y is not canonical M31")
        if self.initial_x + self.trace_rows >= modulus:
            raise DiagnosticError("state-machine final x is not canonical M31")
        if self.initial_y + self.trace_rows // 2 >= modulus:
            raise DiagnosticError("state-machine final y is not canonical M31")


ProductShape = (
    Shape
    | XorShape
    | PlonkShape
    | BlakeShape
    | PoseidonShape
    | StateMachineShape
)


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
    shapes: tuple[ProductShape, ...] = DEFAULT_SHAPES
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
            shape.validate()
