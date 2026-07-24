"""Workload coverage and bounded settings for Native CUDA measurement."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scripts.native_cuda_diagnostic_lib.model import (
    BlakeShape,
    DiagnosticError,
    PlonkShape,
    PoseidonShape,
    ProductShape,
    Shape,
    StateMachineShape,
    XorShape,
)


SCHEMA = "native_cuda_structural_benchmark_v2"
MAX_REPEAT = 16
MAX_ROUNDS = 30
MAX_TIMEOUT_SECONDS = 7200.0
MAX_COOLDOWN_SECONDS = 300.0
REGRESSION_CEILING = 1.05
MINIMUM_PORTFOLIO_RATIO = 1.0 / 1.3
PRIMARY_PORTFOLIO_RATIO = 0.5


class BenchmarkError(RuntimeError):
    """A benchmark input or measured product violated the contract."""


@dataclass(frozen=True, order=True)
class SustainedShape:
    cycles: int = 4

    def validate(self) -> None:
        if not 2 <= self.cycles <= 4:
            raise DiagnosticError("sustained CUDA cycles must be in [2, 4]")

    def statement(self) -> dict[str, object]:
        return {
            "workload_id": "mixed_native_wide_poseidon_state_machine_v1",
            "cycle_order": [
                "wide_fibonacci",
                "poseidon",
                "state_machine",
            ],
            "steady_cycles": self.cycles - 1,
            "requests_per_cycle": 3,
        }


@dataclass(frozen=True)
class Workload:
    workload_id: str
    structural_class: str
    shape: ProductShape | SustainedShape | None
    enabled: bool
    unavailable_reason: str | None = None
    headline_scored: bool = True

    def validate(self) -> None:
        if not self.workload_id or not self.structural_class:
            raise BenchmarkError("CUDA workload identity must be nonempty")
        if self.enabled:
            if self.shape is None or self.unavailable_reason is not None:
                raise BenchmarkError(
                    f"enabled CUDA workload is malformed: {self.workload_id}"
                )
            try:
                self.shape.validate()
            except DiagnosticError as error:
                raise BenchmarkError(str(error)) from error
        elif self.shape is not None or not self.unavailable_reason:
            raise BenchmarkError(
                f"disabled CUDA workload lacks one reason: {self.workload_id}"
            )
        if (
            self.enabled
            and self.structural_class == "sustained"
            and self.headline_scored
        ):
            raise BenchmarkError(
                "sustained CUDA workload cannot enter headline scoring "
                "before locked-host calibration"
            )


COVERAGE_MATRIX = (
    Workload("latency_wf_log14x32", "latency", Shape(14, 32), True),
    Workload(
        "lookup_xor_log14_step2",
        "lookup_periodic",
        XorShape(14, 2, 3),
        True,
    ),
    Workload(
        "lookup_xor_log16_step2",
        "lookup_periodic",
        XorShape(16, 2, 3),
        True,
    ),
    Workload(
        "structured_plonk_log14",
        "structured_arithmetic",
        PlonkShape(14),
        True,
    ),
    Workload(
        "structured_plonk_log16",
        "structured_arithmetic",
        PlonkShape(16),
        True,
    ),
    Workload("narrow_deep_wf_log22x3", "narrow_deep", Shape(22, 3), True),
    Workload("wide_wf_log18x37", "wide", Shape(18, 37), True),
    Workload("wide_wf_log18x73", "wide", Shape(18, 73), True),
    Workload("wide_wf_log18x128", "wide", Shape(18, 128), True),
    Workload("large_wf_log20x100", "large", Shape(20, 100), True),
    Workload(
        "seeded_blake_log10x10",
        "seeded_wide",
        BlakeShape(10, 10),
        True,
    ),
    Workload(
        "seeded_blake_log12x10",
        "seeded_wide",
        BlakeShape(12, 10),
        True,
    ),
    Workload(
        "poseidon_log10_instances",
        "hash_heavy",
        PoseidonShape(10),
        True,
    ),
    Workload(
        "poseidon_log13_instances",
        "hash_heavy",
        PoseidonShape(13),
        True,
    ),
    Workload(
        "lookup_native",
        "lookup_heavy",
        None,
        False,
        "Native lookup/LogUp AIRs do not yet emit CUDA packs",
    ),
    Workload(
        "irregular_state_machine_log16",
        "irregular",
        StateMachineShape(16, 9, 3),
        True,
    ),
    Workload(
        "vm_portfolio",
        "vm",
        None,
        False,
        "RISC-V ALU, memory, branch, SHA and Keccak CUDA packs are pending",
    ),
    Workload("extreme_wf_log22x100", "extreme", Shape(22, 100), True),
    Workload(
        "mixed_shape_queue",
        "sustained",
        SustainedShape(),
        True,
        None,
        False,
    ),
)


@dataclass(frozen=True)
class Profile:
    workload_ids: tuple[str, ...]
    warmups: int
    samples: int
    rounds: int
    cold_samples: int


PROFILES = {
    "smoke": Profile(
        (
            "latency_wf_log14x32",
            "lookup_xor_log14_step2",
            "seeded_blake_log10x10",
            "poseidon_log10_instances",
            "irregular_state_machine_log16",
            "wide_wf_log18x37",
            "mixed_shape_queue",
        ),
        warmups=1,
        samples=2,
        rounds=1,
        cold_samples=1,
    ),
    "screen": Profile(
        tuple(
            workload.workload_id
            for workload in COVERAGE_MATRIX
            if workload.enabled
        ),
        warmups=3,
        samples=5,
        rounds=1,
        cold_samples=1,
    ),
    "judge": Profile(
        tuple(
            workload.workload_id
            for workload in COVERAGE_MATRIX
            if workload.enabled
        ),
        warmups=10,
        samples=5,
        rounds=7,
        cold_samples=2,
    ),
}


@dataclass(frozen=True)
class Settings:
    candidate_bin: Path
    baseline_bin: Path | None
    output_path: Path
    repo_root: Path
    profile_name: str
    warmups: int
    samples: int
    rounds: int
    cold_samples: int
    cooldown_seconds: float
    timeout_seconds: float
    device_ordinal: str
    bootstrap_resamples: int
    workloads: tuple[Workload, ...]
    rust_oracle_bin: Path | None = None
    rust_oracle_sha256: str | None = None

    @property
    def artifact_root(self) -> Path:
        return self.output_path.with_name(f"{self.output_path.stem}.artifacts")

    def validate(self) -> None:
        if self.profile_name not in PROFILES:
            raise BenchmarkError(f"unknown CUDA profile: {self.profile_name}")
        if self.warmups < 0 or self.samples < 1:
            raise BenchmarkError("CUDA warmups/samples are invalid")
        if 1 + self.warmups + self.samples > MAX_REPEAT:
            raise BenchmarkError(
                f"first request + warmups + samples exceeds {MAX_REPEAT}"
            )
        if not 1 <= self.rounds <= MAX_ROUNDS:
            raise BenchmarkError(f"CUDA rounds must be in [1, {MAX_ROUNDS}]")
        if not 1 <= self.cold_samples <= MAX_ROUNDS:
            raise BenchmarkError("CUDA cold sample count is invalid")
        if not 0 <= self.cooldown_seconds <= MAX_COOLDOWN_SECONDS:
            raise BenchmarkError("CUDA cooldown is outside its bound")
        if not 0 < self.timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise BenchmarkError("CUDA timeout is outside its bound")
        if not self.device_ordinal.isdecimal():
            raise BenchmarkError("CUDA device ordinal must be decimal")
        if not 1_000 <= self.bootstrap_resamples <= 1_000_000:
            raise BenchmarkError("CUDA bootstrap resample count is invalid")
        if not self.workloads:
            raise BenchmarkError("CUDA benchmark has no workloads")
        identities = set()
        for workload in self.workloads:
            workload.validate()
            if not workload.enabled:
                raise BenchmarkError(
                    f"selected workload is unavailable: {workload.workload_id}"
                )
            if workload.workload_id in identities:
                raise BenchmarkError("CUDA workload identities are not unique")
            identities.add(workload.workload_id)
        if self.profile_name == "judge":
            if self.baseline_bin is None:
                raise BenchmarkError("CUDA judge profile requires a baseline binary")
            if self.rounds < 7 or self.warmups < 10 or self.samples < 5:
                raise BenchmarkError("CUDA judge sampling contract was weakened")
            if self.rust_oracle_bin is None or self.rust_oracle_sha256 is None:
                raise BenchmarkError(
                    "CUDA judge profile requires a pinned Rust oracle binary"
                )
        if (self.rust_oracle_bin is None) != (self.rust_oracle_sha256 is None):
            raise BenchmarkError(
                "CUDA Rust oracle binary and SHA-256 pin must be supplied together"
            )
        if self.rust_oracle_sha256 is not None and (
            len(self.rust_oracle_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.rust_oracle_sha256
            )
        ):
            raise BenchmarkError(
                "CUDA Rust oracle SHA-256 pin must be canonical lowercase hex"
            )
