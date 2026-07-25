"""Bounded workload and execution model for Native profiler evidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

if __package__.startswith("scripts."):
    from scripts.native_proof_matrix_lib.model import Workload, parse_workload
else:
    from native_proof_matrix_lib.model import Workload, parse_workload


PROFILE_PROTOCOL = "functional"
PROFILE_SAMPLES = 1
PROFILE_WORKLOAD_DESCRIPTORS = (
    "wide_fibonacci:log_n_rows=16,sequence_len=64",
    "xor:log_size=17,log_step=2,offset=3",
    "plonk:log_n_rows=16",
    "state_machine:log_n_rows=17,initial_x=9,initial_y=3",
    "blake:log_n_rows=12,n_rounds=10",
    "poseidon:log_n_instances=14",
)
PROFILE_WORKLOADS = tuple(parse_workload(value) for value in PROFILE_WORKLOAD_DESCRIPTORS)
COUNTER_WORKLOADS = tuple(workload.name for workload in PROFILE_WORKLOADS)

STABLE_ROOT_STAGE_IDS = (
    "channel_and_scheme_init",
    "preprocessed_commit",
    "main_trace_commit",
    "statement_mix",
    "core_prove",
)
STABLE_CORE_STAGE_IDS = (
    "draw_random_coeff",
    "composition_trace_extract",
    "composition_evaluation",
    "composition_interpolate_and_split",
    "composition_commit",
    "oods_point_and_mask_points",
    "sampled_value_evaluation",
    "sampled_value_channel_mix",
    "fri_quotient_build_and_commit",
    "proof_of_work",
    "fri_decommit",
    "trace_decommit",
    "constraint_check_and_assembly",
)
COMMIT_CHILD_STAGE_IDS = frozenset({
    "interpolate_columns",
    "evaluate_extended_domain",
    "merkle_commit",
})
HOST_TIMER_IDS = (
    "backend_init_seconds",
    "input_seconds",
    "prove_seconds",
    "proof_encode_seconds",
    "verify_seconds",
    "request_seconds",
)

MAX_CAPTURE_FILES = 128
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_BYTES = 512 * 1024 * 1024

# Every profiled encoder reserves two 8-byte timestamp samples. Metal limits
# this counter buffer to 32 KiB on supported Apple Silicon devices.
METAL_MAX_ENCODERS_PER_COMMAND_BUFFER = 2048


class CaptureError(ValueError):
    pass


@dataclass(frozen=True)
class CaptureSettings:
    output_dir: Path
    cpu_bin: Path
    metal_bin: Path
    workloads: tuple[Workload, ...]
    warmups: int
    sample_duration_seconds: int
    cooldown_seconds: float
    timeout_seconds: float
    encoder_counter_workload: str
    metal_max_encoders: int
    blake2_backend: str
    metal_runtime: str
    metal_aot_bundle: Path | None
    metal_aot_manifest_sha256: str | None
    controller_command: list[str]

    @property
    def protocol(self) -> str:
        return PROFILE_PROTOCOL

    @property
    def samples(self) -> int:
        return PROFILE_SAMPLES

    @property
    def resource_profile(self) -> str:
        return "large"
