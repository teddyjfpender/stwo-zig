"""Tagged workloads, canonical descriptors, and pre-launch matrix bounds."""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from types import MappingProxyType

from .resource_admission import (
    ACCOUNTED_BYTES_PER_COMMITTED_CELL,
    RESOURCE_PROFILES,
    resource_limits,
)


REPORT_SCHEMA_VERSION = 7

INTEROP_ARTIFACT_SCHEMA_VERSION = 1
INTEROP_UPSTREAM_COMMIT = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
INTEROP_EXCHANGE_MODE = "proof_exchange_json_wire_v1"
RUST_ORACLE_TOOLCHAIN = "nightly-2025-07-14"
RUST_ORACLE_SHA256 = "bca74321517d41e6c2128ab20567756ab498ef18cee3fba422a51eea74b92b2b"

DEFAULT_WORKLOADS = (
    "wide_fibonacci:log_n_rows=10,sequence_len=8",
    "xor:log_size=10,log_step=2,offset=3",
    "plonk:log_n_rows=10",
    "state_machine:log_n_rows=10,initial_x=9,initial_y=3",
    "blake:log_n_rows=8,n_rounds=2",
    "poseidon:log_n_instances=13",
)
DEFAULT_WARMUPS = 10
DEFAULT_PROTOCOL = "functional"
DEFAULT_COOLDOWN_SECONDS = 1.0

MAX_MATRIX_ROWS = 13
MIN_HEADLINE_WARMUPS = 10
MAX_LOG_ROWS = 22
MAX_SEQUENCE_LEN = 512
MAX_BLAKE_ROUNDS = 32
MAX_XOR_OFFSET = (1 << 31) - 1
M31_MODULUS = (1 << 31) - 1
MAX_COMMITTED_TRACE_CELLS = RESOURCE_PROFILES["standard"].max_committed_cells
MAX_WARMUPS = 30
MAX_SAMPLES = 21
MAX_COOLDOWN_SECONDS = 300.0
MAX_TIMEOUT_SECONDS = 3600.0
MAX_TOTAL_REQUEST_CELLS = 1 << 31

LANES = ("cpu", "metal")
EXPECTED_BACKENDS = {"cpu": "cpu_native", "metal": "metal_hybrid"}
PROTOCOL_PRESETS = {
    "smoke": {
        "name": "smoke",
        "pow_bits": 0,
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 3,
        "fold_step": 1,
    },
    "functional": {
        "name": "functional",
        "pow_bits": 10,
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 3,
        "fold_step": 1,
    },
}
HEADLINE_REQUIREMENT_KEYS = {
    "verified_unprofiled",
    "sampling_contract",
    "functional_protocol",
    "release_fast",
    "clean_complete_provenance",
    "thread_parallelism_enabled",
    "byte_identical_verified_samples",
    "backend_telemetry_valid",
}
SESSION_KEYS = {
    "max_circle_log",
    "host_byte_budget",
    "retained_host_twiddle_bytes",
    "tower_build_count",
}
RUNTIME_ADMISSION_KEYS = {
    "initialized",
    "origin",
    "source_sha256",
    "manifest_sha256",
    "metallib_sha256",
    "metallib_bytes",
    "active_call_leases",
    "live_resident_resources",
    "initialization_count",
    "shutdown_count",
    # Added by the Zig report schema (report.zig platform_identity): the
    # runtime/registry/hardware identity string the admission was made under.
    "platform_identity",
}
BACKEND_COUNTER_KEYS = {
    "host_merkle_commits",
    "resident_merkle_commits",
    "metal_quotient_dispatches",
    "metal_sampled_value_dispatches",
    "metal_circle_transform_dispatches",
    "metal_circle_lde_dispatches",
    "metal_fri_circle_fold_dispatches",
    "metal_fri_line_fold_dispatches",
    "metal_fri_fold_commit_epochs",
    "metal_qm31_coordinate_dispatches",
    "metal_trace_generation_dispatches",
    "metal_trace_generation_synchronizations",
    "metal_trace_generation_copybacks",
    "cpu_small_merkle_commits",
    "cpu_streaming_merkle_commits",
    "cpu_sampled_value_evaluations",
    "cpu_small_circle_interpolations",
    "cpu_small_circle_evaluations",
    "cpu_small_circle_ldes",
}


def trace_generation_counters_valid(counters: dict[str, int]) -> bool:
    dispatches = counters["metal_trace_generation_dispatches"]
    synchronizations = counters["metal_trace_generation_synchronizations"]
    copybacks = counters["metal_trace_generation_copybacks"]
    return synchronizations == dispatches and copybacks <= synchronizations


PIPELINE_CACHE_COUNTER_KEYS = {
    "library_cache_hits",
    "library_cache_misses",
    "pipeline_cache_hits",
    "binary_archive_hits",
    "binary_archive_misses",
    "direct_compiles",
    "archive_populations",
    "archive_serializations",
    "library_cache_entries",
    "library_cache_bytes",
    "library_cache_peak_entries",
    "library_cache_peak_bytes",
    "library_cache_evictions",
    "library_cache_rejections",
    "pipeline_cache_entries",
    "pipeline_cache_bytes",
    "pipeline_cache_peak_entries",
    "pipeline_cache_peak_bytes",
    "pipeline_cache_evictions",
    "pipeline_cache_invalidations",
    "pipeline_cache_rejections",
    "library_cache_entry_limit",
    "library_cache_byte_limit",
    "pipeline_cache_entry_limit",
    "pipeline_cache_byte_limit",
}
PIPELINE_CACHE_SECONDS_KEY = "pipeline_preparation_seconds"
LIBRARY_PREPARATION_SECONDS_KEY = "library_preparation_seconds"
ARCHIVE_STORE_COUNTER_KEYS = {
    "archive_disk_hits",
    "archive_disk_misses",
    "archive_disk_evictions",
    "archive_disk_rebuilds",
    "archive_disk_rejections",
    "archive_disk_quarantines",
    "archive_lock_acquisitions",
    "archive_lock_contentions",
    "archive_lock_timeouts",
    "archive_publication_successes",
    "archive_publication_failures",
    "archive_bytes_published",
    "archive_bytes_evicted",
    "archive_persistence_bypasses",
    "archive_disk_entries",
    "archive_disk_bytes",
    "archive_disk_entry_limit",
    "archive_disk_byte_limit",
    "archive_per_entry_byte_limit",
    "archive_quarantine_entries",
    "archive_quarantine_bytes",
    "archive_quarantine_entry_limit",
    "archive_quarantine_byte_limit",
}
ARCHIVE_STORE_SECONDS_KEY = "archive_lock_wait_seconds"
ACCELERATED_CLASSIFICATIONS = {
    "accelerated_with_fallbacks",
    "accelerated_without_fallbacks",
}
RATE_RELATIVE_TOLERANCE = 1e-12
RATE_ABSOLUTE_TOLERANCE = 1e-15

PARAMETER_ORDER = {
    "wide_fibonacci": ("log_n_rows", "sequence_len"),
    "xor": ("log_size", "log_step", "offset"),
    "plonk": ("log_n_rows",),
    "state_machine": ("log_n_rows", "initial_x", "initial_y"),
    "blake": ("log_n_rows", "n_rounds"),
    "poseidon": ("log_n_instances",),
}
NATIVE_UNITS = {
    "wide_fibonacci": "trace_rows",
    "xor": "xor_rows",
    "plonk": "plonk_rows",
    "state_machine": "state_transitions",
    "blake": "blake_round_instances",
    "poseidon": "poseidon_instances",
}
AIR_PROTOCOLS = {
    "xor": "raw-stwo-xor-lookup-v2",
    "state_machine": "raw-stwo-state-machine-v2",
}


class MatrixError(RuntimeError):
    """A benchmark artifact failed the matrix contract."""


@dataclass(frozen=True)
class Workload:
    name: str
    parameter_items: tuple[tuple[str, int], ...]

    @classmethod
    def wide_fibonacci(cls, log_n_rows: int, sequence_len: int) -> "Workload":
        return cls(
            "wide_fibonacci",
            (("log_n_rows", log_n_rows), ("sequence_len", sequence_len)),
        )

    @classmethod
    def xor(cls, log_size: int, log_step: int, offset: int) -> "Workload":
        return cls(
            "xor",
            (("log_size", log_size), ("log_step", log_step), ("offset", offset)),
        )

    @classmethod
    def plonk(cls, log_n_rows: int) -> "Workload":
        return cls("plonk", (("log_n_rows", log_n_rows),))

    @classmethod
    def state_machine(
        cls, log_n_rows: int, initial_x: int, initial_y: int
    ) -> "Workload":
        return cls(
            "state_machine",
            (
                ("log_n_rows", log_n_rows),
                ("initial_x", initial_x),
                ("initial_y", initial_y),
            ),
        )

    @classmethod
    def blake(cls, log_n_rows: int, n_rounds: int) -> "Workload":
        return cls(
            "blake",
            (("log_n_rows", log_n_rows), ("n_rounds", n_rounds)),
        )

    @classmethod
    def poseidon(cls, log_n_instances: int) -> "Workload":
        return cls("poseidon", (("log_n_instances", log_n_instances),))

    @property
    def parameters(self) -> dict[str, int]:
        return dict(self.parameter_items)

    @property
    def trace_log_rows(self) -> int:
        if self.name == "xor":
            return self.parameters["log_size"]
        if self.name == "poseidon":
            return self.parameters["log_n_instances"] - 3
        return self.parameters["log_n_rows"]

    @property
    def trace_rows(self) -> int:
        return 1 << self.trace_log_rows

    @property
    def committed_columns(self) -> int:
        if self.name == "blake":
            return self.parameters["n_rounds"] * 96
        if self.name == "poseidon":
            return 1264
        if self.name == "wide_fibonacci":
            return self.parameters["sequence_len"]
        if self.name == "xor":
            return 15
        if self.name == "state_machine":
            return 12
        return 8

    @property
    def committed_trees(self) -> int:
        if self.name in ("xor", "state_machine"):
            return 3
        return 2

    @property
    def committed_trace_cells(self) -> int:
        if self.name == "state_machine":
            return self.trace_rows * 9
        return self.trace_rows * self.committed_columns

    @property
    def accounted_bytes(self) -> int:
        return self.committed_trace_cells * ACCOUNTED_BYTES_PER_COMMITTED_CELL

    @property
    def native_unit(self) -> str:
        return NATIVE_UNITS[self.name]

    @property
    def native_units(self) -> int:
        if self.name == "blake":
            return self.trace_rows * self.parameters["n_rounds"]
        if self.name == "poseidon":
            return 1 << self.parameters["log_n_instances"]
        if self.name == "state_machine":
            return self.trace_rows + self.trace_rows // 2
        return self.trace_rows

    @property
    def slug(self) -> str:
        suffix = "-".join(f"{key}-{value}" for key, value in self.parameter_items)
        return f"{self.name}-{suffix}"

    def report_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "parameters": self.parameters,
            "trace_log_rows": self.trace_log_rows,
            "trace_rows": self.trace_rows,
            "committed_trees": self.committed_trees,
            "committed_columns": self.committed_columns,
            "committed_trace_cells": self.committed_trace_cells,
            "native_unit": self.native_unit,
            "native_units": self.native_units,
        }

    def native_flags(self) -> list[str]:
        flags = ["--example", self.name]
        for key, value in self.parameter_items:
            flags.extend((f"--{key.replace('_', '-')}", str(value)))
        return flags


def _canonical_workload(name: str, parameters: dict[str, int]) -> Workload:
    expected = PARAMETER_ORDER.get(name)
    if expected is None:
        raise ValueError(f"unsupported workload example: {name}")
    if set(parameters) != set(expected):
        raise ValueError(
            f"{name} parameters must be exactly {','.join(expected)}"
        )
    ordered = tuple((key, parameters[key]) for key in expected)
    workload = Workload(name, ordered)
    validate_workload(workload, resource_profile="large")
    return workload


def parse_workload(value: str) -> Workload:
    if "=" not in value:
        parts = value.replace(",", ":").split(":")
        if len(parts) != 2:
            raise argparse.ArgumentTypeError(
                "workload must be EXAMPLE:key=value,... or legacy LOG_ROWS:SEQUENCE_LEN"
            )
        try:
            return _canonical_workload(
                "wide_fibonacci",
                {"log_n_rows": int(parts[0]), "sequence_len": int(parts[1])},
            )
        except ValueError as error:
            raise argparse.ArgumentTypeError(str(error)) from error

    try:
        name, encoded_parameters = value.split(":", 1)
        parameters: dict[str, int] = {}
        for item in encoded_parameters.split(","):
            key, encoded = item.split("=", 1)
            if not key or key in parameters:
                raise ValueError("workload parameter names must be unique and nonempty")
            parameters[key] = int(encoded)
        return _canonical_workload(name, parameters)
    except (ValueError, TypeError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def validate_workload(workload: Workload, resource_profile: str = "standard") -> None:
    if workload.name not in PARAMETER_ORDER:
        raise ValueError(f"unsupported workload example: {workload.name}")
    if tuple(key for key, _ in workload.parameter_items) != PARAMETER_ORDER[workload.name]:
        raise ValueError("workload parameters are not in canonical order")
    values = workload.parameters
    if workload.trace_log_rows <= 0 or workload.trace_log_rows > MAX_LOG_ROWS:
        raise ValueError(f"trace log rows must be in [1, {MAX_LOG_ROWS}]")
    if workload.name == "wide_fibonacci":
        sequence_len = values["sequence_len"]
        if sequence_len < 2 or sequence_len > MAX_SEQUENCE_LEN:
            raise ValueError(f"sequence length must be in [2, {MAX_SEQUENCE_LEN}]")
    elif workload.name == "xor":
        log_step = values["log_step"]
        if log_step < 0 or log_step > values["log_size"]:
            raise ValueError("XOR log_step must be in [0, log_size]")
        if values["offset"] < 0 or values["offset"] > MAX_XOR_OFFSET:
            raise ValueError(f"XOR offset must be in [0, {MAX_XOR_OFFSET}]")
        if values["offset"] >= 1 << log_step:
            raise ValueError("XOR offset must be smaller than 2^log_step")
    elif workload.name == "state_machine":
        for coordinate in ("initial_x", "initial_y"):
            if values[coordinate] < 0 or values[coordinate] >= M31_MODULUS:
                raise ValueError(
                    f"State Machine {coordinate} must be a canonical M31 value"
                )
    elif workload.name == "blake":
        n_rounds = values["n_rounds"]
        if n_rounds < 1 or n_rounds > MAX_BLAKE_ROUNDS:
            raise ValueError(f"Blake rounds must be in [1, {MAX_BLAKE_ROUNDS}]")
    limits = resource_limits(resource_profile)
    if workload.committed_trace_cells > limits.max_committed_cells:
        raise ValueError(
            "workload exceeds committed trace cell limit "
            f"for {resource_profile} profile "
            f"({workload.committed_trace_cells} > {limits.max_committed_cells})"
        )
    if workload.accounted_bytes > limits.max_accounted_bytes:
        raise ValueError(
            "workload exceeds accounted memory limit "
            f"for {resource_profile} profile "
            f"({workload.accounted_bytes} > {limits.max_accounted_bytes})"
        )


def descriptor_bytes(workload: Workload, protocol_name: str) -> bytes:
    protocol = PROTOCOL_PRESETS[protocol_name]
    fields = ["native-proof-workload-v3", f"example={workload.name}"]
    fields.extend(f"{key}={value}" for key, value in workload.parameter_items)
    if air_protocol := AIR_PROTOCOLS.get(workload.name):
        fields.append(f"air_protocol={air_protocol}")
    fields.extend(
        (
            f"protocol={protocol['name']}",
            f"pow_bits={protocol['pow_bits']}",
            f"log_blowup_factor={protocol['log_blowup_factor']}",
            f"log_last_layer_degree_bound={protocol['log_last_layer_degree_bound']}",
            f"n_queries={protocol['n_queries']}",
            f"fold_step={protocol['fold_step']}",
        )
    )
    return "|".join(fields).encode("ascii")


def workload_descriptor_sha256(workload: Workload, protocol_name: str) -> str:
    return hashlib.sha256(descriptor_bytes(workload, protocol_name)).hexdigest()


@dataclass(frozen=True)
class SuiteRow:
    id: str
    workload: Workload


@dataclass(frozen=True)
class WorkloadSuite:
    name: str
    description: str
    rows: tuple[SuiteRow, ...]

    @property
    def workloads(self) -> tuple[Workload, ...]:
        return tuple(row.workload for row in self.rows)

    @property
    def committed_trace_cells_per_lane(self) -> int:
        return sum(workload.committed_trace_cells for workload in self.workloads)

    def request_cells(self, warmups: int, samples: int) -> int:
        return self.committed_trace_cells_per_lane * len(LANES) * (warmups + samples)


HOLISTIC_SUITE = WorkloadSuite(
    name="holistic",
    description=(
        "Latency canary plus the proven two-scale CPU/Metal parity portfolio "
        "for all six native AIRs"
    ),
    rows=(
        SuiteRow("wf_log10x8", Workload.wide_fibonacci(10, 8)),
        SuiteRow("wf_log14x32", Workload.wide_fibonacci(14, 32)),
        SuiteRow("wf_log16x64", Workload.wide_fibonacci(16, 64)),
        SuiteRow("xor_log14", Workload.xor(14, 2, 3)),
        SuiteRow("xor_log16", Workload.xor(16, 2, 3)),
        SuiteRow("plonk_log14", Workload.plonk(14)),
        SuiteRow("plonk_log16", Workload.plonk(16)),
        SuiteRow("sm_v2_log14", Workload.state_machine(14, 9, 3)),
        SuiteRow("sm_v2_log16", Workload.state_machine(16, 9, 3)),
        SuiteRow("blake_log10x10", Workload.blake(10, 10)),
        SuiteRow("blake_log12x16", Workload.blake(12, 16)),
        SuiteRow("poseidon_log10", Workload.poseidon(10)),
        SuiteRow("poseidon_log13", Workload.poseidon(13)),
    ),
)

WORKLOAD_SUITES = MappingProxyType({HOLISTIC_SUITE.name: HOLISTIC_SUITE})


def validate_suite(suite: WorkloadSuite) -> None:
    if not suite.name or not suite.description:
        raise ValueError("workload suite name and description must be nonempty")
    if not suite.rows or len(suite.rows) > MAX_MATRIX_ROWS:
        raise ValueError(
            f"workload suite must contain between 1 and {MAX_MATRIX_ROWS} rows"
        )
    row_ids = tuple(row.id for row in suite.rows)
    if any(not row_id for row_id in row_ids) or len(set(row_ids)) != len(row_ids):
        raise ValueError("workload suite row IDs must be unique and nonempty")
    if len(set(suite.workloads)) != len(suite.workloads):
        raise ValueError("workload suite rows must be unique")
    for workload in suite.workloads:
        validate_workload(workload)
    maximum_request_cells = suite.request_cells(MAX_WARMUPS, MAX_SAMPLES)
    if maximum_request_cells > MAX_TOTAL_REQUEST_CELLS:
        raise ValueError(
            "workload suite exceeds aggregate cell budget at maximum sampling "
            f"({maximum_request_cells} > {MAX_TOTAL_REQUEST_CELLS})"
        )


for _suite in WORKLOAD_SUITES.values():
    validate_suite(_suite)
