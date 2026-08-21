"""Immutable R-006 plan construction, scheduling, and replay validation."""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    sha256_bytes,
    sha256_file,
    write_new,
)
from .global_work_closure import (
    global_exact_work_closure,
    validate_global_exact_work_closure,
)
from .host_identity import host_identity
from .model import (
    ATTEMPTS_PER_COMPARISON,
    COMPARISON_LABELS,
    COOLDOWN_NS,
    DIGEST_RE,
    ENVIRONMENT,
    GENERATED_WORKLOADS,
    GENERATED_WORKLOAD_PARAMETERS,
    GIT_OID_RE,
    LANES,
    MILESTONE,
    PAIRS_PER_ROUND,
    PLAN_ATTEMPTS,
    PLAN_SCHEMA,
    PLAN_VERSION,
    PROTOCOL_PATH,
    PROTOCOL_SCHEMA,
    PROTOCOL_SHA256,
    ROUNDS,
    SESSION_RE,
    UTC_RE,
    WARMUPS_PER_ARM,
    WORKLOAD_IDS,
    CaptureError,
)


ROOT_FIELDS = {
    "schema",
    "schema_version",
    "classification",
    "created_at_utc",
    "session_id",
    "protocol",
    "source",
    "global_exact_work_closure",
    "build",
    "host",
    "lane",
    "security",
    "environment",
    "worker_environment",
    "workloads",
    "worker_arms",
    "schedule",
    "attempts",
    "content_sha256",
}
SOURCE_FIELDS = {
    "repository",
    "commit",
    "tree",
    "clean_status",
    "source_closure_files",
    "source_closure_sha256",
}
FILE_FIELDS = {"path", "bytes", "sha256"}
BUILD_FIELDS = {
    "build_step",
    "optimization_mode",
    "toolchain",
    "target",
    "cpu_features",
    "executable_path",
    "executable_bytes",
    "executable_sha256",
}
HOST_FIELDS = {
    "os",
    "os_version",
    "kernel_release",
    "machine",
    "cpu_model",
    "logical_cores",
    "physical_cores",
    "memory_bytes",
    "power_state",
}
ATTEMPT_FIELDS = {
    "ordinal",
    "attempt_id",
    "comparison_id",
    "workload_id",
    "phase",
    "warmup",
    "round",
    "pair_index",
    "position",
    "arm",
    "arm_sample_index",
    "worker_count",
    "proof_path",
    "report_path",
    "stderr_path",
    "verify_stdout_path",
    "verify_stderr_path",
}
REQUIRED_EXACT_BINARY_MARKERS = (
    b"riscv_profiled_proof_v4",
    b"riscv_verified_request_attempt_v3",
    b"stwo.prover.logical-work-profile.v2",
)
EPHEMERAL_SNAPSHOT_MESSAGE_PREFIX = "benchmark: ephemeral typed-air source snapshot"


@dataclass(frozen=True)
class WorkloadPaths:
    elf: Path
    input: Path | None


@dataclass(frozen=True)
class PlanSettings:
    repository: Path
    session_id: str
    lane: str
    power_state: str
    executable: Path
    workloads: Mapping[str, WorkloadPaths]
    toolchain: str
    target: str
    cpu_features: str


SourceProvider = Callable[[Path], dict[str, object]]
HostProvider = Callable[[str], dict[str, object]]
ClosureProvider = Callable[[Path], dict[str, object]]
Clock = Callable[[], dt.datetime]


def _run(command: Sequence[str], repository: Path) -> bytes:
    try:
        result = subprocess.run(
            command,
            cwd=repository,
            env=ENVIRONMENT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CaptureError(f"provenance command failed to launch: {command[0]}") from error
    if result.returncode != 0 or result.stderr:
        raise CaptureError(
            f"provenance command failed: {list(command)!r}, exit={result.returncode}, "
            f"stderr={result.stderr[:160]!r}"
        )
    return result.stdout


def source_identity(repository: Path) -> dict[str, object]:
    root = repository.resolve()
    commit = _run(("git", "rev-parse", "HEAD"), root).decode("ascii").strip()
    tree = _run(("git", "rev-parse", "HEAD^{tree}"), root).decode("ascii").strip()
    status = _run(
        ("git", "status", "--porcelain=v1", "--untracked-files=all"), root
    ).decode("utf-8", errors="strict").splitlines()
    if status:
        raise CaptureError("R-006 planning requires a clean immutable source snapshot")
    message = _run(("git", "log", "-1", "--format=%B"), root).decode(
        "utf-8", errors="strict"
    )
    if message.startswith(EPHEMERAL_SNAPSHOT_MESSAGE_PREFIX):
        raise CaptureError(
            "R-006 normative planning rejects diagnostic ephemeral source snapshots"
        )
    closure = _run(("git", "ls-tree", "-r", "--full-tree", "HEAD"), root)
    if not closure or not closure.endswith(b"\n"):
        raise CaptureError("Git source closure is empty or malformed")
    return {
        "repository": "https://github.com/teddyjfpender/stwo-zig",
        "commit": commit,
        "tree": tree,
        "clean_status": True,
        "source_closure_files": closure.count(b"\n"),
        "source_closure_sha256": sha256_bytes(closure),
    }


def _timestamp(clock: Clock) -> str:
    value = clock()
    if value.tzinfo is None:
        raise CaptureError("capture-plan clock must be timezone-aware")
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _file_identity(path: Path, *, executable: bool = False) -> dict[str, object]:
    resolved = path.resolve()
    if resolved.is_symlink() or not resolved.is_file():
        raise CaptureError(f"capture artifact is not a regular file: {resolved}")
    if executable and not os.access(resolved, os.X_OK):
        raise CaptureError(f"capture executable is not executable: {resolved}")
    size, digest = sha256_file(resolved)
    if size <= 0:
        raise CaptureError(f"capture artifact is empty: {resolved}")
    return {"path": str(resolved), "bytes": size, "sha256": digest}


def _require_binary_markers(path: Path) -> None:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CaptureError("cannot inspect R-006 executable") from error
    if all(marker in raw for marker in REQUIRED_EXACT_BINARY_MARKERS):
        return
    expected = "+".join(marker.decode("ascii") for marker in REQUIRED_EXACT_BINARY_MARKERS)
    raise CaptureError(
        f"R-006 executable lacks the complete exact-work production schema marker set: {expected}"
    )


def _protocol(repository: Path) -> dict[str, object]:
    path = repository.resolve() / PROTOCOL_PATH
    raw = path.read_bytes()
    if sha256_bytes(raw) != PROTOCOL_SHA256:
        raise CaptureError("frozen M5-M9 performance protocol bytes changed")
    document = decode_strict(raw)
    if type(document) is not dict or document.get("schema") != PROTOCOL_SCHEMA:
        raise CaptureError("frozen performance protocol schema changed")
    milestone = next(
        (
            item
            for item in document.get("milestones", [])
            if type(item) is dict and item.get("id") == MILESTONE
        ),
        None,
    )
    if milestone is None or milestone.get("worker_counts") != [1, 2, 4, "min(8,physical_cores)"]:
        raise CaptureError("M7 worker authority changed")
    sampling = document.get("sampling_protocol")
    expected_sampling = {
        "excluded_verified_warmups_per_arm": WARMUPS_PER_ARM,
        "paired_rounds": ROUNDS,
        "measured_verified_proofs_per_arm_per_round": PAIRS_PER_ROUND,
        "cooldown_seconds_between_attempts": COOLDOWN_NS / 1_000_000_000,
        "process_isolation": "one fresh child process for every warmup and measured attempt",
    }
    if type(sampling) is not dict or any(sampling.get(key) != value for key, value in expected_sampling.items()):
        raise CaptureError("M7 sampling authority changed")
    return {
        "path": PROTOCOL_PATH,
        "bytes": len(raw),
        "sha256": PROTOCOL_SHA256,
        "schema": PROTOCOL_SCHEMA,
        "milestone": MILESTONE,
    }


def _validate_generated_input(
    path: Path,
    workload_id: str,
) -> dict[str, int | str]:
    expected = GENERATED_WORKLOAD_PARAMETERS.get(workload_id)
    if expected is None:
        raise CaptureError("generated Poseidon2 workload identity is not frozen")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CaptureError(f"cannot read generated workload input: {path}") from error
    if len(raw) < 4:
        raise CaptureError("generated Poseidon2 input lacks its call-count prefix")
    calls = struct.unpack_from("<I", raw)[0]
    if (
        calls != expected["calls"]
        or len(raw)
        != 4
        + calls * expected["width"] * expected["encoding_word_bytes"]
    ):
        raise CaptureError(
            f"generated Poseidon2 input shape is not canonical for {workload_id}"
        )
    for offset in range(4, len(raw), 4):
        if struct.unpack_from("<I", raw, offset)[0] >= 0x7FFF_FFFF:
            raise CaptureError("generated Poseidon2 input contains a non-canonical M31 word")
    if raw != materialized_poseidon_input(calls):
        raise CaptureError("generated Poseidon2 input differs from its frozen generator")
    return dict(expected)


def materialized_poseidon_input(calls: int) -> bytes:
    """Replay ``poseidon2-software-precompile-equivalence-v1`` exactly."""
    admitted_calls = {
        parameters["calls"] for parameters in GENERATED_WORKLOAD_PARAMETERS.values()
    }
    if type(calls) is not int or calls not in admitted_calls:
        raise CaptureError(
            "R-006 materialization accepts only frozen per-workload call counts"
        )
    modulus = 0x7FFF_FFFF
    mask = (1 << 64) - 1
    random_state = 0x6A09_E667_F3BC_C909
    words = [calls]
    for call in range(calls):
        for lane in range(16):
            if call == 0:
                value = lane
            else:
                random_state = (random_state + 0x9E37_79B9_7F4A_7C15) & mask
                mixed = random_state
                mixed = ((mixed ^ (mixed >> 30)) * 0xBF58_476D_1CE4_E5B9) & mask
                mixed = ((mixed ^ (mixed >> 27)) * 0x94D0_49BB_1331_11EB) & mask
                mixed ^= mixed >> 31
                value = mixed % modulus
            words.append(value)
    return struct.pack(f"<{len(words)}I", *words)


def _workloads(paths: Mapping[str, WorkloadPaths]) -> list[dict[str, object]]:
    if set(paths) != set(WORKLOAD_IDS):
        raise CaptureError(
            f"workload set drifted; missing={sorted(set(WORKLOAD_IDS) - set(paths))}, "
            f"unknown={sorted(set(paths) - set(WORKLOAD_IDS))}"
        )
    result: list[dict[str, object]] = []
    for workload_id in WORKLOAD_IDS:
        supplied = paths[workload_id]
        generated = GENERATED_WORKLOADS.get(workload_id)
        if generated is None:
            if supplied.input is not None:
                raise CaptureError(f"fixed workload {workload_id} must not carry input bytes")
            generator = None
            parameters = None
            input_identity = None
        else:
            if supplied.input is None:
                raise CaptureError(f"generated workload {workload_id} requires materialized input")
            generator = dict(generated)
            parameters = _validate_generated_input(supplied.input, workload_id)
            input_identity = _file_identity(supplied.input)
        result.append(
            {
                "id": workload_id,
                "elf": _file_identity(supplied.elf),
                "input": input_identity,
                "generator": generator,
                "parameters": parameters,
            }
        )
    return result


def _first_arm(lane: str, workload: str) -> str:
    digest = hashlib.sha256(f"{MILESTONE}:{lane}:{workload}".encode("ascii")).digest()
    return "reference" if digest[-1] & 1 == 0 else "subject"


def _comparison_attempts(
    *,
    start: int,
    comparison_id: str,
    workload_id: str,
    reference_workers: int,
    subject_workers: int,
    first_arm: str,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    samples = {"reference": 0, "subject": 0}

    def append(phase: str, round_index: int | None, pair: int, position: int, arm: str) -> None:
        ordinal = start + len(result)
        result.append(
            {
                "ordinal": ordinal,
                "attempt_id": f"r006-{ordinal:04d}",
                "comparison_id": comparison_id,
                "workload_id": workload_id,
                "phase": phase,
                "warmup": phase == "warmup",
                "round": round_index,
                "pair_index": pair,
                "position": position,
                "arm": arm,
                "arm_sample_index": samples[arm],
                "worker_count": reference_workers if arm == "reference" else subject_workers,
                "proof_path": f"attempts/{ordinal:04d}.proof.json",
                "report_path": f"attempts/{ordinal:04d}.report.json",
                "stderr_path": f"attempts/{ordinal:04d}.stderr.bin",
                "verify_stdout_path": f"attempts/{ordinal:04d}.verify.stdout.bin",
                "verify_stderr_path": f"attempts/{ordinal:04d}.verify.stderr.bin",
            }
        )
        samples[arm] += 1

    opposite = {"reference": "subject", "subject": "reference"}
    for pair in range(WARMUPS_PER_ARM):
        leading = first_arm if pair & 1 == 0 else opposite[first_arm]
        append("warmup", None, pair, 0, leading)
        append("warmup", None, pair, 1, opposite[leading])
    for round_index in range(ROUNDS):
        leading = first_arm if round_index & 1 == 0 else opposite[first_arm]
        for pair in range(PAIRS_PER_ROUND):
            append("measured", round_index, pair, 0, leading)
            append("measured", round_index, pair, 1, opposite[leading])
    if len(result) != ATTEMPTS_PER_COMPARISON or samples != {"reference": 40, "subject": 40}:
        raise AssertionError("R-006 schedule geometry drifted")
    return result


def _attempts(lane: str, max_workers: int) -> list[dict[str, object]]:
    result = _comparison_attempts(
        start=0,
        comparison_id="aa-calibration",
        workload_id="multi_shard_addi",
        reference_workers=1,
        subject_workers=1,
        first_arm=_first_arm(lane, "multi_shard_addi"),
    )
    counts = {"two": 2, "four": 4, "max": max_workers}
    for workload in WORKLOAD_IDS:
        first = _first_arm(lane, workload)
        for label in COMPARISON_LABELS:
            result.extend(
                _comparison_attempts(
                    start=len(result),
                    comparison_id=f"{label}-workers-over-one",
                    workload_id=workload,
                    reference_workers=1,
                    subject_workers=counts[label],
                    first_arm=first,
                )
            )
    if len(result) != PLAN_ATTEMPTS:
        raise AssertionError("R-006 global schedule cardinality drifted")
    return result


def build_plan(
    settings: PlanSettings,
    *,
    source_provider: SourceProvider = source_identity,
    host_provider: HostProvider = host_identity,
    closure_provider: ClosureProvider = global_exact_work_closure,
    clock: Clock = lambda: dt.datetime.now(dt.timezone.utc),
) -> dict[str, object]:
    repository = settings.repository.resolve()
    if not repository.is_dir():
        raise CaptureError(f"repository root is missing: {repository}")
    if settings.lane not in LANES:
        raise CaptureError(f"unsupported R-006 lane: {settings.lane}")
    if SESSION_RE.fullmatch(settings.session_id) is None:
        raise CaptureError("session ID must be a stable 1-128 character token")
    for name, value in {
        "toolchain": settings.toolchain,
        "target": settings.target,
        "cpu_features": settings.cpu_features,
    }.items():
        if not value or len(value) > 256 or any(ord(character) < 32 for character in value):
            raise CaptureError(f"build {name} must be explicit printable text")
    host = host_provider(settings.power_state)
    validate_host(host)
    if host["os"] != "Darwin":
        raise CaptureError(
            "R-006 v1 requires Darwin RUSAGE_INFO_V6 resource authority"
        )
    if host["physical_cores"] < 4:
        raise CaptureError("M7 requires at least four physical cores")
    max_workers = min(8, host["physical_cores"])
    executable = _file_identity(settings.executable, executable=True)
    _require_binary_markers(Path(str(executable["path"])))
    global_closure = validate_global_exact_work_closure(
        closure_provider(repository)
    )
    lane = LANES[settings.lane]
    document: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "schema_version": PLAN_VERSION,
        "classification": "pre-execution-capture-authority",
        "created_at_utc": _timestamp(clock),
        "session_id": settings.session_id,
        "protocol": _protocol(repository),
        "source": source_provider(repository),
        "global_exact_work_closure": global_closure,
        "build": {
            "build_step": lane["build_step"],
            "optimization_mode": "ReleaseFast",
            "toolchain": settings.toolchain,
            "target": settings.target,
            "cpu_features": settings.cpu_features,
            "executable_path": executable["path"],
            "executable_bytes": executable["bytes"],
            "executable_sha256": executable["sha256"],
        },
        "host": host,
        "lane": {
            "id": settings.lane,
            "backend": lane["backend"],
            "cli_backend": lane["cli_backend"],
            "runtime_mode": "native" if settings.lane == "cpu-native" else "declared-metal-runtime",
        },
        "security": "secure",
        "environment": dict(ENVIRONMENT),
        "worker_environment": {
            "STWO_ZIG_WORKERS": "attempt.worker_count",
            "STWO_ZIG_MERKLE_WORKERS": "attempt.worker_count",
            "STWO_ZIG_POW_WORKERS": "unset:reuse-proof-pool",
        },
        "workloads": _workloads(settings.workloads),
        "worker_arms": {
            "reference": 1,
            "two": 2,
            "four": 4,
            "max": max_workers,
            "max_rule": "min(8,physical_cores)",
        },
        "schedule": {
            "fresh_process_per_attempt": True,
            "serial_attempts": True,
            "warmups_per_arm": WARMUPS_PER_ARM,
            "rounds": ROUNDS,
            "proofs_per_arm_per_round": PAIRS_PER_ROUND,
            "cooldown_ns": COOLDOWN_NS,
            "retry_failed_attempts": False,
            "drop_outliers": False,
            "attempts": PLAN_ATTEMPTS,
            "pairing": "round-level alternating AB/BA",
        },
        "attempts": _attempts(settings.lane, max_workers),
    }
    document["content_sha256"] = content_digest(document)
    validate_plan(document, repository=repository, verify_local=False)
    return document


def validate_host(value: Any) -> dict[str, Any]:
    host = exact_object(value, HOST_FIELDS, "capture host")
    for key in ("os", "os_version", "kernel_release", "machine", "cpu_model"):
        if type(host[key]) is not str or not host[key]:
            raise CaptureError(f"capture host {key} is empty")
    for key in ("logical_cores", "physical_cores", "memory_bytes"):
        if type(host[key]) is not int or host[key] <= 0:
            raise CaptureError(f"capture host {key} is invalid")
    power = exact_object(
        host["power_state"],
        {"operator_declaration", "machine_verified", "power_source", "low_power_mode"},
        "power state",
    )
    if type(power["operator_declaration"]) is not str or not power["operator_declaration"]:
        raise CaptureError("capture power declaration is empty")
    if (
        power["machine_verified"] is not True
        or power["power_source"] != "AC Power"
        or power["low_power_mode"] is not False
    ):
        raise CaptureError("capture host lacks admissible machine-verified power evidence")
    return host


def _validate_file(value: Any, name: str, *, verify_local: bool, executable: bool = False) -> dict[str, Any]:
    identity = exact_object(value, FILE_FIELDS, name)
    path = Path(identity["path"])
    if not path.is_absolute() or ".." in path.parts:
        raise CaptureError(f"{name} path must be absolute and normalized")
    if type(identity["bytes"]) is not int or identity["bytes"] <= 0:
        raise CaptureError(f"{name} byte count is invalid")
    if type(identity["sha256"]) is not str or DIGEST_RE.fullmatch(identity["sha256"]) is None:
        raise CaptureError(f"{name} digest is invalid")
    if verify_local and _file_identity(path, executable=executable) != identity:
        raise CaptureError(f"{name} changed after plan creation")
    return identity


def _validate_source(value: Any) -> dict[str, Any]:
    source = exact_object(value, SOURCE_FIELDS, "capture source")
    if source["repository"] != "https://github.com/teddyjfpender/stwo-zig":
        raise CaptureError("capture repository identity changed")
    for key in ("commit", "tree"):
        if type(source[key]) is not str or GIT_OID_RE.fullmatch(source[key]) is None:
            raise CaptureError(f"capture source {key} is not a Git object ID")
    if source["clean_status"] is not True:
        raise CaptureError("capture source is not clean")
    if type(source["source_closure_files"]) is not int or source["source_closure_files"] <= 0:
        raise CaptureError("source closure file count is invalid")
    if type(source["source_closure_sha256"]) is not str or DIGEST_RE.fullmatch(source["source_closure_sha256"]) is None:
        raise CaptureError("source closure digest is invalid")
    return source


def _validate_workloads(value: Any, *, verify_local: bool) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) != len(WORKLOAD_IDS):
        raise CaptureError("capture workload cardinality changed")
    result: list[dict[str, Any]] = []
    for expected_id, item in zip(WORKLOAD_IDS, value, strict=True):
        workload = exact_object(item, {"id", "elf", "input", "generator", "parameters"}, "workload")
        if workload["id"] != expected_id:
            raise CaptureError("capture workload order or identity changed")
        _validate_file(workload["elf"], f"workload {expected_id} ELF", verify_local=verify_local)
        generated = GENERATED_WORKLOADS.get(expected_id)
        if generated is None:
            if any(workload[key] is not None for key in ("input", "generator", "parameters")):
                raise CaptureError(f"fixed workload {expected_id} gained generated authority")
        else:
            if workload["generator"] != generated:
                raise CaptureError(f"generated workload {expected_id} authority changed")
            identity = _validate_file(workload["input"], f"workload {expected_id} input", verify_local=verify_local)
            parameters = exact_object(
                workload["parameters"],
                {
                    "schema",
                    "schema_version",
                    "calls",
                    "width",
                    "encoding_word_bytes",
                },
                "generated parameters",
            )
            expected_parameters = GENERATED_WORKLOAD_PARAMETERS[expected_id]
            if parameters != expected_parameters:
                raise CaptureError(
                    f"generated workload {expected_id} geometry changed"
                )
            if verify_local and _validate_generated_input(
                Path(identity["path"]), expected_id
            ) != parameters:
                raise CaptureError(f"generated workload {expected_id} input semantics changed")
        result.append(workload)
    return result


def validate_plan(
    value: Any,
    *,
    repository: Path,
    verify_local: bool,
    source_provider: SourceProvider = source_identity,
    closure_provider: ClosureProvider = global_exact_work_closure,
) -> dict[str, Any]:
    plan = exact_object(value, ROOT_FIELDS, "R-006 capture plan")
    exact = {
        "schema": PLAN_SCHEMA,
        "schema_version": PLAN_VERSION,
        "classification": "pre-execution-capture-authority",
        "security": "secure",
        "environment": ENVIRONMENT,
    }
    for key, expected in exact.items():
        if type(plan[key]) is not type(expected) or plan[key] != expected:
            raise CaptureError(f"capture plan {key} identity changed")
    if type(plan["session_id"]) is not str or SESSION_RE.fullmatch(plan["session_id"]) is None:
        raise CaptureError("capture plan session ID is invalid")
    if type(plan["created_at_utc"]) is not str or UTC_RE.fullmatch(plan["created_at_utc"]) is None:
        raise CaptureError("capture plan timestamp is not canonical UTC")
    if plan["protocol"] != _protocol(repository):
        raise CaptureError("capture protocol identity changed")
    source = _validate_source(plan["source"])
    if verify_local and source_provider(repository.resolve()) != source:
        raise CaptureError("capture source changed after planning")
    closure = validate_global_exact_work_closure(
        plan["global_exact_work_closure"]
    )
    if verify_local:
        live_closure = validate_global_exact_work_closure(
            closure_provider(repository.resolve())
        )
        if live_closure != closure:
            raise CaptureError(
                "P-003 global exact-work closure changed after planning"
            )
    host = validate_host(plan["host"])
    if host["os"] != "Darwin":
        raise CaptureError(
            "R-006 v1 requires Darwin RUSAGE_INFO_V6 resource authority"
        )
    if host["physical_cores"] < 4:
        raise CaptureError("capture host no longer admits M7")
    lane = exact_object(
        plan["lane"],
        {"id", "backend", "cli_backend", "runtime_mode"},
        "capture lane",
    )
    if (
        lane["id"] not in LANES
        or lane["backend"] != LANES[lane["id"]]["backend"]
        or lane["cli_backend"] != LANES[lane["id"]]["cli_backend"]
    ):
        raise CaptureError("capture lane identity changed")
    expected_runtime = "native" if lane["id"] == "cpu-native" else "declared-metal-runtime"
    if lane["runtime_mode"] != expected_runtime:
        raise CaptureError("capture runtime mode changed")
    expected_worker_environment = {
        "STWO_ZIG_WORKERS": "attempt.worker_count",
        "STWO_ZIG_MERKLE_WORKERS": "attempt.worker_count",
        "STWO_ZIG_POW_WORKERS": "unset:reuse-proof-pool",
    }
    if plan["worker_environment"] != expected_worker_environment:
        raise CaptureError("capture worker-environment policy changed")
    build = exact_object(plan["build"], BUILD_FIELDS, "capture build")
    for key in ("toolchain", "target", "cpu_features"):
        if type(build[key]) is not str or not build[key]:
            raise CaptureError(f"capture build {key} is empty")
    expected_lane = LANES[lane["id"]]
    if build["build_step"] != expected_lane["build_step"] or build["optimization_mode"] != "ReleaseFast":
        raise CaptureError("capture build authority changed")
    executable_identity = {
        "path": build["executable_path"],
        "bytes": build["executable_bytes"],
        "sha256": build["executable_sha256"],
    }
    _validate_file(executable_identity, "capture executable", verify_local=verify_local, executable=True)
    if verify_local:
        _require_binary_markers(Path(build["executable_path"]))
    _validate_workloads(plan["workloads"], verify_local=verify_local)
    max_workers = min(8, host["physical_cores"])
    expected_arms = {
        "reference": 1,
        "two": 2,
        "four": 4,
        "max": max_workers,
        "max_rule": "min(8,physical_cores)",
    }
    if plan["worker_arms"] != expected_arms:
        raise CaptureError("capture worker arms changed")
    expected_schedule = {
        "fresh_process_per_attempt": True,
        "serial_attempts": True,
        "warmups_per_arm": WARMUPS_PER_ARM,
        "rounds": ROUNDS,
        "proofs_per_arm_per_round": PAIRS_PER_ROUND,
        "cooldown_ns": COOLDOWN_NS,
        "retry_failed_attempts": False,
        "drop_outliers": False,
        "attempts": PLAN_ATTEMPTS,
        "pairing": "round-level alternating AB/BA",
    }
    if plan["schedule"] != expected_schedule:
        raise CaptureError("capture schedule metadata changed")
    attempts = plan["attempts"]
    if type(attempts) is not list or len(attempts) != PLAN_ATTEMPTS:
        raise CaptureError("capture attempt cardinality changed")
    for item in attempts:
        exact_object(item, ATTEMPT_FIELDS, "capture attempt")
    if attempts != _attempts(lane["id"], max_workers):
        raise CaptureError("capture attempt order differs from frozen schedule")
    if type(plan["content_sha256"]) is not str or DIGEST_RE.fullmatch(plan["content_sha256"]) is None:
        raise CaptureError("capture plan digest is invalid")
    if plan["content_sha256"] != content_digest(plan):
        raise CaptureError("capture plan content digest mismatch")
    return plan


def write_plan_new(path: Path, plan: dict[str, object]) -> bytes:
    payload = canonical_bytes(plan)
    write_new(path, payload)
    return payload


def load_plan(
    path: Path,
    *,
    repository: Path,
    verify_local: bool = True,
    source_provider: SourceProvider = source_identity,
    closure_provider: ClosureProvider = global_exact_work_closure,
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CaptureError(f"cannot read capture plan: {path}") from error
    value = decode_strict(raw)
    validate_plan(
        value,
        repository=repository.resolve(),
        verify_local=verify_local,
        source_provider=source_provider,
        closure_provider=closure_provider,
    )
    if raw != canonical_bytes(value):
        raise CaptureError("capture plan is not canonical JSON")
    return value
