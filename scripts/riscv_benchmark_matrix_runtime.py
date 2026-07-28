"""Identity, command capture, and semantic-oracle runtime for the RISC-V matrix."""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import scripts.riscv_benchmark_matrix_contract as contract
import scripts.riscv_benchmark_matrix_model as model
from scripts.riscv_release_oracle_lib import build_cache
from scripts.riscv_release_oracle_lib.oracle_build import build_oracle, resolve_build_inputs
from scripts.riscv_release_oracle_lib.public_values import (
    IMPLEMENTATION_REPOSITORY,
    PINNED_STARK_V,
    PUBLIC_DATA_FIELDS,
    validate_public_data_shape,
)
from scripts.riscv_stark_v_benchmark import (
    MIN_RUST_PARALLELISM,
    collect_host_environment,
)


ROOT = model.ROOT
DEFAULT_CANDIDATE_CLI = ROOT / "zig-out/bin/stwo-zig-riscv-cpu"
DEFAULT_TRACE_CLI = ROOT / "zig-out/bin/riscv-trace-dump"
MAX_COMMAND_OUTPUT = 64 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 3_600
STARK_V_BUILD_COMMAND = (
    "cargo", "build", "--locked", "--release", "-p", "bench-cli",
    "--features", "parallel",
)
UNSUPPORTED_PROOF_FAMILY_STDERR = (
    "stark-v adapter: error=UnsupportedProofFamily "
    "stage=statement_validation_before_first_commitment "
    "limitation=stark-v-signed-mulh\n"
).encode()
METAL = {
    "status": "gated",
    "reason": "riscv_adapter_cpu_only_and_stark_v_has_no_riscv_metal_prover",
}
PROTOCOL = {
    "name": "functional",
    "candidate": {
        "pow_bits": 10,
        "fri": {
            "log_blowup_factor": 1,
            "log_last_layer_degree_bound": 0,
            "n_queries": 3,
            "fold_step": 1,
        },
    },
    "stark_v": {
        "constructor": "PcsConfig::default()",
        "pow_bits": 10,
        "fri": {
            "log_blowup_factor": 1,
            "log_last_layer_degree_bound": 0,
            "n_queries": 3,
            "fold_step": 1,
        },
    },
    "matched": True,
}


class MatrixRunError(ValueError):
    pass


@dataclass(frozen=True)
class Capture:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ns: int
    cpu_time_ns: int
    stdout_identity: dict[str, Any]
    stderr_identity: dict[str, Any]

    @property
    def cpu_wall_ratio(self) -> float:
        return max(self.cpu_time_ns / self.duration_ns, 1e-12)


class EvidenceStore:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=False)

    def write(self, relative: str, raw: bytes) -> dict[str, Any]:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_bytes(raw)
        os.replace(temporary, path)
        return {
            "path": relative,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }


def safe_id(row_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", row_id)


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def canonical_digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def file_identity(path: Path, *, path_label: str | None = None) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size <= 0:
        raise MatrixRunError(f"missing, symlinked, or empty file: {path}")
    return {
        "path": path_label or str(path.resolve()),
        "sha256": model.sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _run_git(args: list[str]) -> bytes:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, check=False, capture_output=True,
    )
    if result.returncode != 0:
        raise MatrixRunError(
            f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def candidate_identity(
    candidate_cli: Path,
    trace_cli: Path,
    *,
    allow_dirty: bool,
) -> dict[str, Any]:
    head = _run_git(["rev-parse", "--verify", "HEAD"]).decode().strip()
    tree = _run_git(["rev-parse", "HEAD^{tree}"]).decode().strip()
    if re.fullmatch(r"[0-9a-f]{40,64}", head) is None or re.fullmatch(r"[0-9a-f]{40,64}", tree) is None:
        raise MatrixRunError("candidate Git commit/tree identity is invalid")
    status = _run_git(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
    dirty = bool(status)
    if dirty and not allow_dirty:
        raise MatrixRunError("candidate checkout is dirty; pass --allow-dirty only for local diagnostics")
    diff = _run_git(["diff", "--binary", "--no-ext-diff", "HEAD", "--"])
    untracked_raw = _run_git(["ls-files", "--others", "--exclude-standard", "-z"])
    untracked: list[dict[str, str]] = []
    for raw_path in filter(None, untracked_raw.split(b"\0")):
        relative = raw_path.decode("utf-8", errors="strict")
        path = ROOT / relative
        if path.is_symlink():
            digest = hashlib.sha256(os.readlink(path).encode()).hexdigest()
        elif path.is_file():
            digest = model.sha256_file(path)
        else:
            raise MatrixRunError(f"untracked path is not a regular file: {relative}")
        untracked.append({"path": relative, "sha256": digest})
    worktree_payload = {
        "status_sha256": hashlib.sha256(status).hexdigest(),
        "diff_sha256": hashlib.sha256(diff).hexdigest(),
        "untracked": untracked,
    }
    return {
        "repository": IMPLEMENTATION_REPOSITORY,
        "commit": head,
        "git_tree": tree,
        "dirty": dirty,
        "worktree_identity_sha256": canonical_digest(worktree_payload),
        "git_status_sha256": worktree_payload["status_sha256"],
        "git_diff_sha256": worktree_payload["diff_sha256"],
        "untracked_files": untracked,
        "executables": {
            "riscv_cpu": file_identity(candidate_cli),
            "trace_dump": file_identity(trace_cli),
        },
    }


def _rust_timing_binary(source: Path, build_inputs: Any) -> Path:
    target_root = source / "target"
    if build_inputs.rust["target_layout"] == "explicit":
        target_root /= str(build_inputs.rust["target"])
    return target_root / "release/stark-v-bench"


def prepare_oracle(
    source: Path,
    cache_dir: Path | None,
    store: EvidenceStore,
) -> tuple[Path, Path, dict[str, Any]]:
    source = source.resolve(strict=True)
    before = resolve_build_inputs(source, PINNED_STARK_V)
    receipt: dict[str, Any] = {}
    cp11 = build_oracle(source, receipt, PINNED_STARK_V, cache_dir)
    build_started = time.monotonic_ns()
    try:
        result = subprocess.run(
            list(STARK_V_BUILD_COMMAND),
            cwd=source,
            check=False,
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise MatrixRunError("stark-v-bench locked parallel build timed out") from error
    build_duration = max(1, time.monotonic_ns() - build_started)
    build_stdout = store.write("oracle-build/stark-v-bench.stdout", result.stdout)
    build_stderr = store.write("oracle-build/stark-v-bench.stderr", result.stderr)
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).decode(errors="replace")[-4096:]
        raise MatrixRunError(f"stark-v-bench locked parallel build failed: {diagnostic}")
    after = resolve_build_inputs(source, PINNED_STARK_V)
    if before.identity != after.identity:
        raise MatrixRunError("Stark-V source/build identity changed while preparing timing lane")
    timing_binary = _rust_timing_binary(source, after)
    correctness = dict(receipt["oracle"])
    correctness["executable"] = file_identity(cp11)
    timing = {
        "repository": correctness["repository"],
        "commit": PINNED_STARK_V,
        "source_build_identity_sha256": build_cache.cache_key(after.identity),
        "source_build_identity": after.identity,
        "build_command": list(STARK_V_BUILD_COMMAND),
        "features": ["parallel"],
        "build_duration_ns": build_duration,
        "build_stdout": build_stdout,
        "build_stderr": build_stderr,
        "executable": file_identity(timing_binary),
    }
    return cp11, timing_binary, {"correctness": correctness, "timing": timing}


def run_capture(
    argv: list[str],
    store: EvidenceStore,
    relative_prefix: str,
    *,
    env: dict[str, str] | None = None,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> Capture:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            argv,
            cwd=ROOT,
            check=False,
            capture_output=True,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise MatrixRunError(f"command timed out: {' '.join(argv)}") from error
    duration = max(1, time.monotonic_ns() - started)
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu_seconds = after.ru_utime - before.ru_utime + after.ru_stime - before.ru_stime
    cpu_ns = max(1, round(cpu_seconds * 1_000_000_000))
    if len(result.stdout) > MAX_COMMAND_OUTPUT or len(result.stderr) > MAX_COMMAND_OUTPUT:
        raise MatrixRunError(f"command output exceeded {MAX_COMMAND_OUTPUT} bytes")
    stdout_identity = store.write(f"{relative_prefix}.stdout", result.stdout)
    stderr_identity = store.write(f"{relative_prefix}.stderr", result.stderr)
    return Capture(
        argv=tuple(argv),
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_ns=duration,
        cpu_time_ns=cpu_ns,
        stdout_identity=stdout_identity,
        stderr_identity=stderr_identity,
    )


def successful(capture: Capture, label: str) -> None:
    if capture.returncode != 0:
        diagnostic = (capture.stderr or capture.stdout).decode(errors="replace")[-4096:]
        raise MatrixRunError(f"{label} failed ({capture.returncode}): {diagnostic}")


def input_args(workload: model.Workload) -> list[str]:
    return ["--input", str(ROOT / workload.input_rel)] if workload.input_rel else []


def _input_bytes(workload: model.Workload) -> bytes:
    return (ROOT / workload.input_rel).read_bytes() if workload.input_rel else b""


def validate_public_input(public: dict[str, Any], workload: model.Workload, label: str) -> None:
    io = public["io_entries"]
    encoded = b"".join(word.to_bytes(4, "little") for word in io["input_words"])
    actual = encoded[:io["input_len"]]
    if actual != _input_bytes(workload) or hashlib.sha256(actual).hexdigest() != workload.input_sha256:
        raise MatrixRunError(f"{label}: public input does not bind the fixture bytes")


def semantic_summary(
    public: dict[str, Any],
    source: dict[str, Any],
    duration_ns: int,
) -> dict[str, Any]:
    return {
        "total_steps": public["clock"],
        "final_pc": public["final_pc"],
        "final_regs_sha256": canonical_digest(public["final_regs"]),
        "public_data_sha256": canonical_digest(public),
        "source": source,
        "duration_ns": duration_ns,
    }


def run_oracle_semantics(
    cp11: Path,
    workload: model.Workload,
    store: EvidenceStore,
) -> tuple[dict[str, Any], dict[str, Any]]:
    safe = safe_id(workload.row_id)
    argv = [
        str(cp11), "--elf", str(ROOT / workload.elf_rel),
        "--max-steps", str(workload.max_steps), *input_args(workload),
    ]
    capture = run_capture(argv, store, f"logs/{safe}.oracle-semantics")
    successful(capture, f"{workload.row_id}: legacy Stark-V execution comparator")
    payload = contract.strict_json_bytes(
        capture.stdout, f"{workload.row_id} legacy comparator output"
    )
    if set(payload) != {"trace", "public_data"}:
        raise MatrixRunError(f"{workload.row_id}: legacy comparator fields drifted")
    trace = payload["trace"]
    if not isinstance(trace, dict) or set(trace) != {"final_pc", "final_regs", "total_steps"}:
        raise MatrixRunError(f"{workload.row_id}: legacy comparator trace fields drifted")
    public = validate_public_data_shape(
        payload["public_data"], "legacy comparator public_data"
    )
    if (
        trace["total_steps"] != public["clock"]
        or trace["final_pc"] != public["final_pc"]
        or trace["final_regs"] != public["final_regs"]
    ):
        raise MatrixRunError(
            f"{workload.row_id}: legacy comparator trace/public-data self-check failed"
        )
    validate_public_input(public, workload, "legacy comparator")
    if workload.suite == "corpus" and (
        public["clock"] != workload.fixture["expected_total_steps"]
        or public["final_pc"] != workload.fixture["expected_final_pc"]
    ):
        raise MatrixRunError(
            f"{workload.row_id}: legacy comparator differs from corpus metadata"
        )
    return public, semantic_summary(public, capture.stdout_identity, capture.duration_ns)


def semantic_parity(oracle: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    mismatches = [field for field in PUBLIC_DATA_FIELDS if oracle[field] != candidate[field]]
    if mismatches:
        raise MatrixRunError(
            f"benchmark execution mismatch against legacy comparator: "
            f"{', '.join(mismatches)}"
        )
    digest = canonical_digest(oracle)
    if digest != canonical_digest(candidate):
        raise MatrixRunError("semantic public-data digest differs despite field comparison")
    return {
        "status": "pass",
        "fields": list(PUBLIC_DATA_FIELDS),
        "mismatches": [],
        "public_data_sha256": digest,
    }
