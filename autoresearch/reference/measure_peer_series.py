#!/usr/bin/env python3
"""Measure the exact PR6 width-100 series at steady and cold boundaries.

This runner is deliberately fail closed. It creates immutable, same-host raw
evidence for logs 14, 16, 18, 20, and 22 with independent CPU and Metal ABBA
comparisons. It is one required slice of the disabled ``pr6_supremacy`` board;
it does not claim the still-missing exact Blake, Plonk, fixed-wide-Fibonacci,
or state-machine cells.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.process_resources_lib.collector import (  # noqa: E402
    measurement_command,
    measurement_environment,
    parse_process_resources,
)

SCHEMA = "peer-relative-wide-fibonacci-series-point-v2"
SERIES_ID = "clementwalter-pr6-wide-fibonacci-v2"
PEER_REPOSITORY = "https://github.com/ClementWalter/stwo"
PEER_COMMIT = "07ea1ccca13351028da94e66babf79e7ce91437f"
RUST_TOOLCHAIN = "nightly-2025-07-14"
LOG_SIZES = (14, 16, 18, 20, 22)
N_COLUMNS = 100
ACCOUNTED_BYTES_PER_COMMITTED_CELL = 16
MIN_ABBA_ROUNDS = 7
VERIFIED_WARMUPS = 10
BOOTSTRAP_ITERATIONS = 20_000
BOUNDARIES = ("verified_request", "cold_process")
COMPARISONS = {
    "cpu": ("peer_cpu", "zig_cpu"),
    "metal": ("peer_metal", "zig_metal"),
}
LANES = tuple(lane for pair in COMPARISONS.values() for lane in pair)
RESOURCE_PROFILE_BY_LOG = {
    14: "standard",
    16: "standard",
    18: "large",
    20: "large",
    22: "extreme",
}
GATE_MEDIAN_RATIO = 0.80
GATE_CI_HIGH = 0.90


class SeriesError(RuntimeError):
    pass


def run(cmd: list[str], cwd: Path, timeout: float = 7200) -> tuple[str, float]:
    started = time.perf_counter()
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    wall_ms = (time.perf_counter() - started) * 1000.0
    if proc.returncode != 0:
        rendered = " ".join(cmd[:8])
        raise SeriesError(f"{rendered} failed:\n{proc.stderr[-2400:]}\n{proc.stdout[-1200:]}")
    return proc.stdout, wall_ms


def run_measured(
    cmd: list[str], cwd: Path, timeout: float = 7200,
) -> tuple[str, float, dict]:
    measured, measurement = measurement_command(cmd, required=True)
    started = time.perf_counter()
    proc = subprocess.run(
        measured,
        cwd=cwd,
        env=measurement_environment(),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    wall_ms = (time.perf_counter() - started) * 1000.0
    if proc.returncode != 0:
        rendered = " ".join(cmd[:8])
        raise SeriesError(f"{rendered} failed:\n{proc.stderr[-2400:]}\n{proc.stdout[-1200:]}")
    parsed = parse_process_resources(proc.stderr, measurement, require_peak_rss=True)
    peak_rss_kib = parsed["peak_rss_kib"]
    resources = {
        "source": measurement,
        "peak_rss_bytes": int(peak_rss_kib) * 1024,
        "peak_memory_footprint_bytes": parsed["peak_memory_footprint_bytes"],
        "energy_nj": None,
        "instructions": parsed["instructions_retired"],
        "cycles": parsed["cycles_elapsed"],
        "allocation_failure": False,
    }
    return proc.stdout, wall_ms, resources


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def sha256_tracked_tree(repo: Path, prefix: str | None = None) -> str:
    command = ["git", "ls-files", "-z"]
    if prefix is not None:
        command.extend(("--", prefix))
    proc = subprocess.run(command, cwd=repo, capture_output=True, check=True)
    digest = hashlib.sha256()
    for raw_path in filter(None, proc.stdout.split(b"\0")):
        relative = raw_path.decode("utf-8")
        path = repo / relative
        if not path.is_file():
            raise SeriesError(f"tracked source disappeared during digest: {relative}")
        digest.update(len(raw_path).to_bytes(8, "little"))
        digest.update(raw_path)
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def _optional_command(command: list[str]) -> str | None:
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (proc.stdout + proc.stderr).strip()
    return output if proc.returncode == 0 and output else None


def host_identity() -> dict:
    processor = platform.processor() or "unknown cpu"
    if platform.system() == "Darwin":
        processor = _optional_command(["sysctl", "-n", "machdep.cpu.brand_string"]) or processor
    return {
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "processor": processor,
        "logical_cpu_count": os.cpu_count(),
        "load_average": list(os.getloadavg()),
        "thermal_state": {
            "pmset_thermlog": _optional_command(["pmset", "-g", "thermlog"]),
            "cpu_thermal_level": _optional_command(
                ["sysctl", "-n", "machdep.xcpm.cpu_thermal_level"]
            ),
        },
    }


def abba_order(comparison: str) -> list[str]:
    try:
        peer, candidate = COMPARISONS[comparison]
    except KeyError as exc:
        raise SeriesError(f"unknown comparison: {comparison}") from exc
    return [peer, candidate, candidate, peer]


def _git(repo: Path, *args: str) -> str:
    stdout, _ = run(["git", *args], repo)
    return stdout.strip()


def assert_clean_checkout(repo: Path, allow_dirty: bool) -> str:
    commit = _git(repo, "rev-parse", "HEAD")
    dirty = _git(repo, "status", "--porcelain", "--untracked-files=no")
    if dirty and not allow_dirty:
        raise SeriesError("peer series requires a clean committed stwo-zig checkout")
    return commit


def assert_resource_profiles(repo: Path, zig_cpu: Path) -> None:
    proc = subprocess.run([str(zig_cpu), "--help"], cwd=repo, capture_output=True, text=True)
    help_text = proc.stdout + proc.stderr
    required = ("--resource-profile", "large", "extreme")
    if proc.returncode != 0 or any(token not in help_text for token in required):
        raise SeriesError(
            "stwo-zig audit commit lacks explicit large and extreme resource profiles "
            "required for log18/log20 and log22"
        )


def _cargo_build(repo: Path, target_dir: Path, *, metal: bool) -> tuple[Path, list[str]]:
    command = [
        "cargo",
        f"+{RUST_TOOLCHAIN}",
        "build",
        "--release",
        "--locked",
        "--manifest-path",
        "autoresearch/tools/current-stwo-fib-bench/Cargo.toml",
        "--target-dir",
        str(target_dir),
    ]
    if metal:
        command.extend(("--features", "metal"))
    run(command, repo)
    binary = target_dir / "release/peer-stwo-fib-bench"
    if not binary.is_file():
        raise SeriesError(f"peer adapter build did not create {binary}")
    return binary, command


def prepare_binaries(repo: Path, build_root: Path) -> tuple[dict[str, Path], dict]:
    peer_cpu, peer_cpu_build = _cargo_build(repo, build_root / "peer-cpu", metal=False)
    peer_metal, peer_metal_build = _cargo_build(repo, build_root / "peer-metal", metal=True)
    zig_cpu_build = ["zig", "build", "benchmark-native-cpu", "-Doptimize=ReleaseFast"]
    zig_metal_build = ["zig", "build", "native-proof-bench-metal", "-Doptimize=ReleaseFast"]
    run(zig_cpu_build, repo)
    run(zig_metal_build, repo)
    binaries = {
        "peer_cpu": peer_cpu,
        "peer_metal": peer_metal,
        "zig_cpu": repo / "zig-out/bin/stwo-zig-native-cpu-bench",
        "zig_metal": repo / "zig-out/bin/native-proof-bench-metal",
    }
    for lane, binary in binaries.items():
        if not binary.is_file():
            raise SeriesError(f"missing {lane} binary: {binary}")
    return binaries, {
        "peer_cpu": peer_cpu_build,
        "peer_metal": peer_metal_build,
        "zig_cpu": zig_cpu_build,
        "zig_metal": zig_metal_build,
    }


def _protocol_from_peer(report: dict) -> dict:
    return {
        "channel": "Blake2sM31Channel/Blake2sM31MerkleChannel",
        "pow_bits": report.get("pow_bits"),
        "log_blowup_factor": report.get("log_blowup_factor"),
        "log_last_layer_degree_bound": report.get("log_last_layer_degree_bound"),
        "n_queries": report.get("fri_queries"),
        "fold_step": report.get("fold_step"),
        "security_bits": report.get("security_bits"),
    }


def _protocol_from_zig(report: dict) -> dict:
    source = report.get("protocol", {})
    pow_bits = source.get("pow_bits")
    blowup = source.get("log_blowup_factor")
    queries = source.get("n_queries")
    security_bits = (
        pow_bits + blowup * queries
        if all(isinstance(value, int) for value in (pow_bits, blowup, queries))
        else None
    )
    return {
        "channel": "Blake2sM31Channel/Blake2sM31MerkleChannel",
        "pow_bits": pow_bits,
        "log_blowup_factor": blowup,
        "log_last_layer_degree_bound": source.get("log_last_layer_degree_bound"),
        "n_queries": queries,
        "fold_step": source.get("fold_step"),
        "security_bits": security_bits,
    }


def _descriptor(log_size: int) -> dict:
    return {
        "air": "PR6 WideFibonacciEval<100>",
        "log_n_rows": log_size,
        "rows": 1 << log_size,
        "width": N_COLUMNS,
        "initial_rows": "(M31::one(), M31::from_u32_unchecked(row_index))",
        "recurrence": "c = a^2 + b^2",
    }


def _admission(log_size: int, profile: str) -> dict:
    cells = (1 << log_size) * N_COLUMNS
    return {
        "profile": profile,
        "committed_cells": cells,
        "accounted_bytes": cells * ACCOUNTED_BYTES_PER_COMMITTED_CELL,
        "accounted_bytes_per_committed_cell": ACCOUNTED_BYTES_PER_COMMITTED_CELL,
    }


def _one_peer(
    repo: Path,
    binary: Path,
    lane: str,
    log_size: int,
    warmups: int,
    scratch: Path,
    invocation_id: str,
) -> dict:
    output = scratch / f"{invocation_id}.json"
    stdout, wall_ms, resources = run_measured([
        str(binary), lane.replace("_", "-"), str(log_size), str(warmups), "1", str(output)
    ], repo)
    if stdout.strip():
        raise SeriesError(f"{lane} wrote unexpected stdout")
    report = json.loads(output.read_text())
    expected_backend = lane.replace("_", "-")
    if report.get("schema") != "peer-stwo-wide-fibonacci-adapter-v2":
        raise SeriesError(f"{lane} adapter schema mismatch")
    if report.get("peer_source_commit") != PEER_COMMIT:
        raise SeriesError(f"{lane} source commit mismatch")
    if report.get("backend") != expected_backend:
        raise SeriesError(f"{lane} backend mismatch")
    if report.get("backend_type") != "stwo::prover::backend::cpu::CpuBackend":
        raise SeriesError(f"{lane} backend type mismatch")
    if report.get("n_columns") != N_COLUMNS or report.get("log_n_instances") != log_size:
        raise SeriesError(f"{lane} workload mismatch")
    if report.get("warmups") != warmups or report.get("samples") != 1:
        raise SeriesError(f"{lane} sample schedule mismatch")
    if not report.get("all_verified") or not report.get("all_proofs_identical"):
        raise SeriesError(f"{lane} proof receipt failed")
    features = set(report.get("cargo_features", []))
    if lane == "peer_metal":
        if "metal" not in features or report.get("metal_device_admitted") is not True:
            raise SeriesError("peer_metal did not admit the compiled real Metal feature")
        # This is an exact peer property, not candidate policy: PR6's own
        # generate_trace_cpu_metal() deliberately returns None below 2^16.
        # Preserve and publish that log14 CPU-parallel trace path rather than
        # rewriting the pinned peer or pretending it dispatched Metal work.
        expected_trace_backend = "cpu-parallel" if log_size < 16 else "metal"
        if report.get("trace_generation_backend") != expected_trace_backend:
            raise SeriesError(
                f"peer_metal trace backend mismatch: expected {expected_trace_backend}"
            )
    elif "metal" in features or report.get("metal_device_admitted") is not False:
        raise SeriesError("peer_cpu unexpectedly admitted Metal")
    protocol = _protocol_from_peer(report)
    if not all(isinstance(value, int) and value >= 0 for value in protocol.values() if value != protocol["channel"]):
        raise SeriesError(f"{lane} omitted concrete peer protocol parameters")
    admission = _admission(log_size, "peer-unbounded")
    prove_ms = float(report["prove_samples_ms"][0])
    request_ms = float(report["verified_request_samples_ms"][0])
    return {
        "lane": lane,
        "reported_prove_ms": prove_ms,
        "verified_request_ms": request_ms,
        "invocation_wall_ms": wall_ms,
        "trace_row_mhz": (1 << log_size) / prove_ms / 1000.0,
        "committed_cell_mhz": admission["committed_cells"] / prove_ms / 1000.0,
        "proof_identity": {
            "scheme": "sha256(serde_json(StarkProof))",
            "digest": report["proof_canonical_sha256"],
            "bytes_hashed": report["proof_canonical_bytes"],
        },
        "verified": True,
        "timing_scope": report["timing_scope"],
        "protocol": protocol,
        "protocol_sha256": sha256_json(protocol),
        "statement_sha256": sha256_json(_descriptor(log_size)),
        "resource_admission": admission,
        "process_resources": resources,
        "metal_device_admitted": report["metal_device_admitted"],
        "trace_generation_backend": report["trace_generation_backend"],
        "peer_reference_cpu_trace_path": (
            lane == "peer_metal" and report["trace_generation_backend"] == "cpu-parallel"
        ),
        "metal_dispatches": None,
        "metal_synchronization_points": None,
        "metal_cpu_fallbacks": 0 if lane == "peer_metal" else None,
        "raw_report_sha256": sha256_file(output),
    }


def _one_zig(
    repo: Path,
    binary: Path,
    lane: str,
    log_size: int,
    warmups: int,
) -> dict:
    command = [str(binary)]
    if lane == "zig_metal":
        command.extend(("bench", "--metal-runtime", "source-jit"))
    profile = RESOURCE_PROFILE_BY_LOG[log_size]
    command.extend((
        "--example", "wide_fibonacci",
        "--log-n-rows", str(log_size),
        "--sequence-len", str(N_COLUMNS),
        "--protocol", "functional",
        "--warmups", str(warmups),
        "--samples", "1",
        "--resource-profile", profile,
    ))
    stdout, wall_ms, resources = run_measured(command, repo)
    report = json.loads(stdout)
    workload = report.get("workload", {})
    parameters = workload.get("parameters", {})
    if workload.get("name") != "wide_fibonacci":
        raise SeriesError(f"{lane} workload name mismatch")
    if parameters != {"log_n_rows": log_size, "sequence_len": N_COLUMNS}:
        raise SeriesError(f"{lane} workload parameters mismatch")
    if report.get("protocol", {}).get("name") != "functional":
        raise SeriesError(f"{lane} protocol mismatch")
    proof = report.get("proof", {})
    if proof.get("verified_samples") != 1 or not proof.get("all_samples_byte_identical"):
        raise SeriesError(f"{lane} proof receipt failed")
    telemetry = report.get("backend_telemetry")
    sample_telemetry = None
    if lane == "zig_metal":
        telemetry = telemetry or {}
        if telemetry.get("total_cpu_fallbacks") != 0 or not telemetry.get("valid"):
            raise SeriesError("zig_metal did not provide zero-fallback valid telemetry")
        runtime = report.get("runtime_admission") or {}
        if runtime.get("origin") != "diagnostic_source_jit":
            raise SeriesError("zig_metal did not use the declared source-JIT runtime")
        samples = telemetry.get("samples") or []
        if len(samples) != 1:
            raise SeriesError("zig_metal omitted per-sample backend telemetry")
        sample_telemetry = samples[0]
        if sample_telemetry.get("cpu_fallbacks") != 0:
            raise SeriesError("zig_metal sample reported a CPU fallback")
    admission = report.get("resource_admission") or {}
    expected_admission = _admission(log_size, profile)
    for key in ("profile", "committed_cells", "accounted_bytes", "accounted_bytes_per_committed_cell"):
        if admission.get(key) != expected_admission[key]:
            raise SeriesError(f"{lane} resource admission mismatch for {key}")
    protocol = _protocol_from_zig(report)
    sample = report["timing"]["samples"][0]
    prove_ms = float(sample["prove_seconds"]) * 1000.0
    request_ms = float(sample["request_seconds"]) * 1000.0
    return {
        "lane": lane,
        "reported_prove_ms": prove_ms,
        "verified_request_ms": request_ms,
        "invocation_wall_ms": wall_ms,
        "trace_row_mhz": float(sample["trace_row_mhz"]),
        "committed_cell_mhz": float(sample["committed_mcells_per_second"]),
        "proof_identity": {
            "scheme": "sha256(canonical-proof-wire)",
            "digest": proof["samples"][0]["sha256"],
            "bytes_hashed": proof["samples"][0]["bytes"],
        },
        "verified": True,
        "timing_scope": {
            "prove": "prepared-input handoff through proof construction",
            "verify": "independent verifier",
            "total": "input + prove + canonical encoding/hash + independent verify",
            "exclusions": "backend/session initialization, warmups, process startup",
        },
        "protocol": protocol,
        "protocol_sha256": sha256_json(protocol),
        "statement_sha256": sha256_json(_descriptor(log_size)),
        "resource_admission": expected_admission,
        "process_resources": resources,
        "reported_resources": report.get("resources"),
        "metal_runtime": report.get("runtime_admission") if lane == "zig_metal" else None,
        "metal_dispatches": (
            sample_telemetry.get("metal_dispatches") if sample_telemetry else None
        ),
        # The current Native report does not yet expose command-buffer waits.
        # Null is explicit missing evidence and keeps the supremacy board disabled.
        "metal_synchronization_points": None,
        "metal_cpu_fallbacks": (
            sample_telemetry.get("cpu_fallbacks") if sample_telemetry else None
        ),
    }


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _values(rounds: list[dict], lane: str, metric: str, half: int | None = None) -> list[float]:
    values = []
    for round_record in rounds:
        for sample in round_record["samples"]:
            if sample["lane"] == lane and (half is None or sample["abba_half"] == half):
                values.append(float(sample[metric]))
    return values


def _statistics(
    rounds: list[dict], peer: str, candidate: str, metric: str, seed_key: str,
) -> dict:
    peer_values = _values(rounds, peer, metric)
    candidate_values = _values(rounds, candidate, metric)
    median_ratio = statistics.median(candidate_values) / statistics.median(peer_values)
    half_ratios = {}
    for half in (1, 2):
        half_ratios[f"half_{half}"] = (
            statistics.median(_values(rounds, candidate, metric, half))
            / statistics.median(_values(rounds, peer, metric, half))
        )
    rng_seed = int.from_bytes(hashlib.sha256(seed_key.encode()).digest()[:8], "little")
    rng = random.Random(rng_seed)
    bootstrap = []
    for _ in range(BOOTSTRAP_ITERATIONS):
        selected = [rounds[rng.randrange(len(rounds))] for _ in rounds]
        selected_peer = [
            float(sample[metric]) for record in selected for sample in record["samples"]
            if sample["lane"] == peer
        ]
        selected_candidate = [
            float(sample[metric]) for record in selected for sample in record["samples"]
            if sample["lane"] == candidate
        ]
        bootstrap.append(
            statistics.median(selected_candidate) / statistics.median(selected_peer)
        )
    ci_low = _percentile(bootstrap, 0.025)
    ci_high = _percentile(bootstrap, 0.975)
    halves_win = all(ratio < 1.0 for ratio in half_ratios.values())
    return {
        "peer_median_ms": statistics.median(peer_values),
        "candidate_median_ms": statistics.median(candidate_values),
        "candidate_over_peer_median_ratio": median_ratio,
        "paired_bootstrap_95_ci": [ci_low, ci_high],
        "bootstrap_iterations": BOOTSTRAP_ITERATIONS,
        "bootstrap_unit": "ABBA round",
        "abba_half_ratios": half_ratios,
        "both_abba_halves_win": halves_win,
        "gate": {
            "median_ratio_at_most_0_80": median_ratio <= GATE_MEDIAN_RATIO,
            "ci_high_at_most_0_90": ci_high <= GATE_CI_HIGH,
            "both_abba_halves_win": halves_win,
            "passed": median_ratio <= GATE_MEDIAN_RATIO and ci_high <= GATE_CI_HIGH and halves_win,
        },
    }


def _measure_boundary(
    repo: Path,
    binaries: dict[str, Path],
    scratch: Path,
    *,
    log_size: int,
    comparison: str,
    boundary: str,
    rounds: int,
    verified_warmups: int,
) -> dict:
    peer, candidate = COMPARISONS[comparison]
    order = abba_order(comparison)
    warmups = verified_warmups if boundary == "verified_request" else 0
    round_records = []
    for round_index in range(rounds):
        samples = []
        for position, lane in enumerate(order):
            invocation_id = (
                f"log{log_size}-{comparison}-{boundary}-r{round_index}-p{position}-{lane}"
            )
            if lane.startswith("peer_"):
                sample = _one_peer(
                    repo, binaries[lane], lane, log_size, warmups, scratch, invocation_id,
                )
            else:
                sample = _one_zig(repo, binaries[lane], lane, log_size, warmups)
            sample.update({
                "round": round_index,
                "abba_position": position,
                "abba_half": 1 if position < 2 else 2,
                "boundary": boundary,
                "warmups_before_sample": warmups,
            })
            if boundary == "cold_process":
                sample["cold_process_ms"] = sample["invocation_wall_ms"]
            samples.append(sample)
        round_records.append({
            "round": round_index,
            "order": order,
            "samples": samples,
        })
    metric = "verified_request_ms" if boundary == "verified_request" else "cold_process_ms"
    return {
        "boundary": boundary,
        "warmups_before_each_timed_sample": warmups,
        "rounds": round_records,
        "statistics": _statistics(
            round_records,
            peer,
            candidate,
            metric,
            f"{log_size}:{comparison}:{boundary}",
        ),
    }


def _proof_receipt(comparisons: dict) -> dict:
    by_lane: dict[str, set[str]] = {lane: set() for lane in LANES}
    protocols: dict[str, set[str]] = {lane: set() for lane in LANES}
    statements: set[str] = set()
    verified = True
    zero_fallbacks = True
    synchronization_complete = True
    for comparison in comparisons.values():
        for boundary in comparison.values():
            for round_record in boundary["rounds"]:
                for sample in round_record["samples"]:
                    lane = sample["lane"]
                    by_lane[lane].add(sample["proof_identity"]["digest"])
                    protocols[lane].add(sample["protocol_sha256"])
                    statements.add(sample["statement_sha256"])
                    verified = verified and sample["verified"] is True
                    if lane == "zig_metal":
                        zero_fallbacks = zero_fallbacks and sample["metal_cpu_fallbacks"] == 0
                        synchronization_complete = (
                            synchronization_complete
                            and isinstance(sample["metal_synchronization_points"], int)
                        )
    stable = all(len(digests) == 1 for digests in by_lane.values())
    peer_equal = by_lane["peer_cpu"] == by_lane["peer_metal"]
    zig_equal = by_lane["zig_cpu"] == by_lane["zig_metal"]
    protocol_equal = len({next(iter(values)) for values in protocols.values()}) == 1
    if not stable or not peer_equal or not zig_equal or not protocol_equal or len(statements) != 1:
        raise SeriesError(
            "proof/protocol/statement equivalence failed: "
            f"proofs={by_lane}, protocols={protocols}, statements={statements}"
        )
    return {
        "all_samples_stable": stable,
        "peer_cpu_equals_peer_metal": peer_equal,
        "zig_cpu_equals_zig_metal": zig_equal,
        "peer_protocol_equals_zig_protocol": protocol_equal,
        "all_samples_verified": verified,
        "zig_metal_zero_cpu_fallbacks": zero_fallbacks,
        "metal_synchronization_telemetry_complete": synchronization_complete,
        "digests": {lane: next(iter(values)) for lane, values in by_lane.items()},
        "protocol_sha256": next(iter(protocols["peer_cpu"])),
        "statement_sha256": next(iter(statements)),
        "cross_implementation_byte_equality_claimed": False,
    }


def summarize_size(
    repo: Path,
    binaries: dict[str, Path],
    scratch: Path,
    log_size: int,
    rounds: int,
    verified_warmups: int,
) -> dict:
    comparisons = {}
    for comparison in COMPARISONS:
        comparisons[comparison] = {
            boundary: _measure_boundary(
                repo,
                binaries,
                scratch,
                log_size=log_size,
                comparison=comparison,
                boundary=boundary,
                rounds=rounds,
                verified_warmups=verified_warmups,
            )
            for boundary in BOUNDARIES
        }
    return {
        "cell_id": f"pr6_wide_fibonacci_log{log_size}",
        "log_n_rows": log_size,
        "rows": 1 << log_size,
        "n_columns": N_COLUMNS,
        "resource_profile": RESOURCE_PROFILE_BY_LOG[log_size],
        "committed_cells": (1 << log_size) * N_COLUMNS,
        "accounted_bytes": (1 << log_size) * N_COLUMNS * ACCOUNTED_BYTES_PER_COMMITTED_CELL,
        "descriptor": _descriptor(log_size),
        "comparisons": comparisons,
        "proof_equivalence": _proof_receipt(comparisons),
    }


def validate_point(point: dict) -> None:
    if point.get("schema") != SCHEMA or point.get("series_id") != SERIES_ID:
        raise SeriesError("peer series schema identity mismatch")
    peer = point.get("peer_source", {})
    if peer.get("repository") != PEER_REPOSITORY or peer.get("commit") != PEER_COMMIT:
        raise SeriesError("peer series source pin mismatch")
    contract = point.get("measurement_contract", {})
    if contract.get("abba_rounds", 0) < MIN_ABBA_ROUNDS:
        raise SeriesError("peer series requires at least seven paired ABBA rounds")
    if contract.get("verified_warmups") != VERIFIED_WARMUPS:
        raise SeriesError("peer series requires exactly ten verified warmups")
    sizes = point.get("sizes", [])
    if [item.get("log_n_rows") for item in sizes] != list(LOG_SIZES):
        raise SeriesError("peer series must contain exact log sizes 14,16,18,20,22")
    for size in sizes:
        if size.get("n_columns") != N_COLUMNS:
            raise SeriesError("peer series must use exactly 100 columns")
        if set(size.get("comparisons", {})) != set(COMPARISONS):
            raise SeriesError("peer series comparison set mismatch")
        for comparison_name, comparison in size["comparisons"].items():
            if set(comparison) != set(BOUNDARIES):
                raise SeriesError("peer series timing-boundary set mismatch")
            expected_order = abba_order(comparison_name)
            for boundary_name, boundary in comparison.items():
                rounds = boundary.get("rounds", [])
                if len(rounds) < MIN_ABBA_ROUNDS:
                    raise SeriesError("peer series boundary has too few ABBA rounds")
                for round_record in rounds:
                    if round_record.get("order") != expected_order:
                        raise SeriesError("peer series round is not A-B-B-A")
                    samples = round_record.get("samples", [])
                    if [sample.get("lane") for sample in samples] != expected_order:
                        raise SeriesError("peer series sample order mismatch")
                    if not all(sample.get("verified") is True for sample in samples):
                        raise SeriesError("peer series contains an unverified sample")
                    if boundary_name == "cold_process" and not all(
                        sample.get("warmups_before_sample") == 0
                        and sample.get("cold_process_ms", 0) > 0
                        for sample in samples
                    ):
                        raise SeriesError("cold-process boundary is contaminated by warmups")
        receipt = size.get("proof_equivalence", {})
        if not all(receipt.get(key) for key in (
            "all_samples_stable",
            "peer_cpu_equals_peer_metal",
            "zig_cpu_equals_zig_metal",
            "peer_protocol_equals_zig_protocol",
            "all_samples_verified",
            "zig_metal_zero_cpu_fallbacks",
        )):
            raise SeriesError("peer series proof receipt is incomplete")


def measure(
    repo: Path,
    binaries: dict[str, Path],
    builds: dict[str, list[str]],
    *,
    rounds: int,
    verified_warmups: int,
    allow_dirty: bool,
    log_sizes: tuple[int, ...] = LOG_SIZES,
) -> dict:
    if platform.system() != "Darwin":
        raise SeriesError("the PR6 CPU/Metal series requires macOS")
    if tuple(log_sizes) != LOG_SIZES:
        raise SeriesError("immutable series points cannot omit or select log sizes")
    zig_commit = assert_clean_checkout(repo, allow_dirty)
    assert_resource_profiles(repo, binaries["zig_cpu"])
    with tempfile.TemporaryDirectory(prefix="pr6-peer-series-") as raw:
        scratch = Path(raw)
        sizes = [
            summarize_size(repo, binaries, scratch, log_size, rounds, verified_warmups)
            for log_size in log_sizes
        ]

    rustc, _ = run(["rustc", f"+{RUST_TOOLCHAIN}", "--version", "--verbose"], repo)
    cargo, _ = run(["cargo", f"+{RUST_TOOLCHAIN}", "--version"], repo)
    zig_version, _ = run(["zig", "version"], repo)
    point = {
        "schema": SCHEMA,
        "series_id": SERIES_ID,
        "status": "diagnostic_until_full_pr6_matrix_and_sync_telemetry_exist",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "audit_point": {
            "stwo_zig_commit": zig_commit,
            "source_tree_sha256": sha256_tracked_tree(repo),
            "shader_tree_sha256": sha256_tracked_tree(repo, "src/backends/metal/shaders"),
            "cadence": "nightly, on demand, and supremacy-labelled pull requests",
        },
        "peer_source": {
            "repository": PEER_REPOSITORY,
            "pull_request": 6,
            "commit": PEER_COMMIT,
        },
        "host": host_identity(),
        "toolchains": {
            "rust": RUST_TOOLCHAIN,
            "rustc_version": rustc.strip(),
            "cargo_version": cargo.strip(),
            "zig_version": zig_version.strip(),
        },
        "measurement_contract": {
            "abba_rounds": rounds,
            "verified_warmups": verified_warmups,
            "samples_per_abba_position": 1,
            "interleaving": "independent peer/candidate A-B-B-A for CPU and Metal",
            "timing_boundaries": list(BOUNDARIES),
            "gate": {
                "candidate_over_peer_median_ratio_max": GATE_MEDIAN_RATIO,
                "paired_bootstrap_95_ci_high_max": GATE_CI_HIGH,
                "both_abba_halves_must_win": True,
            },
            "workload": "exact PR6 WideFibonacciEval<100>",
            "log_n_rows": list(LOG_SIZES),
            "sequence_len_columns": N_COLUMNS,
            "cold_process_includes_source_jit": True,
            "prove_ms_is_diagnostic_only": True,
            "no_concurrent_benchmarks": True,
        },
        "executables": {
            lane: {
                "path": str(path.resolve()),
                "sha256": sha256_file(path),
                "build_command": builds[lane],
            }
            for lane, path in binaries.items()
        },
        "coverage": {
            "wide_fibonacci_complete": True,
            "full_pr6_matrix_complete": False,
            "missing_exact_workloads": [
                "pr6_blake_logs_10_12_14_16",
                "pr6_plonk_logs_12_14_16",
                "pr6_fixed_wide_fibonacci_logs_4_through_8",
                "pr6_state_machine_log8",
            ],
        },
        "sizes": sizes,
    }
    validate_point(point)
    return point


def write_immutable(path: Path, point: dict) -> None:
    encoded = json.dumps(point, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as destination:
            destination.write(encoded)
    except FileExistsError:
        if path.read_text(encoding="utf-8") != encoded:
            raise SeriesError(f"refusing to replace immutable peer series point {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--rounds", type=int, default=MIN_ABBA_ROUNDS)
    parser.add_argument("--warmups", type=int, default=VERIFIED_WARMUPS)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--allow-dirty", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.rounds < MIN_ABBA_ROUNDS:
        parser.error(f"rounds must be at least {MIN_ABBA_ROUNDS}")
    if args.warmups != VERIFIED_WARMUPS:
        parser.error(f"warmups must be exactly {VERIFIED_WARMUPS}")
    if not all(shutil.which(tool) for tool in ("cargo", "rustc", "zig")):
        raise SystemExit("cargo, rustc, and zig are required on PATH")

    repo = args.repo_root.resolve()
    commit = _git(repo, "rev-parse", "HEAD")
    build_root = args.build_root or (
        Path(tempfile.gettempdir()) / "stwo-pr6-peer-series-build" / commit[:12]
    )
    binaries, builds = prepare_binaries(repo, build_root)
    point = measure(
        repo,
        binaries,
        builds,
        rounds=args.rounds,
        verified_warmups=args.warmups,
        allow_dirty=args.allow_dirty,
    )
    out = args.out or (
        repo / "autoresearch/reference/peer-series/runs" / f"{commit}-v2.json"
    )
    write_immutable(out, point)
    print(f"wrote immutable peer series point {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
