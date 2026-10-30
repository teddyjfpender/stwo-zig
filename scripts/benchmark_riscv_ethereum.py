#!/usr/bin/env python3
"""Compile once and profile verified, synthetic Ethereum-profile RISC-V workloads.

The runner does not promote results or label synthetic programs as block proofs.
Compilation uses the existing Zig build lock. A separate campaign lock serializes
this CLI's builds and proof runs; unrelated commands must still be kept idle.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import shutil
import statistics
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = "src/frontends/riscv/block_v7_multi_union_test_root.zig"
TEST_FILTER = "v7 multi union genuine contiguous original STARK with all-provider oracle"
KINDS = ("keccak_heavy", "memory_heavy", "mixed_ethereum")
BASKETS = {
    "quick": [("keccak_heavy", 1), ("memory_heavy", 64), ("mixed_ethereum", 1)],
    "default": [("keccak_heavy", 8), ("memory_heavy", 4096), ("mixed_ethereum", 8)],
    "scaling": [(kind, n) for kind, sizes in (
        ("keccak_heavy", (1, 8, 32)), ("memory_heavy", (256, 4096, 32768)),
        ("mixed_ethereum", (1, 8, 32))) for n in sizes],
}
DEFAULT_LOCK = "/tmp/stwo-riscv-ethereum-benchmark.lock"


class InvalidReport(ValueError):
    pass


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def case(value: str) -> tuple[str, int]:
    try:
        kind, amount = value.split(":")
        count = int(amount)
        maximum = 32768 if kind == "memory_heavy" else 1024
        if kind not in KINDS or not 1 <= count <= maximum:
            raise ValueError
        return kind, count
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected WORKLOAD:ITERATIONS within the workload limit") from error


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n")
    temporary.replace(path)


def command_text(command: list[str]) -> str | None:
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else None
    except OSError:
        return None


def source_manifest() -> dict:
    paths = subprocess.check_output([
        "git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--",
        "src", "build_support", "build.zig", "build.zig.zon", "scripts/zig_protocol_test.py",
        "scripts/zig_protocol_lib", "scripts/zig_serial_build.py",
    ], cwd=ROOT).decode().split("\0")
    files = []
    for name in sorted(set(filter(None, paths))):
        path = ROOT / name
        if path.is_file():
            files.append({"path": name, "bytes": path.stat().st_size, "sha256": sha(path)})
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": 1, "head": command_text(["git", "rev-parse", "HEAD"]),
        "dirty": bool(command_text(["git", "status", "--porcelain", "--untracked-files=normal"])),
        "source_sha256": hashlib.sha256(canonical).hexdigest(), "files": files,
    }


def machine() -> dict:
    memory = None
    zig_path = shutil.which("zig")
    try:
        memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    except (ValueError, OSError):
        if sys.platform == "darwin":
            text = command_text(["sysctl", "-n", "hw.memsize"])
            memory = int(text) if text else None
    return {
        "os": platform.system(), "release": platform.release(), "architecture": platform.machine(),
        "cpu_count": os.cpu_count(), "memory_bytes": memory,
        "cpu_model": command_text(["sysctl", "-n", "machdep.cpu.brand_string"]) if sys.platform == "darwin" else platform.processor(),
        "python": platform.python_version(), "zig": command_text(["zig", "version"]),
        "zig_executable_sha256": sha(Path(zig_path)) if zig_path else None,
    }


@contextmanager
def campaign_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        started = time.monotonic()
        print(f"Waiting for benchmark lock: {path}", flush=True)
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield time.monotonic() - started
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def execute(command: list[str], log: Path, env: dict[str, str], timeout: int) -> dict:
    """Always reap the entire subprocess group, including on timeout/interrupt."""
    started = time.monotonic()
    started_utc = datetime.now(timezone.utc).isoformat()
    process = None
    state = "completed"
    error = None
    with log.open("w") as output:
        try:
            process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as failure:
            state = "timeout" if isinstance(failure, subprocess.TimeoutExpired) else "interrupted"
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        except OSError as failure:
            state, error = "launch_failed", str(failure)
    return {"process_status": state, "returncode": process.returncode if process else None,
            "started_utc": started_utc, "finished_utc": datetime.now(timezone.utc).isoformat(),
            "command_wall_seconds": time.monotonic() - started, "process_error": error}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidReport(message)


def integer(value: object, name: str, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, f"invalid {name}")
    return value


def stage_rows(profile: dict) -> list[dict]:
    require(isinstance(profile, dict) and profile.get("schema_version") == 1, "unknown stage schema")
    roots = profile.get("stages")
    require(isinstance(roots, list) and bool(roots), "missing stages")
    rows = []

    def visit(node: object, parent: str, index: int, depth: int) -> float:
        require(isinstance(node, dict), "stage must be an object")
        require(depth <= 64 and len(rows) < 100_000, "stage tree exceeds bounded schema")
        stage_id = node.get("id")
        require(isinstance(stage_id, str) and bool(stage_id), "missing stage id")
        seconds = node.get("seconds")
        require(type(seconds) in (int, float) and math.isfinite(seconds) and seconds >= 0, f"invalid stage duration: {stage_id}")
        children = node.get("children")
        require(children is None or isinstance(children, list), f"invalid stage children: {stage_id}")
        children = children or []
        path = f"{parent}/{stage_id}[{index}]" if parent else f"{stage_id}[{index}]"
        child_seconds = sum(visit(child, path, i, depth + 1) for i, child in enumerate(children))
        # Recorder rounds each node to microseconds. Siblings are sequential,
        # so only the bounded sum of rounding errors may exceed their parent.
        tolerance = 0.00001 + len(children) * 0.000001
        require(child_seconds <= seconds + tolerance, f"children exceed parent duration: {path}")
        rows.append({"stage_path": path, "parent_path": parent, "stage_id": stage_id,
                     "label": node.get("label", ""), "depth": depth, "is_leaf": not children,
                     "inclusive_seconds": seconds, "exclusive_seconds": max(0.0, seconds - child_seconds),
                     "rounding_clamp_seconds": max(0.0, child_seconds - seconds)})
        return float(seconds)

    for i, root in enumerate(roots):
        visit(root, "", i, 0)
    return rows


def validate_report(report: dict, kind: str, iterations: int, cut: int | None, windows: int = 4, shared_keccak: bool = False, workers: int = 4, native_main_cache_mib: int = 256, deep_group_mib: int = 1) -> list[dict]:
    require(isinstance(report, dict) and report.get("schema") == 1, "unknown benchmark schema")
    require(report.get("workload") == kind and report.get("iterations") == iterations, "requested workload mismatch")
    require(report.get("source") == "synthetic_complete_execution", "unexpected workload source")
    # Historical schema-1 binaries used exactly four workers. A missing count
    # can never attest a nondefault request or be relabelled as a scaling run.
    reported_workers = integer(report.get("worker_count", 4), "worker_count", 1)
    require(reported_workers <= 32 and reported_workers == workers, "requested worker count mismatch")
    reported_cache = integer(report.get("native_main_cache_mib", 256), "native_main_cache_mib", 0)
    require(reported_cache <= 2048 and reported_cache == native_main_cache_mib, "requested native cache budget mismatch")
    reported_deep = integer(report.get("deep_group_mib", 1), "deep_group_mib", 1)
    require(reported_deep in (1, 4, 8) and reported_deep == deep_group_mib, "requested DEEP metadata budget mismatch")
    if shared_keccak:
        require(kind == "keccak_heavy" and report.get("architecture") == "shared_keccak", "shared Keccak architecture mismatch")
        require(report.get("proof_contract") == "original_complete_stark", "shared proof contract mismatch")
    else:
        require(report.get("architecture", "per_window_callers") == "per_window_callers", "baseline architecture mismatch")
    if shared_keccak:
        for name in ("statement_sha256", "output_sha256"):
            value = report.get(name)
            require(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value), f"invalid shared {name}")
        integer(report.get("program_fetches"), "program_fetches", 1)
        integer(report.get("memory_event_limit"), "memory_event_limit", 1)
        integer(report.get("events_per_ram_shard"), "events_per_ram_shard", 1)
    require(report.get("verified") is True and report.get("producers_destroyed") is True, "missing fresh verification after producer destruction")
    require(report.get("canonical_security") is True and report.get("query_count") == 70 and report.get("pow_bits") == 26, "noncanonical security")
    require(report.get("oracle_enabled") is False and report.get("oracle_ns") == 0, "oracle contaminated benchmark")
    require("recursive_reduction_ns" in report and report["recursive_reduction_ns"] is None, "original proof must not claim a recursive timing")
    for name in ("end_to_end_ns", "prove_ns", "verification_ns", "cycles", "native_windows", "window_cut", "proof_bytes", "tracked_peak_bytes"):
        integer(report.get(name), name, 1)
    for name in ("setup_ns", "caller_windows", "ram_events", "checkpoint_read_bytes", "checkpoint_write_bytes"):
        integer(report.get(name), name)
    if report.get("process_peak_rss_bytes") is not None:
        integer(report["process_peak_rss_bytes"], "process_peak_rss_bytes", 1)
    require(report["native_windows"] <= 16, "unsupported window count")
    if cut is not None:
        require(report["window_cut"] == cut, "requested window cut mismatch")
    else:
        require(report["window_cut"] == (report["cycles"] + windows - 1) // windows, "automatic window cut mismatch")
        require(report["native_windows"] <= windows, "requested window count exceeded")
    require(isinstance(report.get("producer_stats"), dict), "missing producer allocation statistics")
    for name in ("elf_sha256", "proof_sha256"):
        text = report.get(name)
        require(isinstance(text, str) and len(text) == 64 and all(c in "0123456789abcdef" for c in text), f"invalid {name}")
    require(report["end_to_end_ns"] + 1_000_000 >= report["prove_ns"] + report["verification_ns"], "overlapping or invalid whole-job timing")
    rows = stage_rows(report.get("profile"))
    ids = {row["stage_id"] for row in rows}
    required = {"request", "keccak_union_prove" if shared_keccak else "multi_prove",
                "keccak_union_core_proof" if shared_keccak else "multi_core_proof", "composition_evaluation",
                "sampled_value_evaluation", "fri_quotient_build_and_commit", "trace_decommit",
                "serialization", "independent_verification"}
    require(required <= ids, f"missing production stages: {sorted(required - ids)}")
    request = [row for row in rows if row["stage_id"] == "request"]
    require(len(request) == 1 and request[0]["depth"] == 0, "expected one request root")
    require(len([row for row in rows if row["depth"] == 0]) == 1, "stages escaped request boundary")
    elapsed = report["end_to_end_ns"] / 1e9
    require(abs(request[0]["inclusive_seconds"] - elapsed) <= max(0.01, elapsed * 0.01), "profile/request timing mismatch")
    return rows


def flat_metrics(report: dict) -> dict:
    result = {key: value for key, value in report.items() if not isinstance(value, (list, dict))}
    for key, value in report.get("producer_stats", {}).items():
        if not isinstance(value, (list, dict)):
            result["producer_" + key] = value
    return result


def write_csv(path: Path, rows: list[dict], first: tuple[str, ...]) -> None:
    keys = list(first) + sorted({key for row in rows for key in row} - set(first))
    temporary = path.with_suffix(".csv.tmp")
    with temporary.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def rankings(rows: list[dict]) -> list[dict]:
    # Sum repeated siblings with the same stage ID within each run. Exclusive
    # time includes internal-node self time, so no parent/child double counting.
    per_run: dict[tuple, float] = {}
    for row in rows:
        key = (row["workload"], row["iterations"], row["window_cut"], row.get("worker_count", 4), row.get("native_main_cache_mib", 256), row.get("deep_group_mib", 1), row["run_id"], row["stage_id"])
        per_run[key] = per_run.get(key, 0.0) + row["exclusive_seconds"]
    groups: dict[tuple, list[float]] = {}
    for (kind, count, cut, workers, cache_mib, deep_mib, _, stage), duration in per_run.items():
        groups.setdefault((kind, count, cut, workers, cache_mib, deep_mib, stage), []).append(duration)
    out = []
    for (kind, count, cut, workers, cache_mib, deep_mib, stage), values in groups.items():
        ordered = sorted(values)
        out.append({"workload": kind, "iterations": count, "window_cut": cut, "worker_count": workers, "native_main_cache_mib": cache_mib, "deep_group_mib": deep_mib, "stage_id": stage,
                    "runs": len(values), "median_exclusive_seconds": statistics.median(values),
                    "mean_exclusive_seconds": statistics.mean(values),
                    "p95_exclusive_seconds": ordered[max(0, math.ceil(len(values) * .95) - 1)]})
    by_stage: dict[str, list[dict]] = {}
    by_case: dict[tuple, list[dict]] = {}
    for row in out:
        by_stage.setdefault(row["stage_id"], []).append(row)
        by_case.setdefault((row["workload"], row["iterations"], row["window_cut"], row["worker_count"], row["native_main_cache_mib"], row["deep_group_mib"]), []).append(row)
    for collection, name in ((by_stage, "rank_within_stage"), (by_case, "rank_within_case")):
        for group in collection.values():
            for rank, row in enumerate(sorted(group, key=lambda r: r["median_exclusive_seconds"], reverse=True), 1):
                row[name] = rank
    return sorted(out, key=lambda r: (r["stage_id"], r["rank_within_stage"]))


def environment(kind: str, iterations: int, report: Path, windows: int, cut: int | None, shared_keccak: bool = False, workers: int = 4, deep_census: bool = False, native_main_cache_mib: int = 256, deep_group_mib: int = 1) -> tuple[dict, dict]:
    # Inherited STWO diagnostic flags can silently change the algorithm/fixture.
    env = {key: value for key, value in os.environ.items() if not key.startswith("STWO_")}
    settings = {
        "STWO_V7_BENCHMARK": "1", "STWO_V7_BENCH_WORKLOAD": kind,
        "STWO_V7_MULTI_UNION_ITERATIONS": str(iterations), "STWO_V7_BENCH_WINDOWS": str(windows),
        "STWO_V7_MULTI_UNION_CANONICAL": "1", "STWO_V7_MULTI_UNION_COEFFICIENT_INPUTS": "1",
        "STWO_V7_MULTI_UNION_COEFFICIENT_INTERACTION": "1", "STWO_V7_MULTI_UNION_CONSUME_MEMORY": "1",
        "STWO_V7_MULTI_UNION_RAM_TILES": "1", "STWO_V7_BENCH_REPORT": str(report),
        "STWO_V7_BENCH_WORKERS": str(workers),
        "STWO_V7_NATIVE_MAIN_CACHE_MIB": str(native_main_cache_mib),
        "STWO_PCS_DEEP_GROUP_MIB": str(deep_group_mib),
    }
    if shared_keccak:
        settings["STWO_V7_BENCH_SHARED_KECCAK"] = "1"
    if deep_census:
        settings["STWO_PCS_DEEP_CENSUS"] = "1"
    if cut is not None:
        settings["STWO_V7_MULTI_UNION_CUT"] = str(cut)
    env.update(settings)
    return env, settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--basket", choices=BASKETS, default="default")
    parser.add_argument("--case", type=case, action="append", dest="cases", help="override basket; repeat WORKLOAD:ITERATIONS")
    parser.add_argument("--shared-keccak", action="store_true", help="use the distinct shared-Keccak original complete proof (Keccak workloads only)")
    parser.add_argument("--repeats", type=positive, default=3)
    parser.add_argument("--windows", type=positive, default=4)
    parser.add_argument("--workers", type=positive, default=4, help="total CPU workers, including coordinator (1..32)")
    parser.add_argument("--native-main-cache-mib", type=int, default=256, help="one proof-wide native MAIN cache cap (0 disables, maximum 2048 MiB; charged to request budget)")
    parser.add_argument("--deep-group-mib", type=int, choices=(1, 4, 8), default=1, help="bounded DEEP grouping metadata charged to the request allocator")
    parser.add_argument("--deep-census", action="store_true", help="diagnostic DEEP grouping census in run.log; use separately from comparison timings")
    parser.add_argument("--cut", type=positive, help="explicit segment cycle budget instead of automatic window cut")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--build-only", action="store_true", help="build and record provenance without executing a proof")
    parser.add_argument("--build-lock", type=Path, default=Path("/tmp/stwo-zig-build.lock"))
    parser.add_argument("--strip", action="store_true", help="omit profiling symbols; retained by default")
    parser.add_argument("--binary", type=Path, help="reuse executable; adjacent .build.json binds its original source if available")
    parser.add_argument("--timeout", type=positive, default=1800, help="per run seconds")
    parser.add_argument("--build-timeout", type=positive, default=1800)
    parser.add_argument("--lock", type=Path, default=Path(DEFAULT_LOCK))
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.build_only and args.binary:
        parser.error("--build-only cannot reuse --binary")
    if args.windows > 16:
        parser.error("--windows cannot exceed the independently bounded 16-window fixture")
    if not 0 <= args.native_main_cache_mib <= 2048:
        parser.error("--native-main-cache-mib must be between 0 and 2048")
    if args.workers > 32:
        parser.error("--workers cannot exceed the prover's 32-worker bound")
    cases = args.cases or BASKETS[args.basket]
    if args.shared_keccak and not args.build_only and any(kind != "keccak_heavy" for kind, _ in cases):
        parser.error("--shared-keccak requires explicit keccak_heavy cases")
    if len(cases) != len(set(cases)):
        parser.error("duplicate cases are redundant; use --repeats")
    out = (args.out or ROOT / "zig-out" / "benchmarks" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])).resolve()
    binary = args.binary.resolve() if args.binary else out / "prover"
    build_command = [sys.executable, "scripts/zig_protocol_test.py", "--lock", str(args.build_lock), TEST_ROOT, "-OReleaseSafe"]
    if args.strip:
        build_command.append("-fstrip")
    build_command += ["--test-filter", TEST_FILTER, "--test-no-exec", f"-femit-bin={binary}"]
    if args.dry_run:
        print(json.dumps({"out": str(out), "build": None if args.binary else build_command,
                          "cases": cases, "repeats": args.repeats, "windows": args.windows,
                          "workers": args.workers, "native_main_cache_mib": args.native_main_cache_mib, "deep_group_mib": args.deep_group_mib,
                          "environment": environment(cases[0][0], cases[0][1], out / "report.json", args.windows, args.cut, args.shared_keccak, args.workers, args.deep_census, args.native_main_cache_mib, args.deep_group_mib)[1]}, indent=2))
        return 0
    if out.exists() and any(out.iterdir()):
        parser.error("output directory must be new or empty; existing evidence is never overwritten")
    out.mkdir(parents=True, exist_ok=True)
    run_rows: list[dict] = []
    stages: list[dict] = []
    manifest = {"schema": 1, "started_utc": datetime.now(timezone.utc).isoformat(), "status": "starting",
                "source_kind": "synthetic_complete_execution", "architecture": "shared_keccak" if args.shared_keccak else "per_window_callers", "cases": cases, "repeats": args.repeats,
                "worker_count": args.workers, "native_main_cache_mib": args.native_main_cache_mib, "deep_group_mib": args.deep_group_mib,
                "deep_census": args.deep_census,
                "machine": machine(), "runner_sha256": sha(Path(__file__)),
                "binary": str(binary), "benchmark_lock": str(args.lock),
                "lock_scope": "this CLI's campaigns only; unrelated processes are not prevented",
                "compile_time_excluded_from_runs": True}
    manifest["machine_sha256"] = hashlib.sha256(json.dumps(manifest["machine"], sort_keys=True).encode()).hexdigest()
    manifest_path = out / "manifest.json"
    write_json(manifest_path, manifest)
    try:
        with campaign_lock(args.lock) as wait:
            manifest["benchmark_lock_wait_seconds"] = wait
            source = source_manifest()
            write_json(out / "source-manifest.json", source)
            manifest["current_source_sha256"] = source["source_sha256"]
            if args.binary:
                require(binary.is_file() and os.access(binary, os.X_OK), "reuse binary is missing or not executable")
                binary_hash = sha(binary)
                sidecar = Path(str(binary) + ".build.json")
                provenance = json.loads(sidecar.read_text()) if sidecar.is_file() else {}
                require(isinstance(provenance, dict), "build sidecar must be an object")
                require(not provenance or provenance.get("binary_sha256") == binary_hash, "binary does not match its build sidecar")
                if provenance:
                    require(provenance.get("source_binding") == "recorded_build" and isinstance(provenance.get("source_sha256"), str) and len(provenance["source_sha256"]) == 64, "incomplete source binding in build sidecar")
                    original_manifest = binary.parent / "source-manifest.json"
                    if original_manifest.is_file():
                        original_source = json.loads(original_manifest.read_text())
                        require(original_source.get("source_sha256") == provenance["source_sha256"], "original source manifest does not match build")
                        write_json(out / "build-source-manifest.json", original_source)
                build = {"reused": True, "binary_sha256": binary_hash, "compile_command_wall_seconds": 0,
                         "source_sha256": provenance.get("source_sha256"), "source_head": provenance.get("source_head"),
                         "source_binding": "recorded_build" if provenance else "external_unattested",
                         "original_build": provenance or None}
            else:
                env = {key: value for key, value in os.environ.items() if not key.startswith("STWO_")}
                result = execute(build_command, out / "build.log", env, args.build_timeout)
                build = {**result, "command": build_command, "reused": False,
                         "compile_command_wall_seconds": result["command_wall_seconds"],
                         "compile_wall_includes_build_lock_wait": True}
                manifest["build"] = build
                write_json(manifest_path, manifest)
                require(result["process_status"] == "completed" and result["returncode"] == 0, "build failed; see build.log")
                after = source_manifest()
                require(after["source_sha256"] == source["source_sha256"], "source changed during compilation; build provenance is ambiguous")
                binary_hash = sha(binary)
                build.update(binary_sha256=binary_hash, source_binding="recorded_build",
                             source_sha256=source["source_sha256"], source_head=source["head"],
                             software=manifest["machine"], runner_sha256=sha(Path(__file__)))
                write_json(Path(str(binary) + ".build.json"), build)
            manifest.update(build=build, status="built" if args.build_only else "running")
            write_json(manifest_path, manifest)
            if args.build_only:
                manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
                write_json(manifest_path, manifest)
                print(f"Built {binary}; provenance: {binary}.build.json", flush=True)
                return 0
            stop = False
            for repeat in range(1, args.repeats + 1):
                for case_index, (kind, count) in enumerate(cases):
                    run_id = f"{case_index:02d}-{kind}-{count}-r{repeat:02d}"
                    run_dir = out / run_id
                    run_dir.mkdir()
                    report_path = run_dir / "report.json"
                    env, settings = environment(kind, count, report_path, args.windows, args.cut, args.shared_keccak, args.workers, args.deep_census, args.native_main_cache_mib, args.deep_group_mib)
                    print(f"Running {run_id}", flush=True)
                    result = execute([str(binary)], run_dir / "run.log", env, args.timeout)
                    row = {"run_id": run_id, "workload": kind, "iterations": count, "repeat": repeat,
                           "worker_count": args.workers, "native_main_cache_mib": args.native_main_cache_mib, "deep_group_mib": args.deep_group_mib,
                           "status": "failed", "binary_sha256": binary_hash, "binary_source_binding": build["source_binding"],
                           "source_sha256": build.get("source_sha256"), "source_head": build.get("source_head"),
                           "report_path": str(report_path.relative_to(out)), "log_path": str((run_dir / "run.log").relative_to(out)), **result}
                    details = {"command": [str(binary)], "environment": settings, **row}
                    try:
                        require(result["process_status"] == "completed" and result["returncode"] == 0, f"process {result['process_status']} exit={result['returncode']}")
                        require(sha(binary) == binary_hash, "binary changed during campaign")
                        require(report_path.stat().st_size <= 64 << 20, "report exceeds 64MiB schema cap")
                        report = json.loads(report_path.read_text())
                        measured = validate_report(report, kind, count, args.cut, args.windows, args.shared_keccak, args.workers, args.native_main_cache_mib, args.deep_group_mib)
                        row.update(flat_metrics(report), status="passed", report_sha256=sha(report_path))
                        require(row["command_wall_seconds"] + 0.01 >= report["end_to_end_ns"] / 1e9, "report exceeds observed process wall time")
                        for stage in measured:
                            stages.append({"run_id": run_id, "workload": kind, "iterations": count,
                                           "repeat": repeat, "window_cut": report["window_cut"], "worker_count": args.workers, "native_main_cache_mib": args.native_main_cache_mib, "deep_group_mib": args.deep_group_mib,
                                           "binary_sha256": binary_hash, "source_sha256": build.get("source_sha256"),
                                           "binary_source_binding": build["source_binding"], **stage})
                    except (InvalidReport, ValueError, OSError, TypeError, KeyError) as error:
                        row.update(status="failed", error=str(error))
                    row["log_sha256"] = sha(run_dir / "run.log")
                    details.update(row)
                    write_json(run_dir / "run.json", details)
                    run_rows.append(row)
                    write_csv(out / "runs.csv", run_rows, ("run_id", "workload", "iterations", "repeat", "status"))
                    write_csv(out / "stages.csv", stages, ("run_id", "workload", "iterations", "stage_path", "stage_id", "inclusive_seconds", "exclusive_seconds", "is_leaf"))
                    write_csv(out / "stage-leaves.csv", [row for row in stages if row["is_leaf"]], ("run_id", "workload", "iterations", "stage_path", "stage_id", "inclusive_seconds", "exclusive_seconds"))
                    write_csv(out / "stage-rankings.csv", rankings(stages), ("stage_id", "rank_within_stage", "workload", "iterations", "median_exclusive_seconds"))
                    manifest["completed_runs"] = len(run_rows)
                    manifest["failed_runs"] = sum(row["status"] != "passed" for row in run_rows)
                    write_json(manifest_path, manifest)
                    if result["process_status"] == "interrupted" or (args.fail_fast and row["status"] != "passed"):
                        stop = True
                        break
                if stop:
                    break
            manifest["status"] = "completed" if all(row["status"] == "passed" for row in run_rows) else "failed"
            manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
            write_json(manifest_path, manifest)
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        manifest.update(status="failed", error=str(error) or type(error).__name__, finished_utc=datetime.now(timezone.utc).isoformat())
        write_json(manifest_path, manifest)
        print(f"Benchmark failed: {error}; evidence: {out}", file=sys.stderr)
        return 1
    print(f"Evidence: {out}", flush=True)
    return 0 if manifest["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
