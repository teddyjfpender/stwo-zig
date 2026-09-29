#!/usr/bin/env python3
"""Measure complete Cairo product processes and require official proof acceptance.

Run one backend at a time. Every trial writes independent proof/report/stage
receipts, including the initial (cold-process) trial; no warmup is hidden.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time


CANONICAL_SECURITY = {"pow_bits": 26, "fri_config": {"n_queries": 70, "log_blowup_factor": 1, "log_last_layer_degree_bound": 0, "fold_step": 1}, "min_lifting_log_size": 0}
CONTROLLED_ENVIRONMENT = (
    "STWO_ZIG_WORKERS", "STWO_CAIRO_PREPROCESSED_CACHE",
    "STWO_CAIRO_PREPROCESSED_CACHE_DIR", "STWO_CAIRO_PREPROCESSED_CACHE_BUDGET",
    "STWO_CAIRO_METAL_RESIDENT_LOGUP", "STWO_CAIRO_METAL_HOST_BRIDGED_LOGUP",
    "STWO_CAIRO_METAL_FORCE_COPIED_LOGUP", "STWO_CAIRO_METAL_LOGUP_DIAGNOSTICS",
    "STWO_METAL_PROFILE_LDE", "STWO_CAIRO_PROFILE_ARENAS",
    "STWO_CAIRO_VM_ADAPTER", "STWO_CAIRO_VM_PROFILE",
    "STWO_METAL_PROFILE_RELATION", "STWO_CAIRO_METAL_PREFAULT_LOGUP_OUTPUTS",
    "STWO_CAIRO_WITNESS_DYNAMIC_RANGES",
    "STWO_CAIRO_INTERACTION_BATCH_ROWS", "STWO_CAIRO_INTERACTION_DYNAMIC_RANGES",
    "STWO_METAL_EVAL_THREADS_PER_GROUP",
    "STWO_CAIRO_PARALLEL_BASE_LOWERING",
    "STWO_CAIRO_OVERLAP_PREPROCESSED",
    "STWO_CAIRO_GROUP_FIXED_FEEDS",
    "STWO_CAIRO_CPU_WIDE_LDE",
    "STWO_CAIRO_PREPROCESSED_COLUMNS",
    "STWO_CAIRO_NATIVE_COMPOSITION",
    "STWO_CAIRO_COMPACT_POLYNOMIALS",
    "STWO_CAIRO_INCREMENTAL_MULTIPLICITIES",
    "STWO_CAIRO_NORM_LOGUP",
    "STWO_CAIRO_INDIRECT_COMPOSITION",
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def host_details() -> dict:
    cpu = platform.processor() or platform.machine()
    if platform.system() == "Darwin":
        cpu = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    return {"platform": platform.platform(), "cpu": cpu, "logical_cpus": os.cpu_count()}


def measure(command: list[str], log: Path, env: dict[str, str] | None = None) -> dict:
    started = time.monotonic_ns()
    with log.open("xb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, env=env)
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
    elapsed = time.monotonic_ns() - started
    # Darwin reports bytes, Linux reports KiB. wait4 includes the maximum RSS
    # of waited-for descendants, not a sum of simultaneous process footprints.
    return {
        "exit_code": process.returncode,
        "wall_ns": elapsed,
        "user_ns": round(usage.ru_utime * 1e9),
        "system_ns": round(usage.ru_stime * 1e9),
        "max_process_tree_rss_bytes": usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024),
        "rss_is_simultaneous_process_tree_sum": False,
    }


def write_result(directory: Path, result: dict) -> None:
    temporary = directory / "results.json.tmp"
    temporary.write_text(json.dumps(result, indent=2) + "\n")
    temporary.replace(directory / "results.json")


def physical_footprint_summary(trials: list[dict]) -> dict:
    """Report product-owned physical memory separately from descendant RSS."""
    peaks = []
    for trial in trials:
        usage = trial.get("prover_process_usage") or {}
        peak = usage.get("lifetime_peak_physical_footprint_bytes")
        if usage.get("source") == "darwin_proc_pid_rusage_v6" and type(peak) is int and peak > 0:
            peaks.append(peak)
    return {
        "peak_product_physical_footprint_bytes": max(peaks) if peaks and len(peaks) == len(trials) else None,
        "physical_footprint_sample_count": len(peaks),
        "physical_footprint_scope": "prover product process lifetime peak; includes Metal memory; excludes adapter child",
    }


def run_benchmark(args: argparse.Namespace, env: dict[str, str] | None = None) -> dict:
    env = dict(os.environ if env is None else env)
    args.out.mkdir(parents=True, exist_ok=False)
    input_path = args.program or args.prover_input
    result = {
        "schema": "stwo-zig-cairo-benchmark-v2",
        "host": platform.platform(),
        "host_details": host_details(),
        "product_sha256": digest(args.product),
        "oracle_sha256": digest(args.oracle),
        "workload": {"kind": "run-and-prove" if args.program else "prove", "path": str(input_path), "sha256": digest(input_path)},
        "arguments_sha256": digest(args.arguments) if args.arguments else None,
        "params_sha256": digest(args.params) if args.params else None,
        "timing_scope": "product process, including execution when requested, input/assets, proving, Zig verification and publication; official verification measured separately",
        "cache_policy": "existing product cache retained; fresh product process for each recorded trial",
        "controlled_environment": {key: env[key] for key in CONTROLLED_ENVIRONMENT if key in env},
        "status": "running",
        "trials": [],
    }
    write_result(args.out, result)
    for index in range(args.trials):
        prefix = args.out / f"trial-{index + 1}"
        proof, report, stages, verdict = [Path(str(prefix) + suffix) for suffix in (".proof.json", ".report.json", ".stages.json", ".official.json")]
        command = [str(args.product.resolve()), result["workload"]["kind"]]
        command += ["--program" if args.program else "--prover-input", str(input_path.resolve())]
        for flag, value in (("--program-type", args.program_type), ("--arguments", args.arguments), ("--params", args.params)):
            if value is not None:
                command += [flag, str(value)]
        command += ["--proof", str(proof), "--report-out", str(report), "--stage-profile-out", str(stages), "--verify"]
        trial = {"index": index + 1, "status": "running", "phase": "product", "command": command}
        result["trials"].append(trial)
        write_result(args.out, result)
        try:
            trial["process"] = measure(command, Path(str(prefix) + ".product.log"), env)
            process = trial["process"]
            if process["exit_code"]:
                raise RuntimeError(f"product exited {process['exit_code']}; see {prefix}.product.log")
            trial["phase"] = "receipt_validation"
            receipt = json.loads(report.read_text())
            proof_hash = digest(proof)
            if receipt["proof"]["sha256"] != proof_hash or receipt["proof"]["bytes"] != proof.stat().st_size:
                raise RuntimeError("product proof receipt does not match published bytes")
            if receipt["verification"] != {"requested": True, "zig": True}:
                raise RuntimeError("Zig verification did not qualify")
            if args.program:
                if receipt["execution"]["program_sha256"] != result["workload"]["sha256"]:
                    raise RuntimeError("execution receipt does not match the requested program")
                if receipt["execution"].get("arguments_sha256") != result["arguments_sha256"]:
                    raise RuntimeError("execution arguments do not match the requested bytes")
            elif receipt["input"]["sha256"] != result["workload"]["sha256"]:
                raise RuntimeError("input receipt does not match the requested prover input")
            if receipt["backend"] == "metal":
                if __package__:
                    from .check_cairo_metal_report import validate
                else:
                    from check_cairo_metal_report import validate
                validate(receipt, proof_hash, proof.stat().st_size, "authenticated-aot", "json", bool(args.program))
            config = json.loads(proof.read_text())["stark_proof"]["config"]
            expected_config = CANONICAL_SECURITY
            if config != expected_config:
                raise RuntimeError(f"unexpected canonical security configuration: {config}")
            trial["phase"] = "official_verification"
            trial["official_verifier"] = measure([str(args.oracle.resolve()), "verify", "--proof", str(proof), "--channel", "blake2s", "--proof-format", "json", "--result", str(verdict)], Path(str(prefix) + ".oracle.log"), env)
            official = trial["official_verifier"]
            if official["exit_code"]:
                raise RuntimeError(f"official verifier exited {official['exit_code']}; see {prefix}.oracle.log")
            acceptance = json.loads(verdict.read_text())
            if acceptance.get("verified") is not True or acceptance.get("proof_sha256") != proof_hash:
                raise RuntimeError("official verifier did not accept these exact proof bytes")
            if digest(proof) != proof_hash:
                raise RuntimeError("proof bytes changed during official verification")
            if digest(input_path) != result["workload"]["sha256"]:
                raise RuntimeError("workload bytes changed during measurement")
            for path, expected in ((args.arguments, result["arguments_sha256"]), (args.params, result["params_sha256"])):
                if path is not None and digest(path) != expected:
                    raise RuntimeError("workload arguments or profile changed during measurement")
            if digest(args.product) != result["product_sha256"] or digest(args.oracle) != result["oracle_sha256"]:
                raise RuntimeError("a benchmark binary changed during measurement")
            trial.update({"status": "qualified", "phase": "complete", "timing": receipt["timing"], "proof_sha256": proof_hash, "profile": receipt["profile"], "backend": receipt["backend"], "backend_evidence": receipt["backend_evidence"], "cache_evidence": receipt.get("preprocessed_cache"), "prover_process_usage": receipt.get("prover_process_usage"), "stages": json.loads(stages.read_text())["stages"]})
        except Exception as error:
            trial.update({"status": "failed", "error": str(error), "error_type": type(error).__name__})
            result["status"] = "failed"
            write_result(args.out, result)
            raise
        result["summary"] = {
            "median_process_wall_ns": statistics.median(t["process"]["wall_ns"] for t in result["trials"]),
            "median_prove_ns": statistics.median(t["timing"]["prove_ns"] for t in result["trials"]),
            "peak_process_rss_bytes": max(t["process"]["max_process_tree_rss_bytes"] for t in result["trials"]),
            **physical_footprint_summary(result["trials"]),
        }
        write_result(args.out, result)
        print(json.dumps({key: value for key, value in trial.items() if key not in {"stages", "command"}}), flush=True)
    if len(result["trials"]) > 1:
        repeated = result["trials"][1:]
        result["subsequent_trials_summary"] = {
            "indices": [trial["index"] for trial in repeated],
            "median_process_wall_ns": statistics.median(trial["process"]["wall_ns"] for trial in repeated),
            "median_prove_ns": statistics.median(trial["timing"]["prove_ns"] for trial in repeated),
            "peak_process_rss_bytes": max(trial["process"]["max_process_tree_rss_bytes"] for trial in repeated),
            "cache_state_inferred": False,
            **physical_footprint_summary(repeated),
        }
    result["status"] = "qualified"
    write_result(args.out, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--prover-input", type=Path)
    source.add_argument("--program", type=Path)
    parser.add_argument("--program-type", choices=("json", "executable", "pie"))
    parser.add_argument("--arguments", type=Path)
    parser.add_argument("--params", type=Path)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not hasattr(os, "wait4"):
        parser.error("this measurement requires POSIX wait4")
    if args.trials < 1 or args.trials > 100:
        parser.error("--trials must be between 1 and 100")
    if args.program_type and not args.program:
        parser.error("--program-type requires --program")
    if args.arguments and (not args.program or args.program_type == "pie"):
        parser.error("--arguments requires a JSON/executable program")
    for path in (args.product, args.oracle, args.prover_input, args.program, args.arguments, args.params):
        if path is not None and not path.is_file():
            parser.error(f"not a regular file: {path}")
    run_benchmark(args)


if __name__ == "__main__":
    main()
