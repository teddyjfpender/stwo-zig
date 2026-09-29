#!/usr/bin/env python3
"""Alternate two Cairo product binaries on identical workload bytes and security."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import statistics
import sys

if __package__:
    from . import benchmark_cairo as benchmark
else:
    import benchmark_cairo as benchmark


def variant_environment(base: dict[str, str], overrides: list[str]) -> dict[str, str]:
    """Copy the common environment; only documented benchmark controls may vary."""
    result = dict(base)
    seen = set()
    for override in overrides:
        key, separator, value = override.partition("=")
        if not separator or key not in benchmark.CONTROLLED_ENVIRONMENT:
            raise ValueError(f"expected a documented benchmark control NAME=VALUE: {override}")
        if key in seen:
            raise ValueError(f"duplicate variant control: {key}")
        seen.add(key)
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument("--oracle", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--program", type=Path)
    source.add_argument("--prover-input", type=Path)
    parser.add_argument("--program-type", choices=("json", "executable", "pie"))
    parser.add_argument("--arguments", type=Path)
    parser.add_argument("--params", type=Path)
    parser.add_argument("--before-env", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--after-env", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not 2 <= args.pairs <= 100:
        parser.error("--pairs must be between 2 and 100")
    if args.program_type and not args.program:
        parser.error("--program-type requires --program")
    if args.arguments and (not args.program or args.program_type == "pie"):
        parser.error("--arguments requires a JSON/executable program")
    for path in (args.before, args.after, args.oracle, args.program, args.prover_input, args.arguments, args.params):
        if path is not None and not path.is_file():
            parser.error(f"not a regular file: {path}")
    try:
        environments = {
            variant: variant_environment(dict(os.environ), getattr(args, f"{variant}_env"))
            for variant in ("before", "after")
        }
    except ValueError as error:
        parser.error(str(error))
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    result = {
        "schema": "stwo-zig-cairo-paired-benchmark-v1", "status": "running",
        "host_details": benchmark.host_details(), "security": benchmark.CANONICAL_SECURITY,
        "schedule": "AB, BA, AB, ...; serial product processes; all initial trials retained",
        "cache_policy": "existing artifact and Metal pipeline caches retained, with per-trial evidence",
        "variant_environment": {
            variant: {key: env[key] for key in benchmark.CONTROLLED_ENVIRONMENT if key in env}
            for variant, env in environments.items()
        },
        "records": [],
    }
    benchmark.write_result(args.out, result)
    try:
        for index in range(args.pairs):
            for variant in (("before", "after") if index % 2 == 0 else ("after", "before")):
                folder = args.out / f"pair-{index + 1}-{variant}"
                request = argparse.Namespace(
                    product=getattr(args, variant), oracle=args.oracle, program=args.program,
                    prover_input=args.prover_input, program_type=args.program_type,
                    arguments=args.arguments, params=args.params, trials=1, out=folder,
                )
                record = {"pair": index + 1, "variant": variant, "status": "running", "result_path": str(folder / "results.json")}
                result["records"].append(record)
                benchmark.write_result(args.out, result)
                try:
                    receipt = benchmark.run_benchmark(request, environments[variant])
                except Exception as error:
                    record.update({"status": "failed", "error": str(error)})
                    if (folder / "results.json").is_file():
                        record["result"] = json.loads((folder / "results.json").read_text())
                    raise
                record.update({"status": "qualified", "result": receipt})
                benchmark.write_result(args.out, result)
        hashes = {record["result"]["trials"][0]["proof_sha256"] for record in result["records"]}
        profiles = {record["result"]["trials"][0]["profile"] for record in result["records"]}
        backends = {record["result"]["trials"][0]["backend"] for record in result["records"]}
        workloads = {record["result"]["workload"]["sha256"] for record in result["records"]}
        if len(hashes) != 1 or len(profiles) != 1 or len(backends) != 1 or len(workloads) != 1:
            raise ValueError("paired processes did not preserve exact proof bytes, profile, backend and workload")
        result["proof_sha256"] = hashes.pop()
        result["backend"] = backends.pop()
        result["summary"] = {}
        for variant in ("before", "after"):
            trials = [record["result"]["trials"][0] for record in result["records"] if record["variant"] == variant]
            result["summary"][variant] = {
                "median_process_wall_ns": statistics.median(trial["process"]["wall_ns"] for trial in trials),
                "median_prove_ns": statistics.median(trial["timing"]["prove_ns"] for trial in trials),
                "peak_process_rss_bytes": max(trial["process"]["max_process_tree_rss_bytes"] for trial in trials),
                **benchmark.physical_footprint_summary(trials),
            }
        before, after = result["summary"]["before"], result["summary"]["after"]
        result["process_speedup"] = before["median_process_wall_ns"] / after["median_process_wall_ns"]
        result["prove_speedup"] = before["median_prove_ns"] / after["median_prove_ns"]
        result["status"] = "qualified"
    except Exception as error:
        result.update({"status": "failed", "error": str(error), "error_type": type(error).__name__})
    benchmark.write_result(args.out, result)
    print(json.dumps({key: value for key, value in result.items() if key != "records"}, indent=2))
    return 0 if result["status"] == "qualified" else 1


if __name__ == "__main__":
    sys.exit(main())
