#!/usr/bin/env python3
"""Rebuild and compare the original and packed sum_lanes circuit lowering.

Example:
  git worktree add --detach /tmp/s31-before-packed fbf0c65f0
  python3 src/frontends/s31/benchmark_packed_reduction.py \
      --baseline-root /tmp/s31-before-packed \
      --output design/s31/measurements/packed-reduction-2026-10-06.json

The fixture is a 64-lane private M31 array whose sum wraps modulo p. Both
versions compile the same normalized relation and prove the same public claim.
"""

import argparse
import hashlib
import json
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


P = 2**31 - 1
HERE = Path(__file__).resolve().parents[3]
COMPILER = Path("src/frontends/s31/relation_compiler.zig")


def run(*command: str, cwd: Path | None = None) -> str:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if completed.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{completed.stdout}{completed.stderr}")
    return completed.stdout.strip()


def git_version(root: Path) -> dict:
    source = root / COMPILER
    return {
        "git_head": run("git", "rev-parse", "HEAD", cwd=root),
        "relation_compiler_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "relation_compiler_dirty": bool(run("git", "status", "--porcelain", "--", str(COMPILER), cwd=root)),
    }


def host() -> dict:
    cpu = platform.processor()
    if sys.platform == "darwin":
        cpu = run("sysctl", "-n", "machdep.cpu.brand_string")
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": cpu,
        "zig": run("zig", "version"),
        "python": platform.python_version(),
    }


def measure(root: Path, label: str, name: str, source: Path, assignments: list[Path],
            statements: list[Path], wrong_statement: Path, work: Path,
            trials: int) -> dict:
    package = work / f"{label}-package"
    run(sys.executable, str(root / "src/frontends/s31/s31.py"), "build",
        str(source), "--out", str(package), "--lowering", "direct-gate")
    report = json.loads((package / "cost-report.json").read_text())
    prover = package / f"bin/s31-{name}-prover"
    verifier = package / f"bin/s31-{name}-native-verifier"
    key = package / "verification-key.json"
    times = []
    proof_bytes = []
    reported_prove = []
    interaction_pow = []
    fri_pow = []
    excluding_pow = []
    for trial in range(trials + 1):  # first trial warms up the local cache
        proof = work / f"{label}-{trial}.proof"
        start = time.perf_counter()
        completed = subprocess.run((str(prover), "prove", str(assignments[trial]), str(proof)),
                                   text=True, capture_output=True)
        elapsed = time.perf_counter() - start
        if completed.returncode:
            raise RuntimeError(f"{label} proof failed:\n{completed.stdout}{completed.stderr}")
        output = completed.stdout + completed.stderr
        stage = re.search(r"witness=([\d.]+)s, setup=([\d.]+)s, prove=([\d.]+)s", output)
        pow_stage = re.search(r"interaction_pow=([\d.]+)s fri_pow=([\d.]+)s", output)
        if not stage or not pow_stage:
            raise RuntimeError(f"{label} prover omitted stage timings:\n{output}")
        prove_s = float(stage.group(3))
        interaction_s = float(pow_stage.group(1))
        fri_s = float(pow_stage.group(2))
        size = proof.stat().st_size
        run(str(verifier), str(proof), str(statements[trial]), str(key))
        if trial == 0:
            wrong = subprocess.run((str(verifier), str(proof), str(wrong_statement), str(key)),
                                   text=True, capture_output=True)
            if wrong.returncode == 0:
                raise AssertionError(f"{label} verifier accepted a changed public output")
        else:
            times.append(elapsed)
            proof_bytes.append(size)
            reported_prove.append(prove_s)
            interaction_pow.append(interaction_s)
            fri_pow.append(fri_s)
            excluding_pow.append(prove_s - interaction_s - fri_s)
    return {
        "version": git_version(root),
        "profile": report["profile"],
        "canonical_ir_sha256": report["canonical_ir_sha256"],
        "raw": report["raw"],
        "padded": report["padded"],
        "preprocessed_cells": report["preprocessed_cells"],
        "proof_bytes_per_trial": proof_bytes,
        "median_proof_bytes": statistics.median(proof_bytes),
        "wall_proving_seconds_per_trial": times,
        "median_wall_proving_seconds": statistics.median(times),
        "reported_prove_seconds_per_trial": reported_prove,
        "interaction_pow_seconds_per_trial": interaction_pow,
        "fri_pow_seconds_per_trial": fri_pow,
        "prove_excluding_pow_seconds_per_trial": excluding_pow,
        "median_prove_excluding_pow_seconds": statistics.median(excluding_pow),
        "valid_proof_accepted": True,
        "changed_public_output_rejected": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--optimized-root", type=Path, default=HERE)
    parser.add_argument("--lanes", type=int, default=64)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("--trials must be positive")
    if not 1 <= args.lanes <= 4096:
        parser.error("--lanes must be between 1 and 4096")
    baseline = args.baseline_root.resolve()
    optimized = args.optimized_root.resolve()
    for root in (baseline, optimized):
        if not (root / COMPILER).is_file():
            parser.error(f"not an S31 checkout: {root}")

    with tempfile.TemporaryDirectory(prefix="s31-packed-reduction-") as directory:
        work = Path(directory)
        name = f"reduction{args.lanes}"
        source = work / f"{name}.s31.json"
        source.write_text(json.dumps({
            "version": 1, "name": name,
            "inputs": [{"name": "x", "kind": "m31", "length": args.lanes, "visibility": "private"}],
            "nodes": [{"name": "total", "op": "sum_lanes", "lhs": "x"}],
            "assertions": [], "public_outputs": ["total"],
        }, indent=2) + "\n")
        assignments = []
        statements = []
        initial_values = [P - 1, *range(1, args.lanes)]
        initial_expected = sum(initial_values) % P
        for trial in range(args.trials + 1):
            values = initial_values.copy()
            if args.lanes > 1:
                values[1] += trial
            else:
                values[0] = (values[0] + trial) % P
            expected = sum(values) % P
            assignment = work / f"valid-{trial}.json"
            assignment.write_text(json.dumps({
                "public_inputs": {}, "private_inputs": {"x": values},
                "public_outputs": {"total": [expected]},
            }, indent=2) + "\n")
            assignments.append(assignment)
            statement = work / f"statement-{trial}.json"
            statement.write_text(json.dumps({"public_inputs": {}, "public_outputs": {"total": [expected]}}) + "\n")
            statements.append(statement)
        wrong_statement = work / "wrong-statement.json"
        wrong_statement.write_text(json.dumps({"public_inputs": {}, "public_outputs": {"total": [(initial_expected + 1) % P]}}) + "\n")
        results = {
            "baseline": measure(baseline, "baseline", name, source, assignments,
                                statements, wrong_statement, work, args.trials),
            "packed": measure(optimized, "packed", name, source, assignments,
                              statements, wrong_statement, work, args.trials),
        }
    before = results["baseline"]
    after = results["packed"]
    if before["canonical_ir_sha256"] != after["canonical_ir_sha256"]:
        raise AssertionError("the two versions compiled different normalized relations")
    report = {
        "schema": "s31-packed-reduction-benchmark-v1",
        "host": host(),
        "case": {
            "name": name, "input": f"private [m31;{args.lanes}]",
            "public_output_by_trial": f"{initial_expected} + trial index modulo p",
            "contains_field_wraparound": args.lanes > 1,
            "lowering": "direct-gate", "warmup_proofs": 1,
            "measured_trials_per_version": args.trials,
            "prover_timing_note": "Each trial changes the private witness to vary the transcript PoW nonce. Timings exclude build and verifier work. Stage times come from the prover log.",
        },
        "results": results,
        "non_pow_prove_speedup_median": before["median_prove_excluding_pow_seconds"] / after["median_prove_excluding_pow_seconds"],
        "proof_byte_reduction_fraction": 1 - after["median_proof_bytes"] / before["median_proof_bytes"],
    }
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        output = args.output.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded)
        print(output)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, AssertionError) as exc:
        print(f"packed reduction benchmark: {exc}", file=sys.stderr)
        raise SystemExit(1)
