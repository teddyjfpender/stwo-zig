#!/usr/bin/env python3
"""Compare scalar and packed private-M31 input lowering on one S31 relation.

Example:
  git worktree add --detach /tmp/s31-before-packed-inputs c42d8d201
  python3 src/frontends/s31/benchmarks/benchmark_packed_inputs.py \
      --baseline-root /tmp/s31-before-packed-inputs \
      --output design/s31/measurements/language/packed-inputs-2026-10-06.json

The baseline must be c42d8d201, which already contains the packed sum_lanes
projection. This isolates only the private input packing change.
"""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import json
import statistics
import sys
import tempfile
from pathlib import Path

from benchmark_packed_reduction import HERE, P, host, measure, run


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--optimized-root", type=Path, default=HERE)
    parser.add_argument("--lanes", type=int, default=128)
    parser.add_argument("--trials", type=int, default=7)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.trials < 1 or not 4 <= args.lanes <= 4096:
        parser.error("trials must be positive and lanes between 4 and 4096")
    baseline = args.baseline_root.resolve()
    optimized = args.optimized_root.resolve()
    baseline_head = run("git", "rev-parse", "HEAD", cwd=baseline)
    if baseline_head != "c42d8d2015ee18f9ccafb818f1f82ac4136c1ccb":
        parser.error(f"baseline must be c42d8d201, got {baseline_head}")

    with tempfile.TemporaryDirectory(prefix="s31-packed-inputs-") as directory:
        work = Path(directory)
        name = f"packed_input_reduction{args.lanes}"
        source = work / f"{name}.s31.json"
        source.write_text(json.dumps({
            "version": 1, "name": name,
            "inputs": [{"name": "x", "kind": "m31", "length": args.lanes,
                        "visibility": "private"}],
            "nodes": [{"name": "total", "op": "sum_lanes", "lhs": "x"}],
            "assertions": [], "public_outputs": ["total"],
        }, indent=2) + "\n")
        base_values = [P - 1, *range(1, args.lanes)]
        assignments = []
        statements = []
        for trial in range(args.trials + 1):
            values = base_values.copy()
            values[1] += trial
            expected = sum(values) % P
            assignment = work / f"assignment-{trial}.json"
            assignment.write_text(json.dumps({
                "public_inputs": {}, "private_inputs": {"x": values},
                "public_outputs": {"total": [expected]},
            }) + "\n")
            assignments.append(assignment)
            statement = work / f"statement-{trial}.json"
            statement.write_text(json.dumps({
                "public_inputs": {}, "public_outputs": {"total": [expected]},
            }) + "\n")
            statements.append(statement)
        wrong = work / "changed-statement.json"
        wrong.write_text(json.dumps({
            "public_inputs": {},
            "public_outputs": {"total": [(sum(base_values) + 1) % P]},
        }) + "\n")
        before = measure(baseline, "scalar-input", name, source, assignments,
                         statements, wrong, work, args.trials)
        after = measure(optimized, "packed-input", name, source, assignments,
                        statements, wrong, work, args.trials)
    if before["canonical_ir_sha256"] != after["canonical_ir_sha256"]:
        raise AssertionError("normalized relation changed between builds")
    result = {
        "schema": "s31-packed-private-input-benchmark-v1",
        "host": host(),
        "case": {
            "source": f"private [m31;{args.lanes}] -> sum_lanes -> public m31",
            "lowering": "direct-gate",
            "baseline_commit": baseline_head,
            "warmup_proofs_per_version": 1,
            "measured_proofs_per_version": args.trials,
            "witnesses": "distinct private arrays, each with field wraparound",
            "timing": "Prover log stage times; non-PoW subtracts logged interaction and FRI PoW. Wall time includes process startup. Verification excluded.",
        },
        "scalar_input": before,
        "packed_input": after,
        "median_proof_byte_reduction_fraction": 1 - after["median_proof_bytes"] / before["median_proof_bytes"],
        "median_non_pow_prove_speedup": before["median_prove_excluding_pow_seconds"] / after["median_prove_excluding_pow_seconds"],
        "median_wall_prove_speedup": statistics.median(before["wall_proving_seconds_per_trial"]) / statistics.median(after["wall_proving_seconds_per_trial"]),
    }
    encoded = json.dumps(result, indent=2) + "\n"
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
        print(f"packed input benchmark: {exc}", file=sys.stderr)
        raise SystemExit(1)
