#!/usr/bin/env python3
"""Fresh receivers for a standalone RV64 MUL/high/W + shared BYTE STARK."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess


def identity(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def qualify(verifier, artifacts):
    paths = [artifacts / name for name in ("public.json", "claims.json", "proof.bin")]
    public, claims = [json.loads(path.read_text()) for path in paths[:2]]
    negative = artifacts / "negative"
    negative.mkdir(exist_ok=True)
    cases = [("valid", *paths, None)]
    for name, mutate in (
        ("request-opcode", lambda p: p["requests"][0].__setitem__("opcode", "MULHU")),
        ("request-a-full64", lambda p: p["requests"][0].__setitem__("a", p["requests"][0]["a"] ^ (1 << 63))),
        ("request-b-full64", lambda p: p["requests"][0].__setitem__("b", p["requests"][0]["b"] ^ (1 << 63))),
        ("request-result", lambda p: p["requests"][0].__setitem__("result", p["requests"][0]["result"] ^ 1)),
        ("ignored-W-upper-input-still-bus-bound", lambda p: p["requests"][-1].__setitem__("a", p["requests"][-1]["a"] ^ (1 << 63))),
        ("count", lambda p: p["requests"].pop()),
    ):
        changed = copy.deepcopy(public)
        mutate(changed)
        path = negative / (name + ".json")
        path.write_text(json.dumps(changed))
        cases.append((name, path, paths[1], paths[2], "Rv64MultiplicationClosure"))
    for family in ("multiplication", "bytes"):
        changed = copy.deepcopy(claims)
        changed[family]["c0"]["a"]["v"] = (changed[family]["c0"]["a"]["v"] + 1) % 2147483647
        path = negative / (family + ".json")
        path.write_text(json.dumps(changed))
        cases.append((family + "-claim", paths[0], path, paths[2], "Rv64MultiplicationClosure"))
    changed = copy.deepcopy(claims)
    changed["multiplication"]["c0"]["a"]["v"] = (changed["multiplication"]["c0"]["a"]["v"] + 1) % 2147483647
    changed["bytes"]["c0"]["a"]["v"] = (changed["bytes"]["c0"]["a"]["v"] - 1) % 2147483647
    path = negative / "balanced-false-claims.json"
    path.write_text(json.dumps(changed))
    cases.append(("balanced-false-claims", paths[0], path, paths[2], "OodsNotMatching"))
    changed = copy.deepcopy(claims)
    changed["multiplication"]["c0"]["a"]["v"] = 2147483647
    path = negative / "noncanonical.json"
    path.write_text(json.dumps(changed))
    cases.append(("noncanonical", paths[0], path, paths[2], "InvalidRv64MultiplicationClaim"))
    for family in ("count", "state"):
        cases.append(("previous-" + family + "-prefix", paths[0], paths[1], artifacts / ("bad-" + family + "-prefix.bin"), "OodsNotMatching"))
    outcomes, receiver = [], None
    for name, p, c, proof, expected in cases:
        run = subprocess.run([str(verifier), str(p), str(c), str(proof)], text=True, capture_output=True, timeout=180)
        passed = run.returncode == 0 and json.loads(run.stdout).get("verified") is True if expected is None else run.returncode > 0 and expected in run.stderr
        if not passed:
            raise ValueError(f"unexpected {name}: {run.returncode} {run.stderr[:500]}")
        if expected is None:
            receiver = json.loads(run.stdout)
        outcomes.append({"case": name, "expected_accept": expected is None, "passed": True, "receiver_exit": run.returncode, "error": run.stderr.splitlines()[0] if run.stderr else None})
    n = 1 << public["log_size"]
    return {"schema": "rv64-multiplication-provider-qualification-v1", "standalone_mul_byte_provider": True, "cpu_ingress": False, "ethereum_block_proof": False, "operations": ["MUL", "MULH", "MULHU", "MULHSU", "MULW"], "request_count": len(public["requests"]), "log_size": public["log_size"], "queries": 70, "pow_bits": 26, "layout": {"fixed": 3, "main": 87, "interaction": 132, "constraints": 174, "degree_max": 4, "byte_queries_per_padded_row": 96, "previous_main": 1, "previous_interaction": 4}, "source_bytes_including_byte_table": 222 * n * 4 + 12 * 256 * 4, "coset_evaluation_source_scratch_bytes": 227 * n * 4, "cost_scope": "source/scratch only; excludes polynomial coefficients, FFT twiddles, PCS, stacks and caller metadata", "receiver_cost_single_sample": receiver, "receiver_cost_scope": "cold process; diagnostic, not benchmark", "artifacts": [identity(path) for path in (*paths, artifacts / "bad-count-prefix.bin", artifacts / "bad-state-prefix.bin", verifier)], "cases": outcomes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.verifier.resolve(), args.artifacts.resolve())
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.report.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n")
    temporary.replace(args.report)
    print(json.dumps({"standalone_verified": True, "receiver_cases": len(result["cases"]), "cpu_ingress": False}))


if __name__ == "__main__":
    main()
