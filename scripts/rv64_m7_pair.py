#!/usr/bin/env python3
"""Compare all artifacts of each resident request with a pinned baseline receipt.

Runs on the pod. Unlike the legacy resident receipt's parity_vs_m3 field, this
checks the M6 default format, including every physical recursion node and tree.
It records each request separately and never infers fresh receiver acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path

import rv64_resident_basket as R


def sha(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def snapshot(request):
    proof = Path(request["proof"])
    recursive = R.recursive_snapshot(proof, request["leaves"])
    result = {"native/" + p.name: sha(p) for p in sorted(proof.glob("*.bin"))}
    if not result:
        raise ValueError("missing native proof artifacts")
    result["bundle.json"] = sha(proof / "bundle.json")
    result.update({"recursive/" + name: value for name, value in recursive["proof_sha256"].items()})
    result["recursive/tree.json"] = recursive["tree_sha256"]
    return result


def compare(control, candidate):
    controls = {}
    for request in control["requests"]:
        fingerprint = snapshot(request)
        block = request["block"]
        if block in controls and controls[block] != fingerprint:
            raise ValueError(f"baseline proof nondeterminism on {block}")
        controls[block] = fingerprint
    expected_positions = {(block, trial) for block in control["blocks"] for trial in range(candidate["repeat"])}
    actual_positions = [(r["block"], r["trial"]) for r in candidate["requests"]]
    if set(candidate["blocks"]) != set(control["blocks"]) or set(actual_positions) != expected_positions or len(actual_positions) != len(expected_positions):
        raise ValueError("candidate is missing requests, repeats blocks, or uses a different workload")
    rows = []
    for request in candidate["requests"]:
        block = request["block"]
        expected = controls[block]
        actual = snapshot(request)
        names = sorted(set(expected) | set(actual))
        mismatches = [name for name in names if expected.get(name) != actual.get(name)]
        rows.append({"block": block, "trial": request["trial"], "ordinal": request["ordinal"],
                     "compared_artifacts": len(names), "byte_identical": not mismatches,
                     "mismatches": mismatches, "fingerprint": actual,
                     "output_matches_pin": request["output_matches_pin"],
                     "stages": request["stages"], "proof_bytes_root": request["proof_bytes_root"]})
    if not rows:
        raise ValueError("candidate has no measured requests")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    control, candidate = [json.loads(p.read_text()) for p in (args.control, args.candidate)]
    rows = compare(control, candidate)
    result = {"schema": "rv64-m7-resident-pair/v1", "label": "M", "control": str(args.control),
              "control_sha256": sha(args.control), "candidate": str(args.candidate),
              "candidate_sha256": sha(args.candidate), "candidate_source": candidate.get("source_commit"),
              "candidate_assets": candidate["assets"], "candidate_environment": candidate["environment"],
              "control_assets": control["assets"], "control_environment": control["environment"],
              "control_loadavg": control["load_avg_before"], "candidate_loadavg": candidate["load_avg_before"],
              "producer_process": candidate["producer_process"], "physical_gpu_memory": candidate["physical_gpu_memory"],
              "receivers": candidate.get("receivers", []), "requests": rows,
              "byte_identical": all(r["byte_identical"] and r["output_matches_pin"] for r in rows)}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"out": str(args.out), "byte_identical": result["byte_identical"],
                      "requests": [{k: r[k] for k in ("block", "trial", "byte_identical", "compared_artifacts", "stages")}
                                   for r in rows]}, indent=2))
    if not result["byte_identical"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
