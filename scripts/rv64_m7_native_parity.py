#!/usr/bin/env python3
"""Compare every emitted artifact with an explicit M6 default receipt.

The M4 daemon's built-in parity compares with M3 (a different outer format).
This gate instead pins the M6 k4-cap3 receipts and keeps all native bins,
bundle bytes, recursive node proofs and tree bytes in its equality check.
"""
import argparse
import json
from pathlib import Path
import rv64_m3_pod as P
import rv64_resident_basket as R


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--references", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    receipt = json.loads((args.run / "receipt.json").read_text())
    rows = []
    for request in receipt["requests"]:
        reference = args.references / f'{request["block"]}-2gpu-c1-bench/receipt.json'
        control = json.loads(reference.read_text())
        if not control["receiver"]["accepted"]:
            raise SystemExit("reference lacks independent acceptance: " + str(reference))
        proof = Path(request["proof"])
        native = {p.name: P.sha(p) for p in sorted(proof.glob("*.bin"))}
        snapshot = R.recursive_snapshot(proof, request["leaves"])
        actual = {"native": native, "bundle": P.sha(proof / "bundle.json"), "recursive": snapshot}
        ref = control["proof_sha256"]
        checks = {
            "native_bins": actual["native"] == ref["native"],
            "bundle": actual["bundle"] == ref["bundle"],
            "recursive_tree": snapshot["tree_sha256"] == ref["recursive"]["tree_sha256"],
            "recursive_proofs": snapshot["proof_sha256"] == ref["recursive"]["proof_sha256"],
        }
        rows.append({"block": request["block"], "trial": request["trial"],
                     "reference": str(reference), "reference_sha256": P.sha(reference),
                     "checks": checks, "byte_identical": all(checks.values()),
                     "proof_sha256": actual, "stages": request["stages"],
                     "root_proof_bytes": request["proof_bytes_root"]})
    receivers = receipt["receivers"]
    accepted_blocks = {r["block"] for r in receivers if r["accepted"]}
    result = {"schema": "rv64-m7-native-parity/v1", "label": "M", "run": str(args.run),
              "receipt_sha256": P.sha(args.run / "receipt.json"),
              "source_commit": receipt["source_commit"], "assets": receipt["assets"],
              "load_avg_before": receipt["load_avg_before"], "load_avg_after": receipt["load_avg_after"],
              "all_byte_identical": all(r["byte_identical"] for r in rows),
              "all_received": set(receipt["blocks"]) <= accepted_blocks,
              "requests": rows, "receivers": receivers}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ("source_commit", "all_byte_identical", "all_received")}))
    if not result["all_byte_identical"] or not result["all_received"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
