#!/usr/bin/env python3
"""Byte-parity of a run's proofs against an M3/M4 reference receipt.

Flattens receipt["proof_sha256"] (native bins, bundle, every recursive proof,
tree) of both receipts and reports identical / differing / missing entries.
Usage: rv64_m4_parity.py RUN_RECEIPT REFERENCE_RECEIPT
Exit 0 only when every reference entry is present and identical.
"""
import json
import sys


def flatten(value, prefix=""):
    out = {}
    if isinstance(value, dict):
        for key, item in value.items():
            out.update(flatten(item, f"{prefix}{key}/"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.update(flatten(item, f"{prefix}{index}/"))
    else:
        out[prefix.rstrip("/")] = value
    return out


def main():
    run = flatten(json.load(open(sys.argv[1]))["proof_sha256"])
    ref = flatten(json.load(open(sys.argv[2]))["proof_sha256"])
    differing = sorted(k for k in ref if k in run and run[k] != ref[k])
    missing = sorted(k for k in ref if k not in run)
    extra = sorted(k for k in run if k not in ref)
    result = {"byte_identical": not differing and not missing and len(ref) > 0,
              "compared": len(ref), "differing": differing, "missing": missing,
              "extra": extra, "reference": sys.argv[2]}
    print(json.dumps(result, indent=1))
    sys.exit(0 if result["byte_identical"] else 1)


if __name__ == "__main__":
    main()
