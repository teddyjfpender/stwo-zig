#!/usr/bin/env python3
"""parity_m3.py RUN_DIR BLOCK: byte parity of proof_sha256 vs the M3 integrate scale receipt (same env)."""
import json, sys
run, block = sys.argv[1], sys.argv[2]
mine = json.load(open(f"{run}/receipt.json"))["proof_sha256"]
ref = json.load(open(f"/workspace/m3/runs/integrate/{block}-2gpu-scale/receipt.json"))["proof_sha256"]
def flat(d, p=""):
    out = {}
    if isinstance(d, dict):
        for k, v in d.items(): out.update(flat(v, f"{p}/{k}"))
    else: out[p] = d
    return out
a, b = flat(mine), flat(ref)
mism = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
print(json.dumps({"reference": f"integrate/{block}-2gpu-scale", "compared": len(set(a) | set(b)), "byte_identical": not mism, "mismatched": mism[:20]}))
