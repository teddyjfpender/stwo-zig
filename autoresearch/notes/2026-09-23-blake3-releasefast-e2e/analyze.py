#!/usr/bin/env python3
"""Summarize retained E2E receipts without treating unlike contracts as an A/B."""
import json
import re
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
summary = {"comparison": "current_full_width_only", "speedup_established": False}
for backend in ("cpu", "metal"):
    path = ROOT / f"{backend}.json"
    if not path.exists():
        continue
    report = json.loads(path.read_text())
    assert report["proof_suite"] == "blake3"
    assert report["pcs_config"]["pow_bits"] == 26
    assert report["pcs_config"]["fri_config"]["n_queries"] == 70
    assert report["verified_samples"] == report["samples"] == 3
    assert report["warmups"] == 1 and report["csp_ecdsa"]
    timings = report["timings"]
    assert len(timings) == 3
    for timing in timings:
        assert sum(v for k, v in timing.items() if k != "total_ns") == timing["total_ns"]
    summary[backend] = {
        "median_seconds": {k.removesuffix("_ns"): statistics.median(t[k] for t in timings) / 1e9 for k in timings[0]},
        "samples_seconds": [t["total_ns"] / 1e9 for t in timings],
        "physical_peak_bytes": report["resources"]["after_verified_samples"]["lifetime_max_phys_footprint_bytes"],
        "tracked_peak_bytes": report["host_allocation_budget"]["peak_live_bytes"],
        "proof_sha256": report["proof_sha256"],
    }
for name, filename in (("parent_qualification", "parent.log"), ("parent_product_settings", "parent-product-settings.log")):
    parent = ROOT / filename
    if not parent.exists():
        continue
    log = parent.read_text()
    timing = re.search(r"BLAKE3_EXTENSION_PARENT_TIMING ([^\n]+)", log)
    verified = re.search(r"BLAKE3_EXTENSION_PARENT verified=true ([^\n]+)", log)
    assert timing and verified and "steps succeeded" in log
    if name == "parent_product_settings":
        assert "allocator=smp workers=16 samples=1 warmups=0" in log
    fields = dict(part.split("=", 1) for part in timing[1].split())
    receipt = dict(part.split("=", 1) for part in verified[1].split())
    assert fields["optimize"] == "ReleaseFast"
    assert receipt["leaf_queries"] == receipt["parent_queries"] == "70"
    assert receipt["pow_bits"] == "26"
    phases = {k.removesuffix("_ns"): int(v) / 1e9 for k, v in fields.items() if k.endswith("_ns")}
    assert sum(int(v) for k, v in fields.items() if k.endswith("_ns") and k != "total_ns") == int(fields["total_ns"])
    summary[name] = {"seconds": phases, "workers": int(fields["workers"]), "samples": 1, "worker_peak_bytes": int(receipt["worker_peak_bytes"]), "scope": "canonical_guest_poseidon_parent_from_authenticated_capture", "leaf_proving_included": False}
(ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
