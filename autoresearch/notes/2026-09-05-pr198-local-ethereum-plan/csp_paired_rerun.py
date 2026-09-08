#!/usr/bin/env python3
"""Paired CPU/Metal diagnostic using clean, already-built source snapshots.

Reuses the production 16-case harness and the existing alternating A/B schedule.
This records regressions for investigation; it never grants promotion or weakens
the normative A/B host gate. Run serially with no concurrent builds.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from scripts.riscv_csp_ab_benchmark_lib import contract, host_gate, workspace


def require(condition, message):
    if not condition:
        raise contract.ABError(message)


def checked_row(report, backend, head, case, settings):
    require(report["repository_head"] == report["measurement_commit"] == head,
            "measurement source differs from snapshot")
    require(report["suite_manifest_sha256"] == contract.workload_context()["manifest_sha256"],
            "manifest changed")
    run = report["run"]
    require(all(run[key] == value for key, value in settings.items()), "worker/sample policy changed")
    require(run["backend"] == backend and run["recursion_enabled"] is False,
            "execution route changed")
    require(len(report["measurements"]) == 1, "expected one selected case")
    for key in ("all_outputs_match", "all_proofs_verified", "all_peak_memory_available", "all_recursion_disabled"):
        require(report["summary"][key] is True, key)
    row = report["measurements"][0]
    require((row["target"], row["input_size"], row["cycles"]) ==
            (case["target"], case["input_size"], case["expected_cycles"]), "case changed")
    require(row["protocol"] == {"name": "secure", "pcs_config": contract.csp_contract.SECURE_PCS_CONFIG},
            "CSP protocol changed")
    require(row["uses_precompile"] is False and row["recursion_enabled"] is False, "native route changed")
    require(row["peak_memory"] > 0, "missing memory evidence")
    require(len(row["timing"]["verified_end_to_end_sample_seconds"]) == settings["samples"],
            "missing samples")
    evidence = row["evidence"]
    for key, expected in (("guest_sha256", case["guest_sha256"]),
                          ("input_sha256", case["input_sha256"]),
                          ("output_digest", case["expected_output_digest"])):
        require(evidence[key] == expected, f"{key} changed")
    receipt = evidence["retained_verify_receipt"]
    require(receipt["status"] == "verified" and receipt["implementation_commit"] == head
            and receipt["implementation_dirty"] is False, "fresh verification/source failed")
    if backend == "metal":
        telemetry = evidence["resident_polynomial_telemetry"]
        require(telemetry["declines"] == 0 and
                telemetry["verified_samples_with_dispatch"] == settings["samples"], "Metal dispatch failed")
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()
    require(2 <= args.rounds <= 8 and 3 <= args.samples <= 21, "need repeated rounds/samples")
    roots = {name: workspace.repository_root(getattr(args, name)) for name in contract.ARM_NAMES}
    require(roots["baseline"] != roots["current"], "A/B snapshots must differ")
    sources = {}
    for name, root in roots.items():
        require(not workspace.worktree_status(root)["dirty"], f"dirty {name} snapshot")
        sources[name] = {"head": workspace._git_text(root, "rev-parse", "HEAD"),
                         "content": workspace.source_content(root)}
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    settings = {"workers": 16, "warmups": 1, "samples": args.samples}
    environment, policy = host_gate.benchmark_environment(os.environ, settings["workers"])
    cases = contract.canonical_workloads()
    schedule = contract.canonical_schedule(args.rounds)
    plan = {"schema": "stwo.local-csp-paired-diagnostic.v1", "sources": sources,
            "settings": settings, "environment": policy, "schedule": schedule,
            "backends": ["cpu", "metal"], "promotion_ready": False}
    contract.write_new_json(output / "plan.json", plan)
    observations = {}
    identities = {}
    public_value_hashes = {}
    for entry in schedule:
        arm = entry["arm"]
        case = cases[entry["case_ordinal"]]
        root = roots[arm]
        for backend in plan["backends"]:
            stem = f"{entry['ordinal']:03d}-{arm}-{backend}"
            path = output / f"{stem}.json"
            command = [sys.executable, str(root / "scripts/riscv_csp_benchmark.py"),
                       "--backend", backend, "--cli", str(root / f"zig-out/bin/stwo-zig-riscv-{backend}"),
                       "--trace-cli", str(root / "zig-out/bin/riscv-trace-dump"),
                       "--report-out", str(path), "--targets", case["target"],
                       "--sizes", str(case["input_size"])]
            for key, value in settings.items():
                command += [f"--{key}", str(value)]
            gate = host_gate.quiet_host_preflight(host_gate.collect_host(), enforce_load_threshold=False)
            contract.write_new_json(output / f"{stem}-host.json", gate)
            print(f"{stem}: round {entry['round'] + 1}, {case['target']}/{case['input_size']}", flush=True)
            with (output / f"{stem}.log").open("xb") as log:
                subprocess.run(command, cwd=root, env=environment, stdout=log,
                               stderr=subprocess.STDOUT, check=True, timeout=3600)
            report, raw = contract.load_json(path)
            row = checked_row(report, backend, sources[arm]["head"], case, settings)
            identity = {key: row["evidence"][key] for key in
                        ("guest_sha256", "input_sha256", "output_digest", "proof_sha256",
                         "statement_sha256")}
            # Raw public-values JSON includes the implementation commit. Its hash
            # must match within an arm; proof/statement identities match across arms.
            public_hash = row["evidence"]["public_values_sha256"]
            prior_public = public_value_hashes.setdefault((arm, entry["case_ordinal"]), public_hash)
            require(public_hash == prior_public, "public-values evidence changed within snapshot")
            prior = identities.setdefault(entry["case_ordinal"], identity)
            require(identity == prior, "CPU/Metal or A/B proof/statement identity changed")
            key = (backend, entry["case_ordinal"])
            observations.setdefault(key, {name: [] for name in contract.ARM_NAMES})[arm].append({
                "round": entry["round"], "proof_duration_ns": row["proof_duration"],
                "verify_duration_ns": row["verify_duration"],
                "end_to_end_sample_seconds": row["timing"]["verified_end_to_end_sample_seconds"],
                "peak_rss_bytes": row["peak_memory"], "proof_bytes": row["proof_size"],
                "proof_sha256": identity["proof_sha256"], "public_values_sha256": public_hash, "report": path.name,
                "report_sha256": contract.sha256_bytes(raw), "host_admissible": gate["admissible"]})
    summaries = []
    for (backend, ordinal), records in observations.items():
        summary = contract.summarize_case(records)
        summary.update(backend=backend, target=cases[ordinal]["target"], input_size=cases[ordinal]["input_size"],
                       records=records, identity=identities[ordinal])
        # Diagnostic triage only: a five-percent increase in every paired round
        # deserves investigation. It is not statistical proof of non-regression.
        summary["repeat_increase_over_5pct"] = [metric for metric in ("proof_duration_ns", "peak_rss_bytes")
            if all(current[metric] > baseline[metric] * 1.05 for baseline, current in
                   zip(records["baseline"], records["current"], strict=True))]
        summaries.append(summary)
    for name, root in roots.items():
        require(not workspace.worktree_status(root)["dirty"] and
                workspace.source_content(root) == sources[name]["content"], "snapshot changed during run")
    contract.write_new_json(output / "report.json", {"plan": plan, "cases": summaries,
        "promotion_ready": False, "reason": "diagnostic repeated cohort; normative host and regression review still required"})
    print(f"Complete: {output / 'report.json'}", flush=True)


if __name__ == "__main__":
    main()
