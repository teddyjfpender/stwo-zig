#!/usr/bin/env python3
"""Qualify exported CUDA PIE cohort proofs with the pinned Rust verifier."""

import argparse
import csv
import json
from pathlib import Path
import re
import subprocess
import time

import benchmark_cairo_cuda as baseline


STATIC = re.compile(r"cairo-cuda static-phase initial_upload_ns=(\d+) "
                    r"preprocessed_load_ns=(\d+) materialize_ns=(\d+)")
INGRESS = ("paths", "runtime", "source", "controllers", "twiddles", "allocation",
           "binding", "static", "writers", "statement_and_session")
EXTRA = ("fixed_initial_upload_s", "fixed_preprocessed_load_s", "fixed_materialize_s",
         "ingress_other_s", "ingress_preparation_other_s", "publication_other_s", "process_overhead_s",
         "rust_verify_s", "rust_verify_inner_s", "rust_verify_peak_rss_bytes") + tuple(
             f"ingress_{phase}_s" for phase in INGRESS)


def add_ingress_profile(row: dict, directory: Path) -> None:
    backend = json.loads((directory / "backend.json").read_text())
    timings = backend["completed_trials"][0]["ingress_timings"]
    if abs(sum(timings[f"{phase}_ns"] for phase in INGRESS) / 1e9
           - float(row["ingress_s"])) > 0.003:
        raise ValueError(f"ingress phase sum mismatch for {row['pie']}")
    row.update({f"ingress_{phase}_s": round(timings[f"{phase}_ns"] / 1e9, 3)
                for phase in INGRESS})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proving-csv", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    with args.proving_csv.open(newline="") as source:
        reader = csv.DictReader(source)
        fields = reader.fieldnames
        rows = list(reader)
    if fields is None:
        raise ValueError("proving CSV has no header")
    fields = fields + [field for field in EXTRA if field not in fields]
    for row in rows:
        directory = args.results / row["pie"] / "sn-pie-1-trial-1"
        verification = directory / "verification.json"
        if row["status"] == "verified":
            add_ingress_profile(row, directory)
            row["ingress_preparation_other_s"] = round(
                float(row["ingress_s"]) - float(row["ingress_source_s"])
                - float(row["fixed_preprocessed_load_s"]), 3)
            verdict = json.loads(verification.read_text())
            if (verdict.get("verified") is not True or
                    verdict.get("proof_sha256") != row["proof_sha256"]):
                raise ValueError(f"saved verifier receipt mismatch for {row['pie']}")
            row["rust_verify_inner_s"] = round(verdict["wall_time_ns"] / 1e9, 3)
            continue
        if row["status"] != "proof_generated":
            continue
        add_ingress_profile(row, directory)
        proof = directory / "proof.json"
        log = (directory / "prover.log").read_text(errors="replace")
        match = STATIC.search(log)
        if match is None:
            raise ValueError(f"fixed-load profile missing for {row['pie']}")
        initial, preprocessed, materialize = (int(value) / 1e9 for value in match.groups())
        row.update(fixed_initial_upload_s=round(initial, 3),
                   fixed_preprocessed_load_s=round(preprocessed, 3),
                   fixed_materialize_s=round(materialize, 3),
                   ingress_preparation_other_s=round(float(row["ingress_s"])
                                                     - float(row["ingress_source_s"])
                                                     - preprocessed, 3),
                   ingress_other_s=round(float(row["ingress_s"]) - initial - preprocessed - materialize, 3),
                   publication_other_s=round(float(row["adapted_to_publication_s"])
                                             - float(row["ingress_s"])
                                             - float(row["proof_execute_finish_s"]), 3),
                   process_overhead_s=round(float(row["process_wall_s"])
                                             - float(row["adapted_to_publication_s"]), 3))
        if not proof.is_file() or baseline.sha(proof) != row["proof_sha256"]:
            raise ValueError(f"exported proof missing or changed for {row['pie']}")
        started = time.perf_counter()
        result = subprocess.run(["/usr/bin/time", "-l", str(args.verifier), "verify", "--proof", str(proof),
                                 "--channel", "blake2s", "--proof-format", "json",
                                 "--result", str(verification)], capture_output=True, text=True,
                                timeout=180)
        row["rust_verify_s"] = round(time.perf_counter() - started, 3)
        memory = re.search(r"(\d+)\s+maximum resident set size", result.stderr)
        row["rust_verify_peak_rss_bytes"] = int(memory.group(1)) if memory else ""
        if result.returncode:
            row.update(status="verify_failed", error=(result.stdout + result.stderr)[-500:])
        else:
            verdict = json.loads(verification.read_text())
            if (verdict.get("schema_version") != 1 or verdict.get("channel") != "blake2s" or
                    verdict.get("proof_format") != "json" or verdict.get("error") is not None or
                    verdict.get("verified") is not True or
                    verdict.get("proof_sha256") != row["proof_sha256"] or
                    verdict.get("stwo_cairo_revision") != baseline.CAIRO_REVISION or
                    verdict.get("stwo_revision") != baseline.STWO_REVISION):
                row.update(status="verify_failed", error="official verifier receipt mismatch")
            else:
                row["status"] = "verified"
                row["rust_verify_inner_s"] = round(verdict["wall_time_ns"] / 1e9, 3)
        print(f"{row['pie']}: {row['status']}", flush=True)
        with args.out.open("w", newline="") as sink:
            writer = csv.DictWriter(sink, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
    with args.out.open("w", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
