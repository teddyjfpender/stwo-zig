#!/usr/bin/env python3
"""Run repeated, natively verified S31 and Cairo proving trials."""

import argparse
import gzip
import json
import re
import statistics
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
S31_BIN = Path(__file__).resolve().parent / "zig-out/bin/s31-showcase"
CAIRO_BIN = ROOT / "zig-out/bin/stwo-cairo-cpu"


def run(*args: str) -> str:
    proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode:
        raise RuntimeError(f"command failed ({proc.returncode}): {args}\n{proc.stdout}{proc.stderr}")
    return proc.stdout + proc.stderr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("rounds", type=int)
    parser.add_argument("--trials", type=int, default=5)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("trials must be positive")
    case = ROOT / "zig-out/s31/scale" / str(args.rounds)
    expected = json.loads((case / "public_words.json").read_text())
    cairo_input = case / "cairo-input.json"
    if not cairo_input.exists():
        parser.error(f"missing Cairo prover input: {cairo_input}")

    execute_log = run(
        "scarb", "--manifest-path", str(case / "cairo/Scarb.toml"), "execute",
        "--no-build", "--arguments", "1,2,3,65535", "--output", "none",
        "--print-program-output", "--print-resource-usage",
    )
    (case / "cairo-execute.log").write_text(execute_log)
    match = re.search(r"steps:\s*([\d,]+)", execute_log)
    if not match:
        raise RuntimeError("missing Cairo VM step count")
    output = [int(x) for x in execute_log.split("Program output:\n", 1)[1].split("Resources:", 1)[0].split()]
    if output != expected:
        raise RuntimeError(f"Cairo execution output differs: {output} != {expected}")

    s31_times = []
    cairo_times = []
    s31_size = None
    cairo_size = None
    cairo_gzip_size = None
    cairo_profile = None
    for trial in range(args.trials):
        s31_proof = case / f"s31-{trial}.proof"
        log = run(str(S31_BIN), "prove", str(s31_proof))
        (case / f"s31-{trial}.log").write_text(log)
        public_line = re.search(r"^public words: ([0-9 ]+)$", log, re.MULTILINE)
        if not public_line or [int(word) for word in public_line.group(1).split()] != expected:
            raise RuntimeError(f"S31 public output differs from generated reference: {log}")
        metrics = re.search(
            r"field-ops=(\d+)->(\d+), Blake-G=(\d+)->(\d+), proof=(\d+) bytes, "
            r"setup=([0-9.]+)s, prove=([0-9.]+)s, total through verification=([0-9.]+)s", log
        )
        if not metrics:
            raise RuntimeError(f"missing S31 metrics: {log}")
        raw_rows, padded_rows, raw_blake, padded_blake, size, setup, prove, total = metrics.groups()
        if s31_size is not None and s31_size != int(size):
            raise RuntimeError("S31 proof size changed between trials")
        s31_size = int(size)
        s31_times.append({"setup_s": float(setup), "prove_s": float(prove), "total_s": float(total)})

        cairo_proof = case / f"cairo-{trial}.proof.json"
        cairo_report = case / f"cairo-{trial}.report.json"
        cairo_proof.unlink(missing_ok=True)
        cairo_report.unlink(missing_ok=True)
        run(
            str(CAIRO_BIN), "prove", "--prover-input", str(cairo_input),
            "--proof", str(cairo_proof), "--proof-format", "json",
            "--report-out", str(cairo_report), "--verify",
        )
        report = json.loads(cairo_report.read_text())
        if not report["verification"]["zig"]:
            raise RuntimeError("Cairo native verification failed")
        if cairo_profile is not None and report["profile"] != cairo_profile:
            raise RuntimeError("Cairo proving profile changed between trials")
        cairo_profile = report["profile"]
        proof = json.loads(cairo_proof.read_text())
        config = proof["stark_proof"]["config"]
        fri = config["fri_config"]
        expected_fri = {
            "pow_bits": 26,
            "log_blowup_factor": 1,
            "log_last_layer_degree_bound": 0,
            "n_queries": 70,
            "fold_step": 1,
        }
        actual_fri = {"pow_bits": config["pow_bits"], **{key: fri[key] for key in expected_fri if key != "pow_bits"}}
        if actual_fri != expected_fri:
            raise RuntimeError(f"unexpected Cairo FRI configuration: {actual_fri}")
        public = [word[1][0] for word in proof["claim"]["public_data"]["public_memory"]["output"]]
        if public != expected:
            raise RuntimeError(f"Cairo proof public output differs: {public} != {expected}")
        cairo_size = report["proof"]["bytes"]
        cairo_gzip_size = len(gzip.compress(cairo_proof.read_bytes(), mtime=0))
        timing = report["timing"]
        cairo_times.append({
            "prove_s": timing["prove_ns"] / 1e9,
            "request_s": timing["request_until_publication_ns"] / 1e9,
            "peak_footprint_bytes": report["prover_process_usage"]["lifetime_peak_physical_footprint_bytes"],
        })
        print(f"rounds={args.rounds} trial={trial + 1}/{args.trials} "
              f"S31={float(prove):.3f}s Cairo={timing['prove_ns'] / 1e9:.3f}s", flush=True)

    native_verifier = Path(__file__).resolve().parent / f"zig-out/bin/s31-square{args.rounds}-verifier"
    run(str(native_verifier), str(case / "s31-0.proof"), "1", "2", "3", "65535")
    wrong = subprocess.run(
        (str(native_verifier), str(case / "s31-0.proof"), "1", "2", "3", "65534"),
        cwd=ROOT, capture_output=True, text=True,
    )
    if wrong.returncode == 0:
        raise RuntimeError("S31 verifier accepted changed public input")
    tampered = bytearray((case / "s31-0.proof").read_bytes())
    tampered[len(tampered) // 2] ^= 1
    tampered_path = case / "s31-tampered.proof"
    tampered_path.write_bytes(tampered)
    tampered_result = subprocess.run(
        (str(native_verifier), str(tampered_path), "1", "2", "3", "65535"),
        cwd=ROOT, capture_output=True, text=True,
    )
    if tampered_result.returncode == 0:
        raise RuntimeError("S31 verifier accepted a modified proof")

    summary = {
        "schema": "s31-cairo-scale-v0",
        "rounds": args.rounds,
        "public_words": expected,
        "trials": args.trials,
        "fri_visible_settings": expected_fri,
        "s31": {
            "raw_field_rows": int(raw_rows),
            "padded_field_rows": int(padded_rows),
            "raw_blake_g_rows": int(raw_blake),
            "padded_blake_g_rows": int(padded_blake),
            "binary_proof_bytes": s31_size,
            "prove_seconds": [sample["prove_s"] for sample in s31_times],
            "median_prove_seconds": statistics.median(sample["prove_s"] for sample in s31_times),
            "median_total_through_verification_seconds": statistics.median(sample["total_s"] for sample in s31_times),
            "native_verified": True,
            "changed_public_rejected": True,
            "tampered_proof_rejected": True,
        },
        "cairo": {
            "proving_profile": cairo_profile,
            "vm_steps": int(match.group(1).replace(",", "")),
            "json_proof_bytes_last_trial": cairo_size,
            "gzip_json_proof_bytes_last_trial": cairo_gzip_size,
            "prove_seconds": [sample["prove_s"] for sample in cairo_times],
            "median_prove_seconds": statistics.median(sample["prove_s"] for sample in cairo_times),
            "median_request_through_verification_seconds": statistics.median(sample["request_s"] for sample in cairo_times),
            "median_peak_physical_footprint_bytes": statistics.median(sample["peak_footprint_bytes"] for sample in cairo_times),
            "native_verified": True,
        },
        "comparison_limit": "Different proof protocols, verifier implementations, encodings, and preprocessing policies; one host; stochastic PoW.",
    }
    (case / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
