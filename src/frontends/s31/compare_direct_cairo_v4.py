#!/usr/bin/env python3
"""Matched current direct-M31 chip and Cairo recurrence proof comparison."""

import argparse
import gzip
import json
import platform
import statistics

import s31


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=32768)
    parser.add_argument("--trials", type=int, default=5)
    args = parser.parse_args()
    record_path = s31.ROOT / "design" / "s31" / "measurements" / "profiles-direct-v4-2026-10-06.json"
    record = json.loads(record_path.read_text())
    fingerprint = s31.compiler_fingerprint()
    if record["compiler_sha256"] != fingerprint:
        raise ValueError("direct profile benchmark used another compiler build")
    work = s31.ROOT / "zig-out" / "s31" / "benchmark-direct-v4" / fingerprint[:16]
    direct_case = next(item for item in record["results"] if item["rounds"] == args.rounds and item["lowering"] == "direct-chip")
    if args.trials < 1 or args.trials > len(direct_case["trials"]):
        raise ValueError("trial count exceeds the direct profile record")
    package = work / f"{args.rounds}-direct-chip" / "package"
    s31.verify_package(package)
    verifier = package / "bin" / f"s31-step{args.rounds}-native-verifier"
    cairo_case = s31.ROOT / "zig-out" / "s31" / "scale" / str(args.rounds)
    executable = cairo_case / "cairo" / "target" / "dev" / f"s31_square{args.rounds}_cairo.executable.json"
    adapter = s31.ROOT / "tools" / "stwo-cairo-vm-adapter-rs" / "target" / "release" / "stwo-cairo-vm-adapter"
    cairo_prover = s31.ROOT / "zig-out" / "bin" / "stwo-cairo-cpu"
    for path in (executable, adapter, cairo_prover):
        if not path.exists():
            raise FileNotFoundError(path)
    output_dir = work / f"{args.rounds}-direct-cairo"
    output_dir.mkdir(parents=True, exist_ok=True)
    trials = []
    for trial in range(args.trials):
        direct = direct_case["trials"][trial]
        assignment = json.loads((work / f"step{args.rounds}.trial-{trial}.valid.json").read_text())
        inputs = assignment["public_inputs"]["x"]
        expected = inputs + assignment["public_outputs"]["result"]
        if direct["public_inputs"]["x"] != inputs:
            raise AssertionError("direct profile witness differs")
        direct_proof = work / f"{args.rounds}-direct-chip" / f"trial-{trial}.proof"
        statement = work / f"step{args.rounds}.trial-{trial}.statement.json"
        if s31.file_hash(direct_proof) != direct["proof_sha256"]:
            raise AssertionError("direct proof artifact changed since benchmark")
        s31.invoke(str(verifier), str(direct_proof), str(statement), str(package / "verification-key.json"))
        arguments = output_dir / f"trial-{trial}.arguments.json"
        s31.write_json(arguments, [hex(value) for value in inputs])
        prover_input = output_dir / f"trial-{trial}.cairo-input.json"
        s31.invoke(
            str(adapter), "run", "--program", str(executable), "--program-type", "executable",
            "--arguments", str(arguments), "--prover-input-out", str(prover_input),
        )
        cairo_proof = output_dir / f"trial-{trial}.cairo-proof.json"
        cairo_report = output_dir / f"trial-{trial}.cairo-report.json"
        s31.invoke(
            str(cairo_prover), "prove", "--prover-input", str(prover_input),
            "--proof", str(cairo_proof), "--proof-format", "json",
            "--report-out", str(cairo_report), "--verify",
        )
        report = json.loads(cairo_report.read_text())
        proof = json.loads(cairo_proof.read_text())
        if not report["verification"]["zig"]:
            raise AssertionError("Cairo native verifier rejected its proof")
        cairo_words = [word[1][0] for word in proof["claim"]["public_data"]["public_memory"]["output"]]
        if cairo_words != expected:
            raise AssertionError(f"Cairo public words {cairo_words} != {expected}")
        config = proof["stark_proof"]["config"]
        fri = config["fri_config"]
        visible = {
            "pow_bits": config["pow_bits"],
            "log_blowup_factor": fri["log_blowup_factor"],
            "log_last_layer_degree_bound": fri["log_last_layer_degree_bound"],
            "n_queries": fri["n_queries"],
            "fold_step": fri["fold_step"],
        }
        if visible != {"pow_bits": 26, "log_blowup_factor": 1, "log_last_layer_degree_bound": 0, "n_queries": 70, "fold_step": 1}:
            raise AssertionError(f"Cairo FRI settings changed: {visible}")
        trials.append({
            "trial": trial,
            "public_words": expected,
            "direct_prove_s": direct["prove_s"],
            "direct_setup_s": direct["setup_s"],
            "direct_prove_excluding_pow_s": direct["prove_excluding_pow_s"],
            "direct_proof_bytes": direct["proof_bytes"],
            "direct_proof_sha256": direct["proof_sha256"],
            "cairo_prove_s": report["timing"]["prove_ns"] / 1e9,
            "cairo_request_s": report["timing"]["request_until_publication_ns"] / 1e9,
            "cairo_peak_physical_bytes": report["prover_process_usage"]["lifetime_peak_physical_footprint_bytes"],
            "cairo_profile": report["profile"],
            "cairo_proof_json_bytes": cairo_proof.stat().st_size,
            "cairo_proof_gzip_bytes": len(gzip.compress(cairo_proof.read_bytes(), mtime=0)),
            "cairo_proof_sha256": s31.file_hash(cairo_proof),
        })
        print(f"trial {trial}: direct={trials[-1]['direct_prove_s']:.3f}s Cairo={trials[-1]['cairo_prove_s']:.3f}s", flush=True)
    result = {
        "schema": "s31-direct-cairo-comparison-v4",
        "compiler_sha256": fingerprint,
        "machine": platform.platform(),
        "rounds": args.rounds,
        "trial_count": args.trials,
        "cairo_executable_sha256": s31.file_hash(executable),
        "cairo_proving_profile": trials[0]["cairo_profile"],
        "visible_fri_settings": visible,
        "median_direct_prove_s": statistics.median(t["direct_prove_s"] for t in trials),
        "median_cairo_prove_s": statistics.median(t["cairo_prove_s"] for t in trials),
        "trials": trials,
        "comparison_note": "The same public recurrence values were proved and natively verified. Both use visible 26-bit PoW, blowup 2, 70 queries and degree-one last layer, but proof protocols, encoding, preprocessing, native verifiers and security analyses differ. Cairo prove excludes VM adapter execution; S31 prove excludes witness generation and cold setup.",
    }
    output = s31.ROOT / "design" / "s31" / "measurements" / "direct-cairo-v4-2026-10-06.json"
    s31.write_json(output, result)
    print(output)


if __name__ == "__main__":
    main()
