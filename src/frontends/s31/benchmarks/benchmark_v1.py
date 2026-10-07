#!/usr/bin/env python3
"""Pinned, verified S31/Cairo arithmetic, hash, and mixed circuit benchmark."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import platform
import re
import statistics
import subprocess
import time
from pathlib import Path

HERE = S31_SOURCE_ROOT
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location("s31_cli", HERE / "python/s31.py")
s31 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s31)
CAIRO_CASES = {
    "arith4": ("cairo_square", "s31_square256_cairo"),
    "hash4": ("cairo_hash", "s31_hash4_cairo"),
    "mixed4": ("cairo_mixed", "s31_mixed4_cairo"),
}
FRI = {"pow_bits": 26, "log_blowup_factor": 1, "log_last_layer_degree_bound": 0,
       "n_queries": 70, "fold_step": 1}


def measured(*argv: str, cwd: Path = ROOT) -> dict:
    start = time.perf_counter_ns()
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # These commands print only short status lines; their proof data goes to files.
    stdout = process.stdout.read()
    stderr = process.stderr.read()
    _, status, usage = os.wait4(process.pid, 0)
    process.returncode = os.waitstatus_to_exitcode(status)
    wall = (time.perf_counter_ns() - start) / 1e9
    if process.returncode:
        raise RuntimeError(f"{argv} exited {process.returncode}\n{stdout}{stderr}")
    return {
        "stdout": stdout,
        "stderr": stderr,
        "wall_seconds": wall,
        "max_resident_bytes": usage.ru_maxrss if platform.system() == "Darwin" else usage.ru_maxrss * 1024,
    }


def expected_words(source: dict, assignment: dict) -> list[int]:
    words = []
    for item in source["inputs"]:
        if item["visibility"] == "public":
            words.extend(assignment["public_inputs"][item["name"]])
    for name in source["public_outputs"]:
        words.extend(assignment["public_outputs"][name])
    return words + [0] * (8 - len(words))


def check_cairo_proof(path: Path, report: dict, expected: list[int]) -> dict:
    proof = json.loads(path.read_text())
    public = [word[1][0] for word in proof["claim"]["public_data"]["public_memory"]["output"]]
    if public != expected[:len(public)] or len(public) != len(expected):
        raise AssertionError(f"Cairo proof public output differs: {public} != {expected}")
    config = proof["stark_proof"]["config"]
    fri = config["fri_config"]
    actual_fri = {"pow_bits": config["pow_bits"], **{key: fri[key] for key in FRI if key != "pow_bits"}}
    if actual_fri != FRI or not report["verification"]["zig"]:
        raise AssertionError("Cairo proof was unverified or used another FRI profile")
    raw = path.read_bytes()
    return {"json_bytes": len(raw), "gzip_json_bytes": len(gzip.compress(raw, mtime=0)),
            "sha256": hashlib.sha256(raw).hexdigest()}


def median(samples: list[dict], key: str) -> float:
    return statistics.median(sample[key] for sample in samples)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--out", type=Path, default=ROOT / "zig-out/s31/mvp-benchmark/summary.json")
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("trials must be positive")
    output = args.out.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    work_dir = ROOT / "zig-out/s31/mvp-benchmark/runs"
    work_dir.mkdir(parents=True, exist_ok=True)
    compiler = s31.compiler_fingerprint()
    cairo_bin = ROOT / "zig-out/bin/stwo-cairo-cpu"
    adapter = ROOT / "tools/stwo-cairo-vm-adapter-rs/target/release/stwo-cairo-vm-adapter"
    if not cairo_bin.exists() or not adapter.exists():
        raise RuntimeError("build stwo-cairo-cpu and the Cairo VM adapter before benchmarking")
    cases = {}
    for name, (cairo_dir_name, cairo_target) in CAIRO_CASES.items():
        source_path = HERE / "examples" / f"{name}.s31.json"
        assignment_path = HERE / "examples" / f"{name}.valid.json"
        source = json.loads(source_path.read_text())
        assignment = json.loads(assignment_path.read_text())
        expected = expected_words(source, assignment)
        package = s31.build(source_path, ROOT / "zig-out/s31/mvp-benchmark/packages" / f"{name}-{compiler[:16]}")
        s31.verify_package(package)
        prover = package / "bin" / f"s31-{name}-prover"
        verifier = package / "bin" / f"s31-{name}-native-verifier"
        key = package / "verification-key.json"
        statement = HERE / "examples" / f"{name}.statement.json"
        cost = json.loads((package / "cost-report.json").read_text())
        cairo_dir = HERE / "examples" / cairo_dir_name
        s31.invoke("scarb", "--manifest-path", str(cairo_dir / "Scarb.toml"), "build")
        execution = s31.invoke("scarb", "--manifest-path", str(cairo_dir / "Scarb.toml"), "execute",
                               "--no-build", "--arguments", ",".join(str(v) for v in assignment.get("private_inputs", {}).get("secret", assignment.get("public_inputs", {}).get("x", []))),
                               "--output", "none", "--print-program-output", "--print-resource-usage")
        actual = [int(x) for x in execution.split("Program output:\n", 1)[1].split("Resources:", 1)[0].split()]
        if actual != expected:
            raise AssertionError(f"{name}: Cairo VM output differs: {actual} != {expected}")
        vm_steps = int(re.search(r"steps:\s*([\d,]+)", execution).group(1).replace(",", ""))
        executable = cairo_dir / "target/dev" / f"{cairo_target}.executable.json"
        s31_trials = []
        cairo_trials = []
        for trial in range(args.trials):
            proof = work_dir / f"{name}.{trial}.s31.proof"
            proof.unlink(missing_ok=True)
            s31_prove = measured(str(prover), "prove", str(assignment_path), str(proof))
            words_match = re.search(r"public words: ([0-9 ]+)", s31_prove["stderr"])
            if not words_match or [int(v) for v in words_match.group(1).split()] != expected:
                raise AssertionError("S31 prover public words differ")
            stages = re.search(r"witness=([0-9.]+)s, setup=([0-9.]+)s, prove=([0-9.]+)s, total through verification=([0-9.]+)s", s31_prove["stderr"])
            if not stages:
                raise AssertionError(f"missing S31 stage timings: {s31_prove['stderr']}")
            s31_verify = measured(str(verifier), str(proof), str(statement), str(key), cwd=work_dir)
            s31_trials.append({
                "witness_seconds": float(stages.group(1)), "cold_setup_seconds": float(stages.group(2)),
                "prove_seconds": float(stages.group(3)), "prove_process_wall_seconds": s31_prove["wall_seconds"],
                "verify_wall_seconds": s31_verify["wall_seconds"], "proof_bytes": proof.stat().st_size,
                "proof_sha256": s31.file_hash(proof),
                "prover_max_resident_bytes": s31_prove["max_resident_bytes"],
                "verifier_max_resident_bytes": s31_verify["max_resident_bytes"],
            })
            cairo_input = work_dir / f"{name}.{trial}.cairo-input.json"
            cairo_input.unlink(missing_ok=True)
            witness = measured(str(adapter), "run", "--program", str(executable),
                               "--program-type", "executable", "--arguments", str(cairo_dir / "arguments.json"),
                               "--prover-input-out", str(cairo_input))
            cairo_proof = work_dir / f"{name}.{trial}.cairo-proof.json"
            cairo_report = work_dir / f"{name}.{trial}.cairo-report.json"
            cairo_proof.unlink(missing_ok=True)
            cairo_report.unlink(missing_ok=True)
            cairo_process = measured(str(cairo_bin), "prove", "--prover-input", str(cairo_input),
                                     "--proof", str(cairo_proof), "--proof-format", "json",
                                     "--report-out", str(cairo_report), "--verify")
            report = json.loads(cairo_report.read_text())
            artifact = check_cairo_proof(cairo_proof, report, expected)
            cairo_trials.append({
                "witness_wall_seconds": witness["wall_seconds"],
                "input_and_assets_seconds": report["timing"]["input_and_assets_ns"] / 1e9,
                "prove_seconds": report["timing"]["prove_ns"] / 1e9,
                "verify_seconds": report["timing"]["verify_ns"] / 1e9,
                "prove_process_wall_seconds": cairo_process["wall_seconds"],
                "prover_peak_physical_bytes": report["prover_process_usage"]["lifetime_peak_physical_footprint_bytes"],
                "witness_max_resident_bytes": witness["max_resident_bytes"],
                **artifact,
            })
            print(f"{name} {trial + 1}/{args.trials}: S31={s31_trials[-1]['prove_seconds']:.3f}s Cairo={cairo_trials[-1]['prove_seconds']:.3f}s", flush=True)
        cases[name] = {
            "statement_words": expected, "cairo_vm_steps": vm_steps,
            "s31_program_sha256": s31.file_hash(source_path), "cairo_executable_sha256": s31.file_hash(executable),
            "s31_cost": cost, "cairo_profile": report["profile"],
            "s31_trials": s31_trials, "cairo_trials": cairo_trials,
            "median_s31_prove_seconds": median(s31_trials, "prove_seconds"),
            "median_cairo_prove_seconds": median(cairo_trials, "prove_seconds"),
            "cairo_to_s31_prove_ratio": median(cairo_trials, "prove_seconds") / median(s31_trials, "prove_seconds"),
        }
    summary = {
        "schema": "s31-cairo-mvp-release-benchmark-v1", "compiler_sha256": compiler,
        "machine": platform.platform(), "zig_version": s31.invoke("zig", "version").strip(),
        "scarb_version": s31.invoke("scarb", "--version").strip(),
        "cairo_adapter_sha256": s31.file_hash(adapter), "cairo_prover_sha256": s31.file_hash(cairo_bin),
        "fri_visible_settings": FRI, "trials": args.trials, "cases": cases,
        "comparison_limit": "Proof protocols, encodings, verifier paths and preprocessing policies differ. Cairo VM witness and S31 circuit witness are separately timed; PoW is stochastic.",
    }
    output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(output)


if __name__ == "__main__":
    main()
