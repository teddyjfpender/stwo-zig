#!/usr/bin/env python3
"""Run a sequential, exact-proof CUDA sample against an authenticated CPI manifest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def digest(path: Path) -> str:
    hash_state = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            hash_state.update(block)
    return hash_state.hexdigest()


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    common_env = {
        "LD_LIBRARY_PATH": "/usr/local/cuda-13.0/targets/x86_64-linux/lib",
        "STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS": "/tmp/stwo-cuda-challenge/.cache/preprocessed-canonical.bin",
        "STWO_CAIRO_CUDA_ARTIFACT_DIR": "/tmp/stwo-cuda-challenge/.cache/cuda-artifacts",
        "STWO_CAIRO_CUDA_PREPROCESSED_VARIANT": "canonical",
        "STWO_CUDA_MEMORY_PHASES": "1",
    }
    for row in json.loads(args.manifest.read_text())[:args.limit]:
        name = row["pie"]
        target = args.out / name
        target.mkdir(exist_ok=True)
        result_path = target / "result.json"
        if result_path.exists() and json.loads(result_path.read_text()).get("status") == "verified":
            print(name, "already verified", flush=True)
            continue
        source = args.inputs / (name + ".cpi")
        if digest(source) != row["input_sha256"]:
            raise ValueError(f"{name}: adapted input hash differs")
        # The compact profile intentionally rejects arenas above 38 GiB.
        # Larger campaign inputs use the verified managed-capacity baseline
        # until a bounded working-set implementation can replace it.
        policy = ({"STWO_CUDA_COMPACT_DEVICE_PROFILE": "1"}
                  if row["steps"] <= 5_340_000 else
                  {"STWO_CUDA_MANAGED_ARENA": "1", "STWO_CUDA_MANAGED_PLACEMENT": "capacity"})
        proof_env = env.copy()
        proof_env.update(common_env)
        for key in ("STWO_CUDA_COMPACT_DEVICE_PROFILE", "STWO_CUDA_MANAGED_ARENA", "STWO_CUDA_MANAGED_PLACEMENT"):
            proof_env.pop(key, None)
        proof_env.update(policy)
        proof = target / "proof.json"
        command = [sys.executable, str(args.source / "scripts/cairo_cuda_memory_trial.py"),
                   "--out", str(target), "--", str(args.source / "zig-out/bin/stwo-cairo-cuda"),
                   "prove", "--backend", "cuda", "--input", str(source),
                   "--input-sha256", row["input_sha256"], "--output", str(proof),
                   "--report-out", str(target / "report.json")]
        with (target / "driver.log").open("w") as output:
            outcome = subprocess.run(command, cwd=args.source, env=proof_env, stdout=output,
                                     stderr=subprocess.STDOUT, timeout=1800, check=False)
        result = {"pie": name, "steps": row["steps"],
                  "h200_ingress_s": row.get("h200_ingress_s"),
                  "h200_cairo_prove_s": row.get("h200_cairo_prove_s"),
                  "h200_wrap_s": row.get("h200_wrap_s"),
                  "expected_proof_sha256": row.get("expected_proof_sha256"),
                  "input_sha256": row["input_sha256"], "policy_env": policy,
                  "exit_code": outcome.returncode}
        if outcome.returncode == 0 and proof.exists():
            result["proof_sha256"] = digest(proof)
            if row.get("expected_proof_sha256") is None or result["proof_sha256"] == row["expected_proof_sha256"]:
                verdict = target / "official-verdict.json"
                verify = subprocess.run([str(args.verifier), "verify", "--proof", str(proof),
                                         "--channel", "blake2s", "--proof-format", "json",
                                         "--result", str(verdict)], stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE, timeout=300, check=False)
                result["verifier_exit_code"] = verify.returncode
                if verify.returncode == 0 and json.loads(verdict.read_text()).get("verified"):
                    result["status"] = "verified"
                    result["proof_hash_matches_reference"] = (
                        True if row.get("expected_proof_sha256") is not None else None)
                    summary = json.loads((target / "summary.json").read_text())
                    trial = json.loads((target / "report.json").read_text())["completed_trials"][0]
                    result.update({
                        "full_command_s": summary["elapsed_ns"] / 1e9,
                        "publication_s": trial["adapted_input_until_publication_ns"] / 1e9,
                        "ingress_s": trial["ingress_ns"] / 1e9,
                        "proof_s": trial["proof_execute_and_decode_ns"] / 1e9,
                        "device_peak_bytes": summary["whole_device_peak_bytes"],
                        "host_rss_peak_bytes": summary["process_rss_peak_bytes"],
                    })
                else:
                    result["status"] = "verifier_failed"
                    result["verifier_error"] = verify.stderr.decode(errors="replace")[-500:]
            else:
                result["status"] = "proof_hash_mismatch"
        else:
            result["status"] = "proof_failed"
        write_json(result_path, result)
        print(name, result["status"], result.get("publication_s"), flush=True)


if __name__ == "__main__":
    main()
