#!/usr/bin/env python3
"""Qualify all four SN PIE CUDA proofs with the pinned official Rust verifier."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

CAIRO_REVISION = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78"
STWO_REVISION = "7b211edde786775016ef3eecb837a6240d8fe792"
SECURITY = {"query_count": 70, "query_pow_bits": 26, "interaction_pow_bits": 24,
            "log_blowup_factor": 1, "fri_fold_step": 1,
            "log_last_layer_degree_bound": 0, "channel_salt": 0}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def check_receipts(backend: dict, oracle: dict, proof: Path, *, input_sha256: str,
                   executable_sha256: str) -> dict:
    trials = backend.get("completed_trials", [])
    if backend.get("schema") != "stwo-zig-cairo-cuda-canonical-receipt-v2" or len(trials) != 1:
        raise ValueError("missing canonical CUDA backend receipt")
    trial = trials[0]
    if bytes(trial["input_sha256"]).hex() != input_sha256 or \
            bytes(trial["executable_sha256"]).hex() != executable_sha256:
        raise ValueError("benchmark input/executable identity mismatch")
    verdict = trial["verdict"]
    if verdict.get("provider") != "nvidia_cuda" or any(
            verdict["counters"].get(key) != 0
            for key in ("cpu_fallback_attempts", "cpu_fallbacks_completed")):
        raise ValueError("benchmark lacks NVIDIA residency evidence")
    for key, expected in SECURITY.items():
        if trial["protocol"].get(key) != expected:
            raise ValueError(f"security mismatch: {key}")
    if "fri_lifting_log_size" not in trial["protocol"] or trial["protocol"]["fri_lifting_log_size"] is not None:
        raise ValueError("unexpected FRI lifting policy")
    if trial["protocol"].get("preprocessed_variant") != "canonical":
        raise ValueError("unexpected preprocessing profile")
    digest = sha(proof)
    recorded_digest = bytes(trial["proof_sha256"]).hex()
    if recorded_digest != digest or trial.get("proof_bytes") != proof.stat().st_size:
        raise ValueError("CUDA proof publication identity mismatch")
    if oracle.get("schema_version") != 1 or oracle.get("channel") != "blake2s" or \
            oracle.get("proof_format") != "json" or oracle.get("error") is not None or \
            oracle.get("verified") is not True or oracle.get("proof_sha256") != digest or \
            oracle.get("stwo_cairo_revision") != CAIRO_REVISION or \
            oracle.get("stwo_revision") != STWO_REVISION:
        raise ValueError("pinned official Rust verifier did not accept the emitted proof")
    return trial


class Memory(ctypes.Structure):
    _fields_ = [("total", ctypes.c_ulonglong), ("free", ctypes.c_ulonglong),
                ("used", ctypes.c_ulonglong)]


def run_trial(args: argparse.Namespace, number: int, trial: int, nvml, device) -> dict:
    out = args.out / f"sn-pie-{number}-trial-{trial}"
    out.mkdir()
    proof, report, verification = out / "proof.json", out / "backend.json", out / "verification.json"
    source = args.input_dir / f"sn-pie-{number}.cpi"
    command = [str(args.prover), "prove", "--backend", "cuda", "--input", str(source),
               "--output", str(proof), "--report-out", str(report), "--repeat", "1"]
    env = dict(os.environ, STWO_CAIRO_CUDA_ARTIFACT_DIR=str(args.artifact_dir),
               STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS=str(args.preprocessed),
               STWO_CAIRO_CUDA_PREPROCESSED_VARIANT="canonical")
    input_digest = sha(source)
    peak = 0
    sample_errors = 0
    sample_count = 0
    done = threading.Event()

    def sample() -> None:
        nonlocal peak, sample_errors, sample_count
        while not done.is_set():
            memory = Memory()
            if nvml.nvmlDeviceGetMemoryInfo(device, ctypes.byref(memory)) == 0:
                peak = max(peak, memory.used)
                sample_count += 1
            else:
                sample_errors += 1
            done.wait(0.01)

    sampler = threading.Thread(target=sample)
    sampler.start()
    started = time.monotonic_ns()
    process = None
    usage = None
    process_error = None
    timed_out = threading.Event()
    def expire() -> None:
        timed_out.set()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        with (out / "prover.log").open("xb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       env=env, start_new_session=True)
            killer = threading.Timer(args.timeout, expire)
            killer.start()
            try:
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
            finally:
                killer.cancel()
    except OSError as error:
        process_error = str(error)
    finally:
        wall_ns = time.monotonic_ns() - started
        done.set()
        sampler.join()
    result = {"benchmark": f"SN PIE {number}", "trial": trial,
              "status": "unverified", "prover_exit_code": process.returncode if process else None,
              "adapted_input_sha256": input_digest, "process_wall_ns": wall_ns,
              "timed_out": timed_out.is_set(), "process_error": process_error,
              "host_peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024) if usage else None,
              "highest_sampled_device_used_bytes": peak, "nvml_sample_errors": sample_errors,
              "nvml_sample_count": sample_count,
              "gpu_memory_measurement_valid": sample_count > 0 and sample_errors == 0,
              "gpu_memory_scope": "whole device, sampled every 10 ms; lower bound on peak"}
    if process_error is not None or process.returncode != 0:
        (out / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    try:
        verify = subprocess.run([str(args.verifier), "verify", "--proof", str(proof),
                                 "--channel", "blake2s", "--proof-format", "json", "--result", str(verification)],
                                capture_output=True, text=True, timeout=60)
        (out / "verifier.log").write_text(verify.stdout + verify.stderr)
        result["verifier_exit_code"] = verify.returncode
        if verify.returncode != 0:
            raise ValueError("official verification failed")
        backend = json.loads(report.read_text())
        oracle = json.loads(verification.read_text())
        accepted = check_receipts(backend, oracle, proof, input_sha256=input_digest,
                                  executable_sha256=sha(args.prover))
        result.update(status="verified", proof_sha256=sha(proof), backend_trial=accepted,
                      official_verification=oracle)
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as error:
        result["qualification_error"] = str(error)
    (out / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("prover", "verifier", "input-dir", "artifact-dir", "preprocessed", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if args.trials < 1 or args.trials > 8 or args.timeout < 1:
        parser.error("trials must be 1..8 and timeout positive")
    for name in ("prover", "verifier", "input_dir", "artifact_dir", "preprocessed", "out"):
        setattr(args, name, getattr(args, name).resolve())
    for number in range(1, 5):
        if not (args.input_dir / f"sn-pie-{number}.cpi").is_file():
            parser.error(f"missing SN PIE {number} input")
    gpu = subprocess.check_output(["nvidia-smi", "--query-gpu=name,uuid,memory.total,driver_version",
                                   "--format=csv,noheader,nounits"], text=True).strip().splitlines()
    if len(gpu) != 1:
        parser.error("qualification requires exactly one visible NVIDIA GPU")
    args.out.mkdir(parents=True, exist_ok=False)
    nvml = ctypes.CDLL("libnvidia-ml.so.1")
    if nvml.nvmlInit_v2() != 0:
        raise RuntimeError("NVML initialization failed")
    device = ctypes.c_void_p()
    if nvml.nvmlDeviceGetHandleByIndex_v2(0, ctypes.byref(device)) != 0:
        nvml.nvmlShutdown()
        raise RuntimeError("NVML device admission failed")
    suite = {"schema": "stwo-zig-cairo-cuda-sn-pie-suite-v1", "gpu": gpu[0],
             "prover_sha256": sha(args.prover), "verifier_sha256": sha(args.verifier),
             "preprocessed_sha256": sha(args.preprocessed), "security": SECURITY,
             "preprocessed_variant": "canonical", "results": [], "full_suite_verified": False,
             "timing_scope": "adapted input through proof JSON; proving excludes ingress and verification; PIE execution and queueing excluded"}
    try:
        for number in range(1, 5):
            for trial in range(1, args.trials + 1):
                result = run_trial(args, number, trial, nvml, device)
                suite["results"].append(result)
                (args.out / "suite.json").write_text(json.dumps(suite, indent=2) + "\n")
                print(f"SN PIE {number} trial {trial}: {result['status']}", flush=True)
                if result["status"] != "verified":
                    return 1
        suite["full_suite_verified"] = True
        (args.out / "suite.json").write_text(json.dumps(suite, indent=2) + "\n")
        return 0
    finally:
        nvml.nvmlShutdown()


if __name__ == "__main__":
    sys.exit(main())
