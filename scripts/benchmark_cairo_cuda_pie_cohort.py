#!/usr/bin/env python3
"""Benchmark arbitrary adapted Starknet PIEs with the qualified CUDA prover.

Runs one PIE at a time, retains prover receipts, and records both
adapted-input-to-publication latency and whole-process/device peaks. Adaptation
and PIE generation are separate stages, not part of the proof timing.
"""

import argparse
import csv
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

import benchmark_cairo_cuda as baseline


FIELDS = ("pie", "os_steps", "n_memory_holes", "archive_bytes", "cpi_bytes",
          "status", "ingress_s", "proof_execute_finish_s", "adapted_to_publication_s",
          "process_wall_s", "host_peak_rss_bytes",
          "gpu_peak_used_bytes", "planned_arena_bytes", "peak_live_bytes", "proof_bytes",
          "proof_sha256", "error")


def run_without_verifier(args: argparse.Namespace, nvml, device) -> dict:
    """Run a canonical proof; the official verifier is run after export."""
    proof = args.out / "proof.json"
    report = args.out / "backend.json"
    source = args.input_dir / "sn-pie-1.cpi"
    env = dict(os.environ, STWO_CAIRO_CUDA_ARTIFACT_DIR=str(args.artifact_dir),
               STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS=str(args.preprocessed),
               STWO_CAIRO_CUDA_PREPROCESSED_VARIANT="canonical")
    command = [str(args.prover), "prove", "--backend", "cuda", "--input", str(source),
               "--output", str(proof), "--report-out", str(report), "--repeat", "1"]
    peak = 0
    done = threading.Event()

    def sample() -> None:
        nonlocal peak
        while not done.is_set():
            memory = baseline.Memory()
            if nvml.nvmlDeviceGetMemoryInfo(device, ctypes.byref(memory)) == 0:
                peak = max(peak, memory.used)
            done.wait(0.01)

    monitor = threading.Thread(target=sample, daemon=True)
    monitor.start()
    started = time.monotonic_ns()
    process = None
    timed_out = threading.Event()
    usage = None
    try:
        with (args.out / "prover.log").open("w") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       env=env, start_new_session=True)

            def expire() -> None:
                timed_out.set()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

            timer = threading.Timer(args.timeout, expire)
            timer.start()
            try:
                _, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
            finally:
                timer.cancel()
    finally:
        done.set()
        monitor.join()
    receipt = {"status": "failed", "process_wall_ns": time.monotonic_ns() - started,
               "host_peak_rss_bytes": usage.ru_maxrss * 1024 if usage else None,
               "highest_sampled_device_used_bytes": peak,
               "prover_exit_code": process.returncode if process else None,
               "timed_out": timed_out.is_set()}
    if process is not None and process.returncode == 0 and proof.is_file() and report.is_file():
        try:
            backend = json.loads(report.read_text())
            trials = backend["completed_trials"]
            if backend.get("schema") != "stwo-zig-cairo-cuda-canonical-receipt-v2" or len(trials) != 1:
                raise ValueError("missing canonical backend receipt")
            trial = trials[0]
            verdict = trial["verdict"]
            counters = verdict["counters"]
            if (bytes(trial["input_sha256"]).hex() != baseline.sha(source) or
                    bytes(trial["executable_sha256"]).hex() != baseline.sha(args.prover) or
                    verdict["provider"] != "nvidia_cuda" or
                    counters["cpu_fallback_attempts"] != 0 or
                    counters["cpu_fallbacks_completed"] != 0 or
                    any(trial["protocol"].get(key) != value for key, value in baseline.SECURITY.items()) or
                    trial["protocol"].get("preprocessed_variant") != "canonical" or
                    bytes(trial["proof_sha256"]).hex() != baseline.sha(proof) or
                    trial["proof_bytes"] != proof.stat().st_size):
                raise ValueError("backend identity, residency, security, or proof digest mismatch")
            receipt.update(status="proof_generated", backend_trial=trial,
                           proof_sha256=baseline.sha(proof))
        except (KeyError, TypeError, ValueError) as error:
            receipt["qualification_error"] = str(error)
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def result_row(name: str, meta: dict, source: Path, receipt: dict) -> dict:
    result = {
        "pie": name, "os_steps": meta["os_steps"], "n_memory_holes": meta.get("n_memory_holes"),
        "archive_bytes": meta.get("bytes"), "cpi_bytes": source.stat().st_size,
        "status": receipt["status"], "process_wall_s": round(receipt["process_wall_ns"] / 1e9, 3),
        "host_peak_rss_bytes": receipt["host_peak_rss_bytes"],
        "gpu_peak_used_bytes": receipt["highest_sampled_device_used_bytes"],
    }
    if receipt["status"] in {"verified", "proof_generated"}:
        trial = receipt["backend_trial"]
        counters = trial["verdict"]["counters"]
        result.update(ingress_s=round(trial["ingress_ns"] / 1e9, 3),
                      proof_execute_finish_s=round(trial["proof_execute_and_decode_ns"] / 1e9, 3),
                      adapted_to_publication_s=round(trial["adapted_input_until_publication_ns"] / 1e9, 3),
                      planned_arena_bytes=trial["planned_arena_bytes"],
                      peak_live_bytes=counters["peak_live_bytes"],
                      proof_bytes=trial["proof_bytes"], proof_sha256=receipt["proof_sha256"])
    else:
        result["error"] = receipt.get("qualification_error") or receipt.get("process_error") or (
            f"prover exit {receipt.get('prover_exit_code')}, timeout={receipt.get('timed_out')}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "input-dir", "prover", "artifact-dir", "preprocessed", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, help="pinned official verifier; otherwise verify exported proofs later")
    parser.add_argument("--max-steps", type=int)
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(args.manifest.read_text())
    suite_path = args.out / "pie-proving.csv"
    prior = {}
    if suite_path.exists():
        with suite_path.open(newline="") as source:
            prior = {row["pie"]: row for row in csv.DictReader(source)}
    gpu = subprocess.check_output(["nvidia-smi", "--query-gpu=name,uuid,memory.total,driver_version",
                                   "--format=csv,noheader,nounits"], text=True).strip().splitlines()
    if len(gpu) != 1:
        parser.error("exactly one NVIDIA GPU must be visible")
    (args.out / "machine.json").write_text(json.dumps({"gpu": gpu[0],
                                                         "security": baseline.SECURITY,
                                                         "prover_sha256": baseline.sha(args.prover),
                                                         "verifier_sha256": baseline.sha(args.verifier)
                                                         if args.verifier else None}, indent=2) + "\n")
    nvml = ctypes.CDLL("libnvidia-ml.so.1")
    if nvml.nvmlInit_v2() != 0:
        raise RuntimeError("NVML initialization failed")
    device = ctypes.c_void_p()
    if nvml.nvmlDeviceGetHandleByIndex_v2(0, ctypes.byref(device)) != 0:
        raise RuntimeError("NVML could not open device 0")
    rows = []
    try:
        for item in manifest["rows"]:
            name, meta = item["pie"], item["meta"]
            if args.max_steps and meta["os_steps"] > args.max_steps:
                continue
            source = args.input_dir / f"{name}.cpi"
            if name in prior:
                rows.append(prior[name])
                continue
            if not source.is_file():
                print(f"{name}: adapted input unavailable", flush=True)
                continue
            work = args.out / name
            work.mkdir(exist_ok=True)
            (work / "inputs").mkdir(exist_ok=True)
            link = work / "inputs/sn-pie-1.cpi"
            if not link.exists():
                os.link(source, link)
            trial_args = argparse.Namespace(prover=args.prover.resolve(),
                                            verifier=args.verifier.resolve() if args.verifier else None,
                                            input_dir=link.parent, artifact_dir=args.artifact_dir.resolve(),
                                            preprocessed=args.preprocessed.resolve(), out=work,
                                            timeout=args.timeout)
            if args.verifier:
                receipt = baseline.run_trial(trial_args, 1, 1, nvml, device)
            else:
                trial_args.out = work / "sn-pie-1-trial-1"
                trial_args.out.mkdir()
                receipt = run_without_verifier(trial_args, nvml, device)
            if receipt["status"] == "failed":
                log = trial_args.out / "prover.log"
                if log.exists():
                    errors = [line.strip() for line in log.read_text(errors="replace").splitlines()
                              if "failed:" in line or line.startswith("error:")]
                    if errors:
                        receipt["process_error"] = "; ".join(errors[-2:])
            row = result_row(name, meta, source, receipt)
            rows.append(row)
            write_csv(suite_path, rows)
            print(f"{name}: {row['status']} publication={row.get('adapted_to_publication_s')}s "
                  f"GPU={row.get('gpu_peak_used_bytes')}", flush=True)
    finally:
        nvml.nvmlShutdown()
    write_csv(suite_path, rows)


if __name__ == "__main__":
    main()
