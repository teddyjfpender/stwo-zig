#!/usr/bin/env python3
"""Measure complete OP trace capture with the production producer, never a proof.

Compare serial and checkpoint/replay schedules using the exact captured-value
digest. Geometry stays fixed; changing batch size creates a different experiment.
"""

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from opstack.process_metrics import peak_rss_bytes


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_capture(report, expected_steps, terminal_pc):
    if (
        report.get("security_qualified") is not False
        or report.get("capture_source") != "in_process_execution"
        or report.get("total_steps") != expected_steps
        or report.get("final_pc") != terminal_pc
    ):
        raise ValueError("capture did not cover the complete measured execution")
    digest = report.get("captured_values_sha256", "")
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("missing canonical captured-value digest")
    return digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--request", type=Path, required=True)
    p.add_argument("--execution", type=Path, required=True)
    p.add_argument("--runner", type=Path, required=True)
    p.add_argument("--resources", type=Path, required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--batch-steps", type=int, default=262143)
    p.add_argument("--workers", type=int, nargs="+", default=[0, 1, 2])
    p.add_argument("--timeout", type=int, default=600)
    args = p.parse_args()
    if not 1 <= args.batch_steps < 1 << 23 or not 1 <= args.timeout <= 3600:
        p.error("batch steps 1..2^23-1 and timeout 1..3600")
    if (
        not args.workers
        or len(set(args.workers)) != len(args.workers)
        or any(not 0 <= w <= 32 for w in args.workers)
    ):
        p.error("distinct execution worker counts 0..32")
    config = json.loads(args.request.read_text())
    execution = json.loads(args.execution.read_text())
    if (
        execution.get("status") != "completed"
        or execution.get("verified_output") is not True
    ):
        raise ValueError("requires a completed independently expected execution")
    if config["expected_output"] != execution["output"]:
        raise ValueError("request/execution output mismatch")
    for key in ("elf", "input"):
        if sha(config[key]) != config[key + "_sha256"]:
            raise ValueError(key + " identity mismatch")
    if config["terminal_pc"] != execution["pc"]:
        raise ValueError("terminal PC mismatch")
    resources = json.loads(args.resources.read_text())
    config.update(batch_steps=args.batch_steps, workers=max(1, max(args.workers)))
    # Prefix and batch caps must not silently turn the benchmark into a prefix.
    config.update(max_batches=0, max_steps=execution["instructions"] + 1)
    args.artifacts.mkdir(parents=True, exist_ok=False)
    request = args.artifacts / "request.json"
    request.write_text(json.dumps(config, indent=2) + "\n")
    results, reference = [], None
    environment = dict(os.environ)
    for workers in args.workers:
        limits = copy.deepcopy(resources)
        limits.setdefault("capture_options", {}).update(execution_workers=workers)
        path = args.artifacts / f"resources-{workers}.json"
        path.write_text(json.dumps(limits, indent=2) + "\n")
        command = [
            str(args.runner.resolve()),
            str(request.resolve()),
            "-",
            "0",
            str(path.resolve()),
        ]
        started = time.monotonic_ns()
        output_path = args.artifacts / f"workers-{workers}.json"
        with (
            (args.artifacts / f"workers-{workers}.stderr").open("w") as err,
            output_path.open("wb") as out,
        ):
            process = subprocess.Popen(command, stdout=out, stderr=err, env=environment)
            try:
                # wait4 returns this child's peak, unlike cumulative RUSAGE_CHILDREN.
                deadline = time.monotonic() + args.timeout
                while True:
                    pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                    if pid:
                        process.returncode = os.waitstatus_to_exitcode(status)
                        break
                    if time.monotonic() >= deadline:
                        process.kill()
                        process.wait()
                        raise TimeoutError("capture time budget exceeded")
                    time.sleep(0.05)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        wall = time.monotonic_ns() - started
        if process.returncode:
            raise ValueError(f"capture failed: {process.returncode}; see stderr")
        report = json.loads(output_path.read_bytes())
        digest = validate_capture(
            report, execution["instructions"], config["terminal_pc"]
        )
        if reference is not None and digest != reference:
            raise ValueError(
                "capture schedules produced different authenticated values"
            )
        reference = digest
        results.append(
            {
                "execution_workers": workers,
                "process_wall_ns": wall,
                "peak_rss_bytes": peak_rss_bytes(usage),
                "report": report,
            }
        )
        receipt = {
            "schema": "stwo.opstack.capture.v1",
            "proof_verified": False,
            "scope": "complete producer trace capture only; no proof or acceptance",
            "request_sha256": sha(request),
            "runner_sha256": sha(args.runner),
            "elf_sha256": config["elf_sha256"],
            "input_sha256": config["input_sha256"],
            "source_sha256": sha(__file__),
            "peak_rss_scope": "wait4 per child; measured high-water RSS, not a cap",
            "environment": {
                k: v for k, v in environment.items() if k.startswith("STWO_")
            },
            "results": results,
        }
        (args.artifacts / "summary.json").write_text(
            json.dumps(receipt, indent=2) + "\n"
        )
        print(
            f"workers={workers} complete capture matched; peak={peak_rss_bytes(usage)}",
            flush=True,
        )


if __name__ == "__main__":
    main()
