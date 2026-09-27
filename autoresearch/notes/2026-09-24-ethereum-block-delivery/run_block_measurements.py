"""Record CPU block proof timing, memory and immutable workload identities.

The binary must be built separately. Building is deliberately outside the timed
interval. Only a successful, freshly verified root permits throughput reporting.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from zig_serial_build import build_lock


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def power_status():
    if platform.system() != "Darwin":
        return None
    return subprocess.run(
        ["pmset", "-g", "batt"], capture_output=True, text=True, check=False
    ).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-output", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=32768)
    parser.add_argument("--profile", choices=("canonical", "diagnostic"), default="canonical")
    parser.add_argument("--paired", action="store_true")
    parser.add_argument("--schedule", type=Path, help="JSON cycle budgets; copied into the measurement directory")
    args = parser.parse_args()
    if not 0 < args.limit <= 1 << 22:
        parser.error("--limit must be between 1 and 4194304")
    inputs = {name: getattr(args, name).resolve(strict=True) for name in
              ("binary", "elf", "input", "expected_output")}
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    schedule_source = args.schedule.resolve(strict=True) if args.schedule else None
    if schedule_source:
        inputs["schedule"] = output / "segment-schedule.json"
    report_path = output / "proof-report.json"
    proof_path = output / "root.proof"
    log_path = output / "run.log"
    time_args = ["/usr/bin/time", "-l" if platform.system() == "Darwin" else "-v"]
    command = [*time_args, *(str(inputs[name]) for name in ("binary", "elf", "input", "expected_output")), str(args.limit),
               str(proof_path), str(report_path), args.profile]
    if args.paired:
        command.append("paired")
    if schedule_source:
        command.append("schedule=" + str(inputs["schedule"]))
    record = {
        "schema": "stwo.cpu-block-measurements.v1",
        "command": command,
        "hardware": {"platform": platform.platform(), "machine": platform.machine(),
                     "logical_cpus": os.cpu_count()},
        "complete_execution_proof_verified": False,
    }
    with build_lock(label="ethereum-block-measurements"):
        if schedule_source:
            with inputs["schedule"].open("xb") as copied:
                copied.write(schedule_source.read_bytes())
        # A queued build may replace the executable before this lock is acquired.
        record["inputs"] = {name: {"path": str(path), "sha256": digest(path)}
                            for name, path in inputs.items()}
        record["power_before"] = power_status()
        start = time.monotonic_ns()
        with log_path.open("x") as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        record["process_wall_ns"] = time.monotonic_ns() - start
        record["exit_code"] = result.returncode
        record["power_after"] = power_status()
    log_text = log_path.read_text()
    if platform.system() == "Darwin":
        for label, key in (("maximum resident set size", "peak_rss_bytes"),
                           ("peak memory footprint", "peak_physical_footprint_bytes")):
            match = re.search(r"^\s*(\d+)\s+" + label + r"\s*$", log_text, re.MULTILINE)
            if match:
                record[key] = int(match[1])
    else:
        match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", log_text)
        if match:
            record["peak_rss_bytes"] = int(match[1]) * 1024
    try:
        if result.returncode:
            raise RuntimeError(f"prover exited with {result.returncode}; see run.log")
        report = json.loads(report_path.read_text())
        if report.get("complete_execution_proof_verified") is not True:
            raise ValueError("report does not establish a verified execution root")
        for field, source in (("elf_sha256", "elf"), ("input_sha256", "input"),
                              ("output_sha256", "expected_output")):
            if report[field] != record["inputs"][source]["sha256"]:
                raise ValueError(f"{field} differs from the timed invocation")
        if report["proof_sha256"] != digest(proof_path):
            raise ValueError("root artifact hash differs from the report")
        expected_security = (70, 26) if args.profile == "canonical" else (8, 0)
        if (report["queries"], report["pow_bits"]) != expected_security:
            raise ValueError("reported security differs from the requested profile")
        if bool(report.get("explicit_segment_schedule", False)) != bool(schedule_source):
            raise ValueError("reported scheduling mode differs from the invocation")
        if schedule_source:
            if digest(inputs["schedule"]) != record["inputs"]["schedule"]["sha256"]:
                raise ValueError("schedule snapshot changed during proving")
            budgets = json.loads(inputs["schedule"].read_text())
            if len(budgets) != report["segments"] or sum(budgets) != report["cycles"]:
                raise ValueError("reported coverage differs from the pinned schedule")
        total = report["total_ns"]
        stages = report["stage_ns"]
        if total <= 0 or any(value < 0 for value in stages.values()) or sum(stages.values()) > total:
            raise ValueError("invalid or overlapping stage timing")
        record.update({
            "complete_execution_proof_verified": True,
            "prover_pipeline_ns": total,
            "stage_ns": stages,
            "unclassified_pipeline_ns": total - sum(stages.values()),
            "peak_tracked_bytes": report["peak_bytes"],
            "proof_bytes": proof_path.stat().st_size,
            "cycles": report["cycles"],
            "segments": report["segments"],
            "explicit_segment_schedule": bool(schedule_source),
            "queries": report["queries"],
            "pow_bits": report["pow_bits"],
            "process_cycles_per_second": report["cycles"] * 1e9 / record["process_wall_ns"],
        })
    except Exception as exc:
        record["measurement_error"] = str(exc)
        raise
    finally:
        (output / "measurement.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
