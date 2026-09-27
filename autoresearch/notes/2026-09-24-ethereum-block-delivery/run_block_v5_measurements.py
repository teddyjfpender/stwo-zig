"""Isolated canonical block-v5 production plus fresh-process verification.

Build executables first. The producer uses a create-only bundle directory;
compilation is excluded from every reported runtime and process RSS sample.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import stat
import time

CAPACITY_ARCHITECTURE = "block-v5-native-capacity-v1-fused-capacity-v1-open-exact-streaming"


def require_capacity_report(report, *, producer):
    """Bind this measurement to the installed typed stack, before acceptance."""
    if report.get("format_version") != 2 or report.get("architecture") != CAPACITY_ARCHITECTURE:
        raise RuntimeError("binary did not report the canonical capacity architecture")
    if report.get("complete_block_verified") is not True:
        raise RuntimeError("binary did not return complete verification")
    if producer:
        if (report.get("queries") != 70 or report.get("pow_bits") != 26 or
                report.get("profile") != "csp_q70_pow26" or
                report.get("native_capacity_protocol_version") != 1 or
                report.get("native_projection_protocol_version") != 1):
            raise RuntimeError("producer did not return canonical capacity security/protocols")
    elif report.get("fresh_process") is not True:
        raise RuntimeError("complete receiver did not run in a fresh process")


def identity(path):
    path = Path(path).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest()}


def execute(command, stdout_path, log_path):
    started = time.monotonic_ns()
    with stdout_path.open("wb") as machine_output, log_path.open("wb") as diagnostics:
        completed = subprocess.run(command, stdout=machine_output, stderr=diagnostics)
    return completed.returncode, time.monotonic_ns() - started


def time_resources(log_path):
    """Read time's process metrics even when no successful JSON report exists."""
    if not log_path.is_file():
        return None
    raw = log_path.read_text(errors="replace")
    resources = {"log": log_path.name,
                 "scope": "External /usr/bin/time process metrics; compilation excluded. Metrics do not imply proof success."}
    rss = re.search(r"^\s*(\d+)\s+maximum resident set size\s*$", raw, re.MULTILINE)
    if rss:
        resources.update(peak_rss_bytes=int(rss[1]), source_format="Darwin time -l; RSS in bytes")
    else:
        rss = re.search(r"^\s*Maximum resident set size \(kbytes\):\s*(\d+)\s*$", raw, re.MULTILINE)
        if rss:
            resources.update(peak_rss_bytes=int(rss[1]) * 1024, source_format="GNU time -v; RSS converted from KiB")
    wall = re.search(r"^\s*(\d+(?:\.\d+)?)\s+real\b", raw, re.MULTILINE)
    if wall:
        resources["time_log_real_seconds"] = float(wall[1])
    else:
        wall = re.search(r"^\s*Elapsed \(wall clock\) time \(h:mm:ss or m:ss\):\s*(\d+(?::\d+){0,2}(?:\.\d+)?)\s*$", raw, re.MULTILINE)
        if wall:
            parts = wall[1].split(":")
            if 1 <= len(parts) <= 3:
                seconds = 0.0
                for part in parts:
                    seconds = seconds * 60 + float(part)
                resources["time_log_real_seconds"] = seconds
    return resources


def inventory(bundle):
    """Completion-time sizes, not peak disk use or proof authority."""
    source_files = {"v5-input-words.bin", "v5-initial-rw.bin", "v5-first-touches.bin", "v5-rw-endpoints.bin"}
    categories = {name: {"files": 0, "bytes": 0} for name in (
        "base_proofs", "recursive_proofs", "public_source_files", "other_staged_files", "all_regular_files_excluding_report"
    )}
    for path in bundle.rglob("*"):
        attributes = path.lstat()
        if not stat.S_ISREG(attributes.st_mode) or path.name == "block-v5-cpu-report.json":
            continue
        if path.suffix == ".proof":
            category = "recursive_proofs" if path.name.startswith("block-v5-open-") else "base_proofs"
        elif path.name in source_files:
            category = "public_source_files"
        else:
            category = "other_staged_files"
        for name in (category, "all_regular_files_excluding_report"):
            categories[name]["files"] += 1
            categories[name]["bytes"] += attributes.st_size
    categories["scope"] = "Regular files present after successful production, excluding producer report; includes source/policy/manifests and remaining staging files. This is not peak disk usage."
    return categories


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--segment-cycles", type=int, default=262144)
    parser.add_argument("--job-id", help="32-byte hexadecimal public job identity")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    pins = {name: identity(getattr(args, name)) for name in ("producer", "verifier", "elf", "input", "oracle")}
    job_id = args.job_id or hashlib.sha256(
        b"stwo-zig/block-v5/measurement-job/v1\0" + b"".join(bytes.fromhex(pins[name]["sha256"]) for name in ("elf", "input", "oracle"))
    ).hexdigest()
    try:
        job_bytes = bytes.fromhex(job_id)
    except ValueError:
        parser.error("--job-id must be 64 hexadecimal digits")
    if len(job_id) != 64 or len(job_bytes) != 32:
        parser.error("--job-id must be 64 hexadecimal digits")
    job_id = job_bytes.hex()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    bundle = output / "bundle"
    timed = ["/usr/bin/time", "-l"] if platform.system() == "Darwin" else ["/usr/bin/time", "-v"]
    producer = timed + [pins["producer"]["path"], pins["elf"]["path"], pins["input"]["path"],
                        pins["oracle"]["path"], str(args.segment_cycles), job_id, str(bundle)]
    measurement = {"schema": "stwo.cpu-block-v5-measurements.v1", "inputs": pins,
                   "hardware": {"platform": platform.platform(), "logical_cpus": os.cpu_count()},
                   "job_id": job_id, "producer_command": producer, "phase": "producing",
                   "complete_block_verified": False, "build_included": False,
                   "machine_outputs": {"producer": "producer.stdout.json", "verifier": "verifier.stdout.json"},
                   "diagnostics_and_time_logs": {"producer": "producer.log", "verifier": "verifier.log"},
                   "policy_scope": "Fresh-process verification of separately pinned producer-generated policy. These measurements do not independently admit an Ethereum block or external public-state policy."}
    manifest = output / "measurement.json"

    def publish():
        manifest.write_text(json.dumps(measurement, indent=2) + "\n")

    publish()
    try:
        code, elapsed = execute(producer, output / "producer.stdout.json", output / "producer.log")
        measurement.update(producer_exit_code=code, producer_process_wall_ns=elapsed)
        if code:
            raise RuntimeError(f"producer exited with {code}; see producer.log")
        report = json.loads((output / "producer.stdout.json").read_text())
        persisted_report = json.loads((bundle / "block-v5-cpu-report.json").read_text())
        if report != persisted_report:
            raise RuntimeError("producer stdout and persisted reports differ")
        measurement["producer_report"] = report
        require_capacity_report(report, producer=True)
        if report["job_id"] != job_id:
            raise RuntimeError("producer public job identity changed")
        measurement["producer_optimization"] = report.get("optimization_mode", report.get("build_mode", report.get("optimization")))
        measurement["optimization_scope"] = "Actual producer build mode when reported; otherwise unknown. Binary hash is recorded; ReleaseFast is not inferred."
        measurement["base_proof_files"] = report["proof_files"]
        measurement["base_proof_file_bytes"] = report["proof_file_bytes"]
        measurement["base_proof_scope"] = "Store base STARK artifacts only; excludes native recursive leaves, forest parents, outer proof and source/policy/manifest files."
        measurement["bundle_file_inventory"] = inventory(bundle)
        actual_base = measurement["bundle_file_inventory"]["base_proofs"]
        if actual_base["files"] != report["proof_files"] or actual_base["bytes"] != report["proof_file_bytes"]:
            raise RuntimeError("producer base-proof report disagrees with bundle files")
        for name, field in (("elf", "elf_sha256"), ("input", "input_sha256"), ("oracle", "oracle_sha256")):
            if report[field] != pins[name]["sha256"]:
                raise RuntimeError(f"producer {name} identity changed")
        verifier = timed + [pins["verifier"]["path"]] + [report[field] for field in (
            "receiver_policy_sha256", "bundle_manifest_sha256", "forest_manifest_sha256", "job_id",
            "source_image_digest", "program_root", "initial_rw_root", "final_rw_root"
        )] + [pins["input"]["path"], str(bundle)]
        measurement.update(phase="fresh_verification", verifier_command=verifier)
        publish()
        code, elapsed = execute(verifier, output / "verifier.stdout.json", output / "verifier.log")
        measurement.update(verifier_exit_code=code, verifier_process_wall_ns=elapsed)
        if code:
            raise RuntimeError(f"fresh verifier exited with {code}; see verifier.log")
        verification = json.loads((output / "verifier.stdout.json").read_text())
        measurement["fresh_verifier_report"] = verification
        require_capacity_report(verification, producer=False)
        if verification["verification"] != report["verification"]:
            raise RuntimeError("fresh verifier summary differs from producer verified public summary")
        for name, before in pins.items():
            if identity(before["path"])["sha256"] != before["sha256"]:
                raise RuntimeError(f"measured {name} file changed during the run")
        measurement.update(phase="complete", complete_block_verified=True)
    except Exception as error:
        measurement.update(phase="failed", error=str(error))
        raise
    finally:
        for process in ("producer", "verifier"):
            try:
                resources = time_resources(output / f"{process}.log")
            except OSError as error:
                measurement[f"{process}_resource_parse_error"] = str(error)
                continue
            if resources is not None:
                measurement[f"{process}_resources"] = resources
        publish()
    print(json.dumps(measurement, indent=2))


if __name__ == "__main__":
    main()
