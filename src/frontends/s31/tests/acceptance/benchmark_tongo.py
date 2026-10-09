#!/usr/bin/env python3
"""Compare matched blinded payment packages; verify every measured proof.

Synthetic witnesses only. This is a native-verified performance diagnostic,
not evidence of zero knowledge, Rust interoperability or production security.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

S31 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31 / "python"))
import s31
from acceptance_proof_privacy import commitments

TIMES = re.compile(r"witness=([\d.]+)s, setup=([\d.]+)s, prove=([\d.]+)s, total through verification=([\d.]+)s")
STAGES = re.compile(r"CIRCUIT_STAGE 0 (\S+) ([\d.]+)s")


def bounded_int(low: int, high: int):
    def parse(value: str) -> int:
        n = int(value)
        if not low <= n <= high:
            raise argparse.ArgumentTypeError(f"expected {low}..{high}")
        return n
    return parse


def measured(args: list[object], env: dict[str, str]) -> tuple[float, int, str]:
    """One joined POSIX child; wait4 reports that child's peak RSS exactly."""
    if not hasattr(os, "wait4"):
        raise RuntimeError("this diagnostic requires POSIX wait4")
    with tempfile.TemporaryFile() as log:
        started = time.perf_counter()
        process = subprocess.Popen([str(x) for x in args], cwd=s31.ROOT,
                                   stdout=log, stderr=log, env=env)
        timeout = threading.Timer(300, process.kill)
        timeout.start()
        try:
            _, status, usage = os.wait4(process.pid, 0)
            elapsed = time.perf_counter() - started
            process.returncode = os.waitstatus_to_exitcode(status)
        except BaseException:
            process.kill()
            process.wait()
            raise
        finally:
            timeout.cancel()
            timeout.join()
        log.seek(0)
        output = log.read().decode(errors="replace")
    if process.returncode != 0:
        raise RuntimeError(f"command failed ({process.returncode}): {args}\n{output}")
    rss_kib = int(usage.ru_maxrss / 1024 if sys.platform == "darwin" else usage.ru_maxrss)
    return elapsed, rss_kib, output


def summary(rows: list[dict]) -> dict:
    return {key: {"median": statistics.median(row[key] for row in rows),
                  "min": min(row[key] for row in rows), "max": max(row[key] for row in rows)}
            for key in ("wall_s", "witness_s", "setup_s", "prove_s", "post_prove_s", "total_native_s",
                        "verify_s", "peak_rss_kib", "proof_bytes")}


def read_optional(path: str) -> str | None:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--assignment", type=Path,
                        default=S31 / "examples/payments/tongo_transfer.valid.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=bounded_int(2, 64), default=12)
    parser.add_argument("--warmups", type=bounded_int(1, 8), default=2)
    parser.add_argument("--workers", type=bounded_int(1, 32))
    parser.add_argument("--profile", action="store_true", help="extra untimed stage-profile proof per lane")
    args = parser.parse_args()
    packages = {"baseline": args.baseline.resolve(), "candidate": args.candidate.resolve()}
    manifests = {lane: s31.verify_package(path) for lane, path in packages.items()}
    keys = {lane: json.loads((path / "verification-key.json").read_text()) for lane, path in packages.items()}
    if keys["baseline"] != keys["candidate"]:
        raise ValueError("benchmark requires identical source-bound keys and security parameters")
    for lane, path in packages.items():
        if (keys[lane].get("profile") != "circuit-blinded-v1" or
                manifests[lane].get("lowering") != "gate" or
                keys[lane]["name"] != "tongo_transfer"):
            raise ValueError("benchmark requires the blinded gate payment profile")
        if ((path / "source.s31.json").read_bytes() !=
                (packages["baseline"] / "source.s31.json").read_bytes()):
            raise ValueError("benchmark sources differ")

    args.output = args.output.resolve()
    if args.output.exists():
        raise FileExistsError(f"benchmark report already exists: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    work = args.output.parent / f"{args.output.stem}-receipts"
    # Refuse an existing run instead of overwriting its evidence.
    work.mkdir()
    assignment = args.assignment.resolve()
    witness = json.loads(assignment.read_text())
    statement = work / "statement.json"
    s31.write_json(statement, {"public_inputs": witness["public_inputs"],
                               "public_outputs": witness["public_outputs"]})
    env = os.environ.copy()
    for name in ("STWO_CIRCUIT_STAGE_PROFILE", "STWO_ZIG_PCS_TIMING"):
        env.pop(name, None)
    if args.workers is not None:
        env["STWO_ZIG_WORKERS"] = str(args.workers)
        env["STWO_ZIG_POW_WORKERS"] = str(args.workers)
    rows, profiles = [], {}
    name = keys["candidate"]["name"]
    previous_trace: dict[str, bytes] = {}

    def sample(lane: str, index: int, warmup: bool, profiled: bool = False) -> dict:
        package = packages[lane]
        label = f"{lane}-{'profile' if profiled else index}"
        proof = work / f"{label}.proof"
        sample_env = {**env, **({"STWO_CIRCUIT_STAGE_PROFILE": "1"} if profiled else {})}
        wall, rss, log = measured([package / f"bin/s31-{name}-prover", "prove", assignment, proof], sample_env)
        times = TIMES.search(log)
        if times is None:
            raise ValueError("prover stage diagnostics missing")
        # Verify both directions against the original and changed binaries.
        verification = {}
        for verifier_lane, verifier_package in packages.items():
            elapsed, _, _ = measured([verifier_package / f"bin/s31-{name}-native-verifier",
                                      proof, statement, verifier_package / "verification-key.json"], env)
            verification[verifier_lane] = elapsed
        fixed, trace = commitments(proof.read_bytes())
        if fixed.hex() != keys[lane]["preprocessed_root"]:
            raise AssertionError("proof fixed commitment does not match the sealed key")
        if previous_trace.get(lane) == trace:
            raise AssertionError("repeated proof reused its trace commitment")
        previous_trace[lane] = trace
        row = {"lane": lane, "index": index, "warmup": warmup, "wall_s": wall,
               "peak_rss_kib": rss, "proof_bytes": proof.stat().st_size,
               "proof_sha256": s31.file_hash(proof), "verification": verification,
               "verify_s": verification[lane], "receipt": str(proof.relative_to(args.output.parent))}
        row.update(zip(("witness_s", "setup_s", "prove_s", "total_native_s"),
                       map(float, times.groups()), strict=True))
        # Derived interval includes serialization, self-verification, cleanup
        # and output inside the native timer; it is not verifier-only latency.
        row["post_prove_s"] = (row["total_native_s"] - row["witness_s"] -
                               row["setup_s"] - row["prove_s"])
        (work / f"{label}.log").write_text(log)
        if profiled:
            profiles[lane] = {"measurement": row, "stages": {key: float(value) for key, value in STAGES.findall(log)},
                              "intervals": {key: float(value) for key, value in
                                            re.findall(r"S31_PHASE (\S+) ([\d.]+)s", log)},
                              "log": str((work / f"{label}.log").relative_to(args.output.parent))}
        print(json.dumps({key: row[key] for key in ("lane", "index", "warmup", "wall_s", "peak_rss_kib")}), flush=True)
        return row

    for index in range(args.warmups + args.samples):
        order = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
        for lane in order:
            rows.append(sample(lane, index, index < args.warmups))
    if args.profile:
        for lane in packages:
            sample(lane, -1, False, True)
    cpuinfo = read_optional("/proc/cpuinfo") or ""
    cpu = next((line.split(":", 1)[1].strip() for line in cpuinfo.splitlines()
                if line.startswith("model name")), platform.processor())
    result = {"schema": "s31-blinded-payment-benchmark-v1", "assignment_sha256": s31.file_hash(assignment),
              "key_sha256": s31.file_hash(packages["candidate"] / "verification-key.json"),
              "key": keys["candidate"], "host": {"cpu": cpu, "platform": platform.platform(),
                  "cpu_quota": read_optional("/sys/fs/cgroup/cpu.max"),
                  "memory_limit": read_optional("/sys/fs/cgroup/memory.max"),
                  "logical_cpus": os.cpu_count(), "affinity_cpus": len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None},
              "workers": {key: env.get(key, "auto") for key in ("STWO_ZIG_WORKERS", "STWO_ZIG_POW_WORKERS")},
              "toolchain": {"zig": s31.invoke("zig", "version").strip(), "python": platform.python_version()},
              "method": {"build": "ReleaseFast", "backend": "CPU", "warmups_per_lane": args.warmups,
                  "samples_per_lane": args.samples, "order": "alternating sequential lanes", "scope":
                  "fresh CLI process: witness, topology, blinding, setup, prove, serialize, self-verify and output; separate native verification; excludes compilation; no resident-cache claim"},
              "packages": {lane: {"compiler_sha256": manifests[lane]["compiler_sha256"],
                  "prover_sha256": s31.file_hash(path / f"bin/s31-{name}-prover"),
                  "verifier_sha256": s31.file_hash(path / f"bin/s31-{name}-native-verifier")} for lane, path in packages.items()},
              "samples": rows, "summary": {lane: summary([row for row in rows if row["lane"] == lane and not row["warmup"]]) for lane in packages},
              "profiles": profiles, "oracle": "both separately compiled native verifiers; complete new-package pinned Rust acceptance remains pending"}
    s31.write_json(args.output, result)
    print(json.dumps({"report": str(args.output), "summary": result["summary"]}, indent=2))


if __name__ == "__main__":
    main()
