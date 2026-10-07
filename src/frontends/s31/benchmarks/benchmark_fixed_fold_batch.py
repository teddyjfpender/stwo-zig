#!/usr/bin/env python3
"""Compare separate and cached fixed-fold commands, including peak RSS on macOS."""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import json
import platform
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import s31


HERE = S31_SOURCE_ROOT
RSS = re.compile(r"^\s*(\d+)\s+maximum resident set size\s*$", re.MULTILINE)


def call(*args: str) -> tuple[float, int | None]:
    timed = args[0] == "/usr/bin/time"
    started = time.perf_counter()
    result = subprocess.run(args, cwd=s31.ROOT, text=True, capture_output=True)
    elapsed = time.perf_counter() - started
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed:\n{result.stdout}{result.stderr}")
    match = RSS.search(result.stderr) if timed else None
    if timed and match is None:
        raise RuntimeError("macOS time did not report maximum resident set size")
    return elapsed, int(match.group(1)) if match else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("assignment", type=Path)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--record", type=Path)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise RuntimeError("this benchmark uses macOS /usr/bin/time -l for peak RSS")
    if not 1 <= args.trials <= 9:
        raise ValueError("trials must be between 1 and 9")
    package = args.package.resolve()
    assignment = args.assignment.resolve()
    manifest = s31.verify_package(package)
    if manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
        raise ValueError("benchmark requires a fixed-fold package")
    cli = (sys.executable, str(HERE / "python/s31.py"))
    wide = manifest["lowering"] == "sparse-wide-gate"
    measured: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="s31-fold-batch-benchmark-") as temporary:
        work = Path(temporary)
        leaf, first, second = (work / f"{name}.proof" for name in ("leaf", "first", "second"))
        call(*cli, "prove", str(package), str(assignment), str(leaf))
        call(*cli, "wrap", str(package), str(leaf), str(first), "--low-memory")
        base = first
        if wide:
            call(*cli, "wrap-next", str(package), str(first), str(second), "--low-memory")
            base = second

        for trial in range(args.trials):
            paths = {mode: work / f"trial-{trial}-{mode}" for mode in ("separate", "batch")}
            for directory in paths.values():
                directory.mkdir()
            timings: dict[str, dict] = {}
            order = ("separate", "batch") if trial % 2 == 0 else ("batch", "separate")
            for mode in order:
                directory = paths[mode]
                if mode == "separate":
                    previous = base
                    steps = []
                    for step in range(3):
                        target = directory / f"fold-{step}.proof"
                        elapsed, rss = call("/usr/bin/time", "-l", *cli,
                                            "fold-base" if step == 0 else "fold-next",
                                            str(package), str(previous), str(target), "--low-memory")
                        steps.append({"wall_seconds": elapsed, "peak_resident_bytes": rss})
                        previous = target
                    timings[mode] = {"wall_seconds": sum(item["wall_seconds"] for item in steps),
                                     "peak_resident_bytes": max(item["peak_resident_bytes"] for item in steps),
                                     "commands": steps}
                else:
                    target = directory / "fold-2.proof"
                    elapsed, rss = call("/usr/bin/time", "-l", *cli, "fold-advance",
                                        str(package), str(base), str(target), "--steps", "3",
                                        "--checkpoint-dir", str(directory / "checkpoints"), "--low-memory")
                    timings[mode] = {"wall_seconds": elapsed, "peak_resident_bytes": rss}
            separate = paths["separate"]
            batch = paths["batch"]
            for step in range(3):
                one = separate / f"fold-{step}.proof"
                batched = batch / "fold-2.proof" if step == 2 else batch / "checkpoints" / f"fold-{step:05d}.proof"
                if one.read_bytes() != batched.read_bytes() or Path(str(one) + ".statement.json").read_bytes() != Path(str(batched) + ".statement.json").read_bytes():
                    raise AssertionError(f"trial {trial} step {step}: batch changed proof or statement bytes")
            top = batch / "fold-2.proof"
            call(*cli, "verify-fold", str(package), str(top))
            measured.append({"trial": trial, "order": order, "separate": timings["separate"],
                             "batch": timings["batch"], "top_proof_sha256": s31.file_hash(top),
                             "top_proof_bytes": top.stat().st_size})

    separate_wall = statistics.median(item["separate"]["wall_seconds"] for item in measured)
    batch_wall = statistics.median(item["batch"]["wall_seconds"] for item in measured)
    report = {
        "schema": "s31-fixed-fold-batch-benchmark-v1",
        "platform": platform.platform(),
        "package": manifest["name"],
        "profile": manifest["lowering"],
        "compiler_sha256": manifest["compiler_sha256"],
        "child_fri_fold_step": manifest["fri_fold_step"],
        "wrapper_fri_fold_step": manifest["recursive_fri_fold_step"],
        "step_count": 3,
        "low_memory": True,
        "trials": measured,
        "median_separate_wall_seconds": separate_wall,
        "median_batch_wall_seconds": batch_wall,
        "median_wall_reduction_percent": 100 * (separate_wall - batch_wall) / separate_wall,
        "median_separate_peak_resident_bytes": statistics.median(item["separate"]["peak_resident_bytes"] for item in measured),
        "median_batch_peak_resident_bytes": statistics.median(item["batch"]["peak_resident_bytes"] for item in measured),
        "proofs_and_statements_byte_identical": True,
    }
    if args.record:
        s31.write_json(args.record.resolve(), report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
