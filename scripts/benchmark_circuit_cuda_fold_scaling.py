#!/usr/bin/env python3
"""Measure CUDA fold-tree scaling with repeated, already verified leaf artifacts.

This isolates recursive reduction cost. Repetition does not establish a
continuous Starknet chain, so these receipts are not end-to-end block proofs.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import threading
import time


STAGE = re.compile(r"circuit-fold-stage (setup_and_canonical_ns|reductions_ns|render_ns)=(\d+)")
FOLD = re.compile(r"circuit-cuda fold-tree leaves=(\d+) reductions=(\d+) prove_ns=(\d+)")
LAYER = re.compile(r"circuit-fold-layer index=(\d+) pairs=(\d+) elapsed_ns=(\d+)")
REDUCTION = re.compile(r"reduce layer (\d+) pair \d+(?: \(root\))?: build (\d+) ms, prove (\d+) ms")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def gpu_used_bytes() -> int | None:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=2, check=True,
        )
        return max(int(line.strip()) for line in result.stdout.splitlines()) * (1 << 20)
    except (FileNotFoundError, ValueError, subprocess.SubprocessError):
        return None


def host_peak_bytes(pid: int) -> int | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        match = re.search(r"^VmHWM:\s+(\d+) kB$", status, re.MULTILINE)
        return int(match.group(1)) * 1024 if match else None
    except OSError:
        return None


def run_size(args: argparse.Namespace, size: int) -> dict:
    directory = args.out / str(size)
    directory.mkdir(parents=True, exist_ok=True)
    leaves = [str(args.leaf[index % len(args.leaf)]) for index in range(size)]
    manifest = directory / "leaves.json"
    manifest.write_text(json.dumps({"leaves": leaves}, indent=2) + "\n")
    proof = directory / "root.proof"
    outputs = directory / "root_outputs.json"
    packed = directory / "root_packed.json"
    command = [str(args.prover), "fold-tree", "--manifest", str(manifest),
               "--registry", str(args.registry), "--proof", str(proof),
               "--outputs", str(outputs), "--packed", str(packed)]
    stop = threading.Event()
    samples: list[int] = []
    host_samples: list[int] = []
    started = time.perf_counter()
    with (directory / "fold.log").open("w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)

        def sample() -> None:
            while not stop.is_set():
                gpu = gpu_used_bytes()
                if gpu is not None:
                    samples.append(gpu)
                host = host_peak_bytes(process.pid)
                if host is not None:
                    host_samples.append(host)
                stop.wait(1.0)

        monitor = threading.Thread(target=sample, daemon=True)
        monitor.start()
        try:
            exit_code = process.wait()
        finally:
            stop.set()
            monitor.join()
    wall_s = time.perf_counter() - started
    log_text = (directory / "fold.log").read_text()
    stages = {name.removesuffix("_ns"): int(value) / 1e9 for name, value in STAGE.findall(log_text)}
    levels = [{"index": int(index), "pairs": int(pairs), "wall_s": int(ns) / 1e9}
              for index, pairs, ns in LAYER.findall(log_text)]
    components: dict[int, dict] = {}
    for index, build_ms, prove_ms in REDUCTION.findall(log_text):
        row = components.setdefault(int(index), {"pairs": 0, "build_ms": 0, "prove_ms": 0})
        row["pairs"] += 1
        row["build_ms"] += int(build_ms)
        row["prove_ms"] += int(prove_ms)
    fold = FOLD.search(log_text)
    if exit_code or fold is None or int(fold.group(1)) != size or int(fold.group(2)) != size - 1:
        raise RuntimeError(f"fold-tree failed for {size} leaves; see {directory / 'fold.log'}")
    if levels and sum(level["pairs"] for level in levels) != size - 1:
        raise RuntimeError(f"incomplete per-level telemetry for {size} leaves")
    if sum(row["pairs"] for row in components.values()) != size - 1:
        raise RuntimeError(f"incomplete per-reduction telemetry for {size} leaves")
    files = {name: {"sha256": digest(path), "bytes": path.stat().st_size}
             for name, path in (("proof", proof), ("outputs", outputs), ("packed", packed))}
    return {"leaves": size, "reductions": size - 1, "wall_s": round(wall_s, 3),
            "prover_ns": int(fold.group(3)), "stages_s": stages, "levels": levels,
            "levels_complete": bool(levels),
            "level_components_ms": {str(index): row for index, row in sorted(components.items())},
            "gpu_peak_used_bytes": max(samples) if samples else None,
            "host_peak_rss_bytes": max(host_samples) if host_samples else None,
            "files": files}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--leaf", type=Path, action="append", required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sizes", type=int, nargs="+", default=[16, 64, 256, 1024])
    args = parser.parse_args()
    args.leaf = [leaf.resolve(strict=True) for leaf in args.leaf]
    args.registry = args.registry.resolve(strict=True)
    args.prover = args.prover.resolve(strict=True)
    args.out = args.out.resolve()
    if len(args.leaf) < 2 or any(size < 2 or size & (size - 1) for size in args.sizes):
        parser.error("provide at least two leaves and power-of-two sizes >= 2")
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for size in args.sizes:
        row = run_size(args, size)
        rows.append(row)
        (args.out / "summary.json").write_text(json.dumps({"schema": "stwo-circuit-cuda-fold-scaling-v1",
                                                       "semantic_scope": "repeated verified leaves; not a continuous block chain",
                                                       "leaf_sha256": [digest(leaf) for leaf in args.leaf],
                                                       "registry_sha256": digest(args.registry),
                                                       "prover_sha256": digest(args.prover),
                                                       "rows": rows}, indent=2) + "\n")
        print(json.dumps(row), flush=True)


if __name__ == "__main__":
    main()
