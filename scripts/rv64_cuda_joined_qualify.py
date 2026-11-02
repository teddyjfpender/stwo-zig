#!/usr/bin/env python3
"""Build and qualify cold joined-AIR CUDA fixtures; never admit an execution."""
import argparse
import concurrent.futures
import hashlib
import json
import shlex
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--fixtures", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--context-object", type=Path, required=True)
    p.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    p.add_argument("--sanitizer", default="/usr/local/cuda/bin/compute-sanitizer")
    p.add_argument("--arch", choices=["89", "90", "100", "120"], default="120")
    p.add_argument("--jobs", type=int, default=4)
    args = p.parse_args()
    if args.jobs < 1 or args.jobs > 16:
        p.error("--jobs must be between 1 and 16")
    root, fixtures, build = args.source_root.resolve(), args.fixtures.resolve(), args.build.resolve()
    if not args.context_object.is_file():
        p.error("--context-object must be the qualified native context object")
    build.mkdir(parents=True, exist_ok=True)
    logs = build / "logs"
    logs.mkdir(exist_ok=True)
    native = root / "src/backends/cuda/native"
    driver = root / "tests/cuda/rv64/joined_smoke.cu"
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", f"arch=compute_{args.arch},code=sm_{args.arch}",
             f"-I{native}", f"-I{root / 'tests/cuda/rv64'}", f"-I{fixtures}", "-Xcompiler=-pthread"]
    version = subprocess.check_output([args.nvcc, "--version"], text=True)
    headers = sorted(native.rglob("*.h")) + sorted(native.rglob("*.cuh")) + sorted((root / "tests/cuda/rv64").glob("*.cuh")) + sorted((root / "tests/cuda/rv64").glob("*.h")) + sorted(fixtures.glob("*.h"))
    header_digest = hashlib.sha256("".join(str(x.relative_to(root) if x.is_relative_to(root) else x.name) + sha(x) for x in headers).encode()).hexdigest()
    sources = sorted(fixtures.glob("case-*-oods.cu")) + [native / "rv64/parameters.cu"]
    if not sources or len(sources) != len(list(fixtures.glob("case-*.bin"))) + 1:
        p.error("fixture source/data inventory is incomplete")

    def compile_one(source):
        name = source.stem
        out, stamp = build / f"{name}.o", build / f"{name}.sha256"
        depfile = build / f"{name}.d"
        # O1 did not materially improve the widest OODS cold build. Keep the
        # measured O3 policy; dependency caching handles subsequent iterations.
        extra = ["-Xptxas=-v"]
        key = hashlib.sha256((version + repr(flags + extra) + sha(source)).encode()).hexdigest()
        started = time.monotonic()
        cached = False
        dependencies = {}
        if out.is_file() and stamp.is_file():
            try:
                previous = json.loads(stamp.read_text())
                dependencies = previous["dependencies"]
                cached = (previous["key"] == key and dependencies and
                          all(Path(path).is_file() and sha(Path(path)) == digest for path, digest in dependencies.items()) and
                          previous["object_sha256"] == sha(out))
            except (ValueError, KeyError, TypeError):
                cached = False
        if not cached:
            with (logs / f"{name}.log").open("w") as log:
                subprocess.run([args.nvcc, *flags, *extra, "-MD", "-MF", str(depfile), "-c", str(source), "-o", str(out)], check=True, stdout=log, stderr=subprocess.STDOUT)
            deptext = depfile.read_text().replace("\\\n", " ")
            paths = [Path(path).resolve() for path in shlex.split(deptext.split(":", 1)[1])]
            if not paths or not all(path.is_file() for path in paths):
                raise RuntimeError(f"invalid compiler dependency manifest: {depfile}")
            dependencies = {str(path): sha(path) for path in paths}
            stamp.write_text(json.dumps({"key": key, "dependencies": dependencies, "object_sha256": sha(out)}, sort_keys=True))
        result = {"source": source.name, "object": str(out), "cached": bool(cached),
                  "ptxas_optimization": 3,
                  "dependency_digest": hashlib.sha256(json.dumps(dependencies, sort_keys=True).encode()).hexdigest(),
                  "seconds": time.monotonic() - started, "source_sha256": sha(source), "object_sha256": sha(out)}
        print(json.dumps({"compiled": source.name, "cached": bool(cached)}), flush=True)
        return result

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(compile_one, sources))
    binary = build / "joined-smoke"
    with (logs / "link.log").open("w") as log:
        subprocess.run([args.nvcc, *flags, str(driver), *(r["object"] for r in results), str(args.context_object.resolve()), "-ldl", "-o", str(binary)], check=True, stdout=log, stderr=subprocess.STDOUT)
    build_seconds = time.monotonic() - started
    commands = [("normal", [str(binary), str(fixtures)])]
    commands += [(tool, [args.sanitizer, "--tool", tool, "--error-exitcode", "99", str(binary), str(fixtures)])
                 for tool in ("memcheck", "racecheck", "initcheck", "synccheck")]
    for name, command in commands:
        with (logs / f"{name}.log").open("w") as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        print(json.dumps({"gate": name, "status": "PASS"}), flush=True)
    receipt = {"schema": "rv64-cuda-joined-numerical/v1", "full_block_verified": False,
               "scope": "synthetic native joined polynomial parity, not authenticated execution acceptance",
               "build_seconds": build_seconds, "jobs": args.jobs, "arch": args.arch,
               "compiler": version, "builder_sha256": sha(Path(__file__).resolve()), "header_digest": header_digest,
               "context_object_sha256": sha(args.context_object), "driver_sha256": sha(driver),
               "objects": results, "fixtures": {x.name: sha(x) for x in sorted(fixtures.glob("*.bin"))},
               "gates": {name: "PASS" for name, _ in commands}}
    (build / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"qualified": str(build / "qualification.json")}), flush=True)


if __name__ == "__main__":
    main()
