#!/usr/bin/env python3
"""Build the persistent in-process RV64 CUDA service from pinned AOT sources."""
import argparse
import concurrent.futures
import ctypes
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--extra-object", action="append", type=Path, default=[], help="Additional AOT dispatcher/projection objects")
    parser.add_argument("--required-symbols", type=Path, help="Required export manifest; defaults to the native RV64 contract")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16:
        parser.error("jobs must be 1..16")
    root, build = args.source_root.resolve(), args.build.resolve()
    native = root / "src/backends/cuda/native"
    symbol_path = args.required_symbols or native / "rv64/required_symbols.json"
    required = json.loads(symbol_path.read_text())["symbols"]
    if not required or len(set(required)) != len(required) or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s) for s in required):
        parser.error("invalid required native export manifest")
    build.mkdir(parents=True, exist_ok=True)
    logs = build / "logs"
    logs.mkdir(exist_ok=True)
    sources = ["rv64/pcs_native.cu", "runtime/context.cu", "transform/lde.cu", "transform/n2b.cu", "transform/b2n_retained.cu",
               "commitment/merkle.cu", "commitment/progressive.cu", "pow/search.cu"]
    sources += ["rv64/" + name + ".cu" for name in ["deep", "samples", "fri", "channel", "pcs", "trace", "sample_order",
                "gkr", "round", "tail", "batch", "gkr_loop", "binding", "parameters", "closure", "global", "ls_dword_witness", "cpu_witness", "events"]]
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-fPIC,-pthread", f"-I{native}"]
    version = subprocess.check_output([args.nvcc, "--version"], text=True)
    def compile_one(relative):
        source = native / relative
        obj = build / (relative.replace("/", "-") + ".o")
        dep = obj.with_suffix(".d")
        stamp = obj.with_suffix(".json")
        key = hashlib.sha256((version + repr(flags) + sha(source)).encode()).hexdigest()
        cached = False
        if obj.is_file() and stamp.is_file():
            old = json.loads(stamp.read_text())
            cached = old.get("key") == key and old.get("dependencies") and old.get("object_sha256") == sha(obj) and all(Path(p).is_file() and sha(Path(p)) == h for p, h in old["dependencies"].items())
        if not cached:
            with (logs / (relative.replace("/", "-") + ".log")).open("w") as log:
                subprocess.run([args.nvcc, *flags, "-MD", "-MF", str(dep), "-c", str(source), "-o", str(obj)], check=True, stdout=log, stderr=subprocess.STDOUT)
            paths = shlex.split(dep.read_text().replace("\\\n", " ").split(":", 1)[1])
            dependencies = {str(Path(p).resolve()): sha(Path(p)) for p in paths}
            stamp.write_text(json.dumps({"key": key, "dependencies": dependencies, "object_sha256": sha(obj)}, sort_keys=True))
        print(json.dumps({"compiled": relative, "cached": bool(cached)}), flush=True)
        return obj
    started = time.monotonic()
    # Report a service/body syntax error before compiling every numerical unit.
    first = compile_one(sources[0])
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        objects = [first, *pool.map(compile_one, sources[1:])]
    objects += [p.resolve(strict=True) for p in args.extra_object]
    library = build / "libstwo-rv64-native.so"
    pending = build / f".libstwo-rv64-native-{os.getpid()}.so"
    try:
        with (logs / "link.log").open("w") as log:
            subprocess.run([args.nvcc, "-shared", "-Xcompiler=-pthread", "-Xlinker=-Bsymbolic", *map(str, objects), "-o", str(pending)], check=True, stdout=log, stderr=subprocess.STDOUT)
        # Check the candidate inode before replacing the live library. This
        # catches hidden symbols and missing TUs without a producer rebuild or
        # capture/setup run. Existing sessions keep their admitted old inode.
        candidate = ctypes.CDLL(str(pending))
        missing = [name for name in required if not hasattr(candidate, name)]
        if missing:
            raise RuntimeError("native CUDA library missing required exports: " + ", ".join(missing))
        # Existing native producers may still map the old inode. Never truncate
        # their library or publish a partially linked file to a new dlopen.
        os.replace(pending, library)
    finally:
        pending.unlink(missing_ok=True)
    receipt = {"schema": "rv64-cuda-native-library-build/v1", "seconds": time.monotonic() - started, "compiler": version,
               "required_exports": len(required), "required_export_manifest_sha256": sha(symbol_path),
               "library_sha256": sha(library), "builder_sha256": sha(Path(__file__).resolve()),
               "objects": {str(p): sha(p) for p in objects}, "scope": "AOT build only; no proof or residency qualification"}
    (build / "build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(str(library), flush=True)


if __name__ == "__main__":
    main()
