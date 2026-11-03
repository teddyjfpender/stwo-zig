#!/usr/bin/env python3
"""Build the persistent in-process RV64 CUDA service from pinned AOT sources."""
import argparse
import concurrent.futures
import ctypes
import hashlib
import json
import math
import os
import re
import signal
from pathlib import Path
import shlex
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_checked(command, log, timeout):
    """A deadline owns the complete compiler process group, including NVVM."""
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        code = process.wait(timeout=timeout)
    except BaseException:
        # wait(timeout) alone leaves nvcc's optimizer children running. Kill the
        # group even when its leader exits before a child handles the signal.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    if code:
        raise subprocess.CalledProcessError(code, command)


def compile_native(nvcc, version, flags, source, obj, log_path, timeout):
    """Publish an object only after compilation and its dependency scan pass."""
    dep, stamp = obj.with_suffix(".d"), obj.with_suffix(".json")
    key = hashlib.sha256((version + repr(flags) + sha(source)).encode()).hexdigest()
    if obj.is_file() and stamp.is_file():
        try:
            old = json.loads(stamp.read_text())
            if (old.get("key") == key and old.get("dependencies") and
                    old.get("object_sha256") == sha(obj) and
                    all(Path(p).is_file() and sha(Path(p)) == h
                        for p, h in old["dependencies"].items())):
                return True
        except (OSError, ValueError):
            pass  # An incomplete cache record cannot establish a hit.
    pending = obj.with_name(f".{obj.name}.{os.getpid()}.pending")
    pending_dep = pending.with_suffix(".d")
    pending_stamp = pending.with_suffix(".json")
    try:
        with log_path.open("w") as log:
            run_checked([nvcc, *flags, "-MD", "-MF", str(pending_dep), "-c",
                         str(source), "-o", str(pending)], log, timeout)
        if not pending.is_file() or pending.stat().st_size == 0:
            raise RuntimeError("compiler did not produce a nonempty object: " + str(source))
        paths = shlex.split(pending_dep.read_text().replace("\\\n", " ").split(":", 1)[1])
        dependencies = {str(Path(p).resolve()): sha(Path(p)) for p in paths}
        if str(source.resolve()) not in dependencies:
            raise RuntimeError("compiler dependency file omitted source: " + str(source))
        pending_stamp.write_text(json.dumps({"key": key, "dependencies": dependencies,
                                            "object_sha256": sha(pending)}, sort_keys=True))
        os.replace(pending, obj)
        os.replace(pending_dep, dep)
        os.replace(pending_stamp, stamp)
    finally:
        for path in (pending, pending_dep, pending_stamp):
            path.unlink(missing_ok=True)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--extra-object", action="append", type=Path, default=[], help="Additional AOT dispatcher/projection objects")
    parser.add_argument("--extra-native-source", action="append", default=[], help="Additional .cu source relative to the native directory")
    parser.add_argument("--compile-timeout", type=float, default=180, help="Seconds per compiler process group")
    parser.add_argument("--link-timeout", type=float, default=180)
    parser.add_argument("--required-symbols", type=Path, help="Required export manifest; defaults to the native RV64 contract")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16 or any(not math.isfinite(t) or t <= 0 for t in (args.compile_timeout, args.link_timeout)):
        parser.error("jobs must be 1..16 and compiler/link deadlines must be positive")
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
    sources += ["rv64/" + name + ".cu" for name in ["deep", "samples", "fri", "channel", "pcs", "trace", "sample_order", "composition_finalize",
                "gkr", "round", "tail", "batch", "batch_oracles", "gkr_loop", "binding", "parameters", "closure", "global", "ls_dword_witness", "cpu_witness", "family_witness", "memory_witness", "arithmetic_witness", "bridge_witness", "bulk_witness", "sponge_witness", "keccak_witness", "sha256_witness", "arith256_witness", "secp_witness", "events"]]
    for name in args.extra_native_source:
        source = (native / name).resolve()
        if not source.is_relative_to(native) or source.suffix != ".cu" or not source.is_file():
            parser.error("extra native source must be an existing .cu under native: " + name)
        relative = source.relative_to(native).as_posix()
        if relative in sources:
            parser.error("duplicate native source: " + relative)
        sources.append(relative)
    if len({name.replace("/", "-") for name in sources}) != len(sources):
        parser.error("native source object names collide after directory flattening")
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-fPIC,-pthread", f"-I{native}"]
    version = subprocess.check_output([args.nvcc, "--version"], text=True)
    def compile_one(relative):
        source = native / relative
        obj = build / (relative.replace("/", "-") + ".o")
        cached = compile_native(args.nvcc, version, flags, source, obj,
                                logs / (relative.replace("/", "-") + ".log"), args.compile_timeout)
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
            run_checked([args.nvcc, "-shared", "-Xcompiler=-pthread", "-Xlinker=-Bsymbolic", *map(str, objects), "-o", str(pending)], log, args.link_timeout)
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
               "compile_timeout_seconds": args.compile_timeout, "link_timeout_seconds": args.link_timeout,
               "objects": {str(p): sha(p) for p in objects}, "scope": "AOT build only; no proof or residency qualification"}
    (build / "build.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(str(library), flush=True)


if __name__ == "__main__":
    main()
