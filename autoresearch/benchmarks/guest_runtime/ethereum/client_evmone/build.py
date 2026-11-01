#!/usr/bin/env python3
"""Build the evmone-class (ziskethone + evmone) RV64IM guest for the stwo
Ethereum guest ABI.

Third-party sources are never vendored: they are fetched at pinned commits into
a cache directory, our patches are applied to a staged copy, and the ELF is
compiled with `zig c++` (Zig 0.15.2: bundled libc++ headers, compiler-rt, RISC-V
backend). Only the Python standard library is used.

  python3 -I build.py --out DIR [--cache DIR] [--profile admitted|candidate]
                      [--host] [--jobs 4] [--clean]

Outputs DIR/client-evmone-<profile>.elf (or DIR/client-evmone-host for --host)
and DIR/build-manifest.json.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[4]
LINKER_SCRIPT = HERE / "linker-wide-cxx.ld"  # rv64/linker-wide.ld + .init_array in .data

# Pinned third-party sources (public repositories; fetched, never vendored).
SOURCES = {
    "ziskethone": {
        "url": "https://github.com/0xPolygonHermez/ziskethone.git",
        "commit": "1c3e8d1737c0269a50af24a6fdb26091a6eaee27",
        "license": "Apache-2.0 OR MIT",
    },
    "evmone": {
        "url": "https://github.com/ethereum/evmone.git",
        "commit": "2a4decd05b7e088b2da0e1f1924f8968e14e3586",  # tag v0.24.0
        "license": "Apache-2.0",
    },
    "blst": {
        "url": "https://github.com/supranational/blst.git",
        "commit": "54e6e55674722fc2797ebb4bbb71b26d881eb4b8",  # tag v0.3.17 (evmone's pin)
        "license": "Apache-2.0",
    },
    "intx": {
        "url": "https://github.com/chfast/intx.git",
        "commit": "0306b495820a5259563e5055f0a8b726b9ae4e0b",  # tag v0.15.0
        "license": "Apache-2.0",
    },
}

# ziskethone's own evmone patch stack, applied in its CMake order (from the
# fetched ziskethone tree). ZEG_ZISK-gated hunks are inert in this build.
ZISKETHONE_EVMONE_PATCHES = [
    "02-evmone-delegation-eoa-fastpath.patch",
    "03-evmone-zisk-u256-abi.patch",
    "04-evmone-zisk-jumpdest-pointer-walk.patch",
    "05-evmone-zisk-jumpdest-precompile.patch",
    "06-evmone-zisk-fused-dispatch.patch",
    "07-evmone-precompile-reused-output.patch",
    "09-evmone-zisk-analyze-into-buffer.patch",
    "10-evmone-selfbalance-cache.patch",
    "11-evmone-zisk-coinbase-aligned-load.patch",
    "12-evmone-zisk-address-aligned-load.patch",
    "13-evmone-zisk-txctx-bytes32-aligned-load.patch",
    "14-evmone-zisk-tx-arena-call-output.patch",
    "15-evmone-depth-limit-all-forks.patch",
    "16-evmone-zisk-memory-views.patch",
]

ZIG_LIBCXX = None  # resolved from `zig env`

GUEST_TARGET = ["-target", "riscv64-linux-musl", "-mcpu=generic_rv64+m"]
COMMON_CXX = ["-std=c++20", "-fno-exceptions", "-fno-rtti", "-ffunction-sections", "-fdata-sections",
              "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-Wno-deprecated-declarations"]
GUEST_EXTRA = ["-fno-pic", "-fomit-frame-pointer", "-mcmodel=medlow"]
DEFINES = ["-DZEG_STWO", "-DZEG_PUBLIC_OUTPUT_BLOCK_HASH", '-DPROJECT_VERSION="0.24.0"',
           "-DZEG_ANALYSIS_CACHE_SLOTS=1152"]


def run(cmd, cwd=None, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], cwd=cwd, check=True, **kw)


def git(repo: Path, *args, capture=False):
    r = subprocess.run(["git", "-C", str(repo), *args], check=True,
                       capture_output=capture, text=True)
    return r.stdout.strip() if capture else None


def fetch(cache: Path) -> dict:
    cache.mkdir(parents=True, exist_ok=True)
    out = {}
    for name, src in SOURCES.items():
        d = cache / name
        if not (d / ".git").exists():
            d.mkdir(parents=True, exist_ok=True)
            git(d, "init", "-q")
            git(d, "remote", "add", "origin", src["url"])
        head = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True)
        if head.returncode != 0 or head.stdout.strip() != src["commit"]:
            git(d, "fetch", "-q", "--depth", "1", "origin", src["commit"])
            git(d, "checkout", "-q", "--force", "FETCH_HEAD")
        got = git(d, "rev-parse", "HEAD", capture=True)
        if got != src["commit"]:
            raise SystemExit(f"{name}: expected {src['commit']}, got {got}")
        if git(d, "status", "--porcelain", capture=True):
            raise SystemExit(f"{name}: fetched checkout is dirty; delete {d}")
        out[name] = {"url": src["url"], "commit": got, "license": src["license"]}
    return out


def stage(cache: Path, work: Path) -> dict:
    """Copy pinned sources into work/src and apply the patch stacks."""
    src = work / "src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    ignore = shutil.ignore_patterns(".git")
    shutil.copytree(cache / "evmone", src / "evmone", ignore=ignore)
    shutil.copytree(cache / "intx", src / "intx", ignore=ignore)
    shutil.copytree(cache / "blst", src / "blst", ignore=ignore)
    shutil.copytree(cache / "ziskethone" / "cpp-guest", src / "ziskethone" / "cpp-guest", ignore=ignore)
    applied = []
    zpatches = cache / "ziskethone" / "cpp-guest" / "patches"
    for p in ZISKETHONE_EVMONE_PATCHES:
        run(["git", "apply", "-p1", zpatches / p], cwd=src / "evmone")
        applied.append(f"ziskethone/cpp-guest/patches/{p}")
    for p in sorted((HERE / "patches").glob("*.patch")):
        target = src / ("evmone" if "-evmone-" in p.name else "ziskethone")
        run(["git", "apply", "-p1", p], cwd=target)
        applied.append(f"client_evmone/patches/{p.name}")
    return {"applied_patches": applied}


def sources(src: Path, host: bool, profile: str, secp: str) -> list[tuple[Path, str]]:
    zg = src / "ziskethone" / "cpp-guest"
    ev = src / "evmone"
    files: list[Path] = []
    files += [p for p in sorted((zg / "src").glob("*.cpp")) if p.name not in ("main.cpp", "ffi.cpp")]
    files += [zg / "zisk" / "tracer_stubs.cpp"]
    files += [p for p in sorted((ev / "lib" / "evmone").glob("*.cpp"))
              if p.name not in ("cpu_check.cpp", "tracing.cpp")]
    files += [p for p in sorted((ev / "lib" / "evmone_precompiles").glob("*.cpp"))
              if not (secp == "stwo" and p.name == "secp256k1.cpp")]
    files += [ev / "lib" / "evmone_precompiles" / "pairing" / "bn254" / "pairing.cpp"]
    files += [ev / "test" / "state" / "precompiles.cpp"]
    glue = HERE / "glue"
    files += [glue / n for n in ("keccak_stwo.cpp", "witness_trie.cpp", "stwo_client.cpp",
                                 )]
    files += [src / "blst" / "src" / "server.c"]
    if host:
        files += [src / "blst" / "build" / "assembly.S"]
    if secp == "stwo":
        files += [glue / "secp256k1_stwo.cpp"]
    else:
        files += [zg / "zisk" / "secp256k1.cpp"]  # host path: evmone's software recover
    if host:
        files += [glue / "host_main.cpp", glue / "host_services.cpp"]
    else:
        files += [glue / "runtime.cpp", glue / "start.S", Path(ZIG_LIBCXX) / "src" / "hash.cpp",
                  Path(ZIG_LIBCXX) / "src" / "memory_resource.cpp"]
    return [(f, {".S": "asm", ".c": "c"}.get(f.suffix, "cxx")) for f in files]


def includes(src: Path) -> list[str]:
    zg = src / "ziskethone" / "cpp-guest"
    ev = src / "evmone"
    dirs = [zg / "include", HERE / "glue", ev / "include", ev / "evmc" / "include", ev,
            ev / "lib", ev / "lib" / "evmone_precompiles", src / "intx" / "include", src / "blst" / "bindings"]
    return [f"-I{d}" for d in dirs]


def needs_rebuild(obj: Path, dep: Path, stamp: Path, flags_hash: str) -> bool:
    if not obj.exists() or not dep.exists() or not stamp.exists() or stamp.read_text() != flags_hash:
        return True
    t = obj.stat().st_mtime
    text = dep.read_text().replace("\\\n", " ")
    for tok in text.split(":", 1)[-1].split():
        p = Path(tok)
        if not p.exists() or p.stat().st_mtime > t:
            return True
    return False


def compile_one(job):
    f, kind, obj, flags = job
    dep = obj.with_suffix(".d")
    stamp = obj.with_suffix(".flags")
    fh = hashlib.sha256(" ".join(flags).encode()).hexdigest()
    if not needs_rebuild(obj, dep, stamp, fh):
        return None
    obj.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["zig", "c++" if kind == "cxx" else "cc", *flags, "-MMD", "-MF", str(dep), "-c", str(f), "-o", str(obj)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return f"FAILED {f}\n{' '.join(cmd)}\n{r.stderr[-6000:]}"
    stamp.write_text(fh)
    return None


def main(argv=None):
    global ZIG_LIBCXX
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--cache", default=None, help="pinned source checkouts (default OUT/cache)")
    ap.add_argument("--profile", choices=("admitted", "candidate"), default="admitted")
    ap.add_argument("--host", action="store_true", help="native debug build with emulated services")
    ap.add_argument("--opt", default="-O2")
    ap.add_argument("--secp", choices=("stwo", "evmone"), default="stwo",
                    help="stwo: recover on the admitted secp services; evmone: software reference")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--no-stage", action="store_true", help="reuse the staged, patched sources")
    a = ap.parse_args(argv)
    out = Path(a.out).resolve()
    cache = Path(a.cache).resolve() if a.cache else out / "cache"
    lib_dir = subprocess.run(["zig", "env"], capture_output=True, text=True, check=True).stdout
    for line in lib_dir.splitlines():
        if ".lib_dir" in line:
            ZIG_LIBCXX = str(Path(line.split('"')[1]) / "libcxx")
    if not ZIG_LIBCXX:
        raise SystemExit("cannot locate zig lib dir")
    zig_version = subprocess.run(["zig", "version"], capture_output=True, text=True, check=True).stdout.strip()

    pinned = fetch(cache)
    work = out / "work"
    if a.clean and work.exists():
        shutil.rmtree(work)
    staged = {"applied_patches": "reused"}
    if not (a.no_stage and (work / "src").exists()):
        staged = stage(cache, work)
    src = work / "src"

    variant = "host" if a.host else a.profile
    defines = list(DEFINES)
    if a.profile == "candidate":
        defines.append("-DCANDIDATE_SERVICES")
    if a.host:
        defines.append("-DSTWO_HOST")
        cxx = [a.opt, "-g", *COMMON_CXX, *defines, *includes(src)]
        cc = [a.opt, "-g", *defines]
    else:
        cxx = [*GUEST_TARGET, a.opt, *COMMON_CXX, *GUEST_EXTRA, *defines, *includes(src)]
        cc = [*GUEST_TARGET, *defines]
    jobs = []
    objdir = work / f"obj-{variant}"
    for f, kind in sources(src, a.host, a.profile, a.secp):
        flags = list(cxx if kind == "cxx" else cc)
        if kind == "c":
            flags += ["-ffunction-sections", "-fdata-sections"]
            if not a.host:
                # No RISC-V assembly in blst: portable C with 32-bit limbs.
                flags += ["-D__BLST_NO_ASM__", a.opt, *GUEST_EXTRA]
            else:
                flags += [a.opt]
        if f.name == "runtime.cpp":
            flags += ["-fno-builtin"]
        if f.name in ("hash.cpp", "memory_resource.cpp"):
            flags += ["-D_LIBCPP_BUILDING_LIBRARY", f"-I{Path(ZIG_LIBCXX) / 'src'}"]
        rel = f.relative_to(src) if f.is_relative_to(src) else Path("ext") / f.name
        jobs.append((f, kind, objdir / (str(rel).replace("/", "__") + ".o"), flags))
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        errors = [e for e in pool.map(compile_one, jobs) if e]
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        raise SystemExit(f"{len(errors)} compile errors")
    objs = [str(j[2]) for j in jobs]
    if a.host:
        exe = out / "client-evmone-host"
        run(["zig", "c++", a.opt, "-g", *objs, "-o", exe])
    else:
        exe = out / f"client-evmone-{a.profile}.elf"
        run(["zig", "c++", "-target", "riscv64-freestanding-none", "-mcpu=generic_rv64+m", "-nostdlib",
             "-static", "-T", LINKER_SCRIPT, "-Wl,--gc-sections", "-Wl,-z,stack-size=0", *objs, "-o", exe])
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    manifest = {
        "schema": "stwo.rv64.client-evmone-build.v1",
        "variant": variant,
        "artifact": str(exe),
        "sha256": digest,
        "zig_version": zig_version,
        "optimization": a.opt,
        "secp": a.secp,
        "defines": defines,
        "pinned_sources": pinned,
        "staging": staged,
        "linker_script": str(LINKER_SCRIPT.relative_to(REPO_ROOT)),
    }
    (out / f"build-manifest-{variant}.json").write_text(json.dumps(manifest, indent=1))
    print(f"{exe} sha256={digest}")


if __name__ == "__main__":
    main()
