#!/usr/bin/env python3
"""Build the evmone-class (ziskethone + evmone) RV64IM guest for the stwo
Ethereum guest ABI.

Third-party sources are never vendored: they are fetched at pinned commits into
a cache directory, our patches are applied to a staged copy, and the ELF is
compiled with `zig c++` (Zig 0.15.2: bundled libc++ headers, compiler-rt, RISC-V
backend). Only the Python standard library is used.

  python3 -I build.py --out DIR [--cache DIR] [--profile admitted|v3|candidate]
                      [--isa im|zba|zbb|zba_zbb|zbkb|zbb_binary] [--isa-audit TOOL]
                      [--host] [--jobs 4] [--clean]

`--profile v3` builds the ADMITTED ethereum_services_v3 guest: SHA-256
compression (32-byte aligned packet), arith256_mod for MULMOD/ADDMOD, 256-bit
ModArith and 256-bit odd-modulus modexp, memcpy (any source alignment) and
memset with inline destination head/tail and software fallback for overlap,
and memcmp of 8-aligned disjoint operands (`--v3-set` selects a subset of sha,
arith, mem, umem for ablations: `mem` = aligned memcpy/memset, `umem` =
unaligned-source memcpy and memcmp, default on; the aligned-only client is
`--v3-set sha,arith,mem`, ELF suffix `-v3-sha-arith-mem`; add `keccak` for the
admitted Keccak-256 sponge, ELF suffix `-v3-...-keccak`; `jumpdest` = the
JUMPDEST analysis service, patches 0028/0029, default on; `bn` (needs
`arith`) = the admitted BN254 G1 add/double and Fq2 services behind
ecAdd/ecMul/ecPairing, and `bls` = the admitted BLS12-381 Fp2 and 384-bit
Montgomery (arith384_mont) services behind blst (EIP-2537 and KZG), both
default on; drop them for the pre-curves client, ELF suffix
`-v3-sha-arith-mem-umem-keccak-jumpdest`).

`--isa` other than `im` targets candidate Zba/Zbb instructions (execution-only
profile `ethereum_services_v3_candidate_isa`; never admitted) and appends
`-<isa>` to the ELF name. `--isa zbb_binary` is the ADMITTED Zbb BINARY subset
(profile `ethereum_services_v3_zbb`): the compiler stays RV64IM and every
byte swap is one `rev8` (glue/stwo_zbb_binary.h, patch 0024); the linked ELF
must pass `rv64-isa-audit --require-subset` (`--isa-audit`, required), i.e.
contain no Zbb/Zba/Zbkb encoding outside andn/orn/xnor/rev8/sext.b/sext.h/zext.h.

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
# Candidate bit-manipulation extensions (CONTEXT.md "Candidate instructions").
# zbkb is an audit experiment only (it emits pack/packh and rotates); zbb_binary
# compiles RV64IM and issues the admitted rev8 explicitly.
ISA_FEATURES = {"im": "", "zba": "+zba", "zbb": "+zbb", "zba_zbb": "+zba+zbb", "zbkb": "+zbkb", "zbb_binary": ""}
COMMON_CXX = ["-std=c++20", "-fno-exceptions", "-fno-rtti", "-ffunction-sections", "-fdata-sections",
              "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-Wno-deprecated-declarations"]
GUEST_EXTRA = ["-fno-pic", "-fomit-frame-pointer", "-mcmodel=medlow"]
DEFINES = ["-DZEG_STWO", "-DZEG_PUBLIC_OUTPUT_BLOCK_HASH", '-DPROJECT_VERSION="0.24.0"',
           "-DZEG_ANALYSIS_CACHE_SLOTS=1152",
           # ziskethone's fused jump superinstructions (evmone patch 06 hook,
           # zisk/evm/fused_dispatch.inl); portable, enabled outside ZisK by this flag.
           "-DZEG_FUSE_TEST"]


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
        target = src / ("evmone" if "-evmone-" in p.name else "blst" if "-blst-" in p.name
                        else "intx" if "-intx-" in p.name else "ziskethone")
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
              if p.name != "sha256.cpp" and not (secp == "stwo" and p.name == "secp256k1.cpp")]
    files += [ev / "lib" / "evmone_precompiles" / "pairing" / "bn254" / "pairing.cpp"]
    files += [ev / "test" / "state" / "precompiles.cpp"]
    glue = HERE / "glue"
    files += [glue / n for n in ("keccak_stwo.cpp", "sha256_stwo.cpp", "witness_trie.cpp", "stwo_client.cpp", "arith_stwo.cpp",
                                 "curves_stwo.cpp")]
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
    dirs = [zg / "include", HERE / "glue", zg / "zisk", ev / "include", ev / "evmc" / "include", ev,
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


def run_tests(src: Path, out: Path, work: Path, a) -> None:
    """Host tests: memory-function fuzz, secp256k1 differential vs evmone, witness trie
    differential vs a reference MPT encoder, ziskethone word paths (hash, compare, copy),
    blst portable C (the guest's configuration) vs blst assembly."""
    tdir = work / "obj-tests"
    tdir.mkdir(parents=True, exist_ok=True)
    glue = HERE / "glue"
    run(["zig", "c++", "-O1", "-fno-builtin", "-std=c++20", f"-I{glue}", HERE / "tests" / "mem_fuzz.cpp",
         "-o", tdir / "mem_fuzz"])
    run([tdir / "mem_fuzz"])
    flags = [a.opt, "-g", *COMMON_CXX, *DEFINES, "-DSTWO_HOST", *includes(src)]
    # Twice: the RV64IM field/scalar products, then the admitted v3 path (fe_mul/sc_mul on the
    # arith256_mod service, emulated on the host by an independent intx reduction).
    for tag, svc in (("", []), ("-v3arith", ["-DADMITTED_V3", "-DADMITTED_ARITH"])):
        units = [(glue / "secp256k1_stwo.cpp", ["-DSTWO_SECP_NO_EVMONE_API", *svc]), (glue / "host_services.cpp", []),
                 (glue / "keccak_stwo.cpp", []), (src / "evmone" / "lib" / "evmone_precompiles" / "secp256k1.cpp", []),
                 (HERE / "tests" / "secp_differential.cpp", [])]
        objs = []
        for f, extra in units:
            o = tdir / (f.name + tag + ".o")
            run(["zig", "c++", *flags, *extra, "-c", f, "-o", o])
            objs.append(o)
        run(["zig", "c++", a.opt, *objs, "-o", tdir / f"secp_differential{tag}"])
        run([tdir / f"secp_differential{tag}", "3000"])
    # Candidate curve/field/sponge glue vs independent references (all hooks live,
    # portable blst so the 384-bit Montgomery hook is exercised too).
    ev = src / "evmone" / "lib" / "evmone_precompiles"
    bn = ["-DCANDIDATE_ARITH", "-DCANDIDATE_BN"]
    units = [(glue / "curves_stwo.cpp", ["-DCANDIDATE_BN", "-DCANDIDATE_BLS"]), (glue / "arith_stwo.cpp", ["-DCANDIDATE_ARITH"]),
             (glue / "host_services.cpp", []), (glue / "keccak_stwo.cpp", []), (glue / "sha256_stwo.cpp", []),
             (ev / "bn254.cpp", bn), (ev / "kzg.cpp", []), (ev / "kzg_precomputed_lines.cpp", []),
             (HERE / "tests" / "curves_test.cpp", bn)]
    objs = []
    for f, extra in units:
        o = tdir / ("curves-" + f.name + ".o")
        run(["zig", "c++", *flags, *extra, "-c", f, "-o", o])
        objs.append(o)
    o = tdir / "curves-blst-server.c.o"
    run(["zig", "cc", a.opt, "-g", "-D__BLST_NO_ASM__", "-DCANDIDATE_BLS", "-ffunction-sections", "-fdata-sections",
         "-c", src / "blst" / "src" / "server.c", "-o", o])
    objs.append(o)
    run(["zig", "c++", a.opt, *objs, "-o", tdir / "curves_test"])
    run([tdir / "curves_test"])
    tobjs = []
    for f in (glue / "witness_trie.cpp", glue / "keccak_stwo.cpp", glue / "host_services.cpp",
              HERE / "tests" / "trie_differential.cpp"):
        o = tdir / ("trie-" + f.name + ".o")
        run(["zig", "c++", *flags, "-c", f, "-o", o])
        tobjs.append(o)
    run(["zig", "c++", a.opt, *tobjs, "-o", tdir / "trie_differential"])
    run([tdir / "trie_differential", "600"])
    # Fused copy + Keccak-256 of contract codes (build_zeg0) vs ethash_keccak256.
    kobjs = []
    for f in (glue / "keccak_stwo.cpp", glue / "host_services.cpp", HERE / "tests" / "keccak_copy_test.cpp"):
        o = tdir / ("kcopy-" + f.name + ".o")
        run(["zig", "c++", *flags, "-c", f, "-o", o])
        kobjs.append(o)
    run(["zig", "c++", a.opt, *kobjs, "-o", tdir / "keccak_copy_test"])
    run([tdir / "keccak_copy_test"])
    # Guest-only sentinel JUMPDEST scan vs evmone's reference scan.
    jexe = tdir / "jumpdest_scan_test"
    run(["zig", "c++", *flags, HERE / "tests" / "jumpdest_scan_test.cpp", "-o", jexe])
    run([jexe])
    wobj = tdir / "zeg_words_test.o"
    run(["zig", "c++", *flags, "-c", HERE / "tests" / "zeg_words_test.cpp", "-o", wobj])
    run(["zig", "c++", a.opt, wobj, "-o", tdir / "zeg_words_test"])
    run([tdir / "zeg_words_test"])
    # blst: the guest's portable-C configuration (patch 0002 path) vs assembly.
    blst = src / "blst"
    outs = {}
    for name, extra in (("asm", [blst / "build" / "assembly.S"]), ("portable", ["-D__BLST_NO_ASM__"])):
        exe = tdir / f"blst_{name}"
        run(["zig", "cc", a.opt, f"-I{blst / 'bindings'}", blst / "src" / "server.c", *extra,
             HERE / "tests" / "blst_portable.c", "-o", exe])
        outs[name] = subprocess.run([str(exe)], capture_output=True, text=True, check=True).stdout
    if outs["asm"] != outs["portable"] or outs["asm"].count("\n") < 100:
        raise SystemExit("blst portable-C build disagrees with the assembly build")
    print(f"blst portable == assembly ({outs['asm'].count(chr(10))} results)")
    # Fused cgoto dispatch vs the plain switch dispatch (plus the xlat dispatch when the
    # parked translated-segment patch wip/0024 is applied), linked against the host build.
    hobj = work / ("obj-host-eest" if a.eest else "obj-host")  # the host variant's object dir
    fobj = tdir / "xlat_difffuzz.o"
    run(["zig", "c++", *flags, "-c", HERE / "tests" / "xlat_difffuzz.cpp", "-o", fobj])
    link = sorted(hobj.glob("evmone__lib__evmone*__*.o")) + sorted(hobj.glob("evmone__lib__evmone_precompiles__*.o"))
    link += [hobj / n for n in ("evmone__test__state__precompiles.cpp.o", "ext__keccak_stwo.cpp.o",
                                "ext__host_services.cpp.o", "ext__sha256_stwo.cpp.o", "ext__secp256k1_stwo.cpp.o",
                                "ext__arith_stwo.cpp.o", "ext__curves_stwo.cpp.o", "blst__src__server.c.o",
                                "blst__build__assembly.S.o", "ziskethone__cpp-guest__zisk__tracer_stubs.cpp.o")]
    run(["zig", "c++", a.opt, fobj, *sorted(set(link)), "-o", tdir / "xlat_difffuzz"])
    run([tdir / "xlat_difffuzz", "20000", "1"])


def main(argv=None):
    global ZIG_LIBCXX
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--cache", default=None, help="pinned source checkouts (default OUT/cache)")
    ap.add_argument("--profile", choices=("admitted", "v3", "candidate"), default="admitted",
                    help="admitted = ethereum_services_v2; v3 = admitted ethereum_services_v3 "
                         "(SHA-256, arith256_mod, bulk memory incl. unaligned memcpy and memcmp); candidate = execution-only")
    ap.add_argument("--v3-set", default="sha,arith,mem,umem,keccak,jumpdest,bn,bls",
                    help="admitted v3 service groups for --profile v3 (sha, arith, mem, jumpdest = JUMPDEST analysis, keccak = Keccak-256 sponge, "
                         "umem = unaligned-source memcpy and memcmp, needs mem, "
                         "bn = BN254 G1/Fq2 [needs arith], bls = BLS12-381 Fp2 + arith384_mont)")
    ap.add_argument("--candidate-jumpdest", action="store_true",
                    help="EXECUTION-ONLY: route JUMPDEST analysis to the candidate jumpdest_bitmap service "
                         "(profile ethereum_services_v3_candidate); ELF suffix -cjd")
    ap.add_argument("--host", action="store_true", help="native debug build with emulated services")
    ap.add_argument("--candidate-set", default="mem,sha,arith",
                    help="candidate service groups for --profile candidate (mem, sha, arith, mul, "
                         "bn = BN254 G1/Fq2 [needs arith], bls = BLS12-381 Fp/Fp2, keccak = Keccak sponge)")
    ap.add_argument("--opt", default="-O2")
    ap.add_argument("--isa", choices=tuple(ISA_FEATURES), default="im",
                    help="guest ISA: RV64IM (admitted) or a candidate Zba/Zbb build")
    ap.add_argument("--zbb-kernel-only", dest="zbb_builtins", action="store_false",
                    help="zbb_binary: use rev8 only in the intx swap kernel (patch 0024), not for every "
                         "__builtin_bswap* (measured 2026-11-02: 4.588 vs 4.582 instr/gas scored; default routes all)")
    ap.add_argument("--isa-audit", default=None,
                    help="rv64-isa-audit binary (src/frontends/riscv/rv64 build); required for --isa zbb_binary")
    ap.add_argument("--secp", choices=("stwo", "evmone"), default="stwo",
                    help="stwo: recover on the admitted secp services; evmone: software reference")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--clean", action="store_true")
    ap.add_argument("--tests", action="store_true",
                    help="build and run the host tests (memory fuzz, secp differential vs evmone)")
    ap.add_argument("--no-stage", action="store_true", help="reuse the staged, patched sources")
    ap.add_argument("--eest", action="store_true",
                    help="EEST conformance build (never deployed): fork and blob schedule from the "
                         "input schema id instead of the mainnet timestamp schedule")
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

    if a.tests and not a.host:
        raise SystemExit("--tests needs --host")
    pinned = fetch(cache)
    work = out / "work"
    if a.clean and work.exists():
        shutil.rmtree(work)
    staged = {"applied_patches": "reused"}
    if not (a.no_stage and (work / "src").exists()):
        staged = stage(cache, work)
    src = work / "src"

    v3_groups = a.v3_set.split(",")
    for svc in v3_groups:
        if svc not in ("sha", "arith", "mem", "keccak", "umem", "jumpdest", "bn", "bls"):
            raise SystemExit(f"unknown admitted v3 service group {svc!r}")
    if "bn" in v3_groups and "arith" not in v3_groups:
        raise SystemExit("v3 service group 'bn' needs 'arith' (plain-form Fq)")
    if "umem" in v3_groups and "mem" not in v3_groups:
        raise SystemExit("v3 service group 'umem' needs 'mem'")
    v3_tag = "v3" if sorted(v3_groups) == ["arith", "bls", "bn", "jumpdest", "keccak", "mem", "sha", "umem"] else "v3-" + "-".join(v3_groups)
    variant = ("host" if a.host else a.profile if a.profile == "admitted" else v3_tag if a.profile == "v3"
               else "candidate-" + a.candidate_set.replace(",", "-"))
    isa_suffix = "" if a.isa == "im" or a.host else "-" + a.isa
    if a.candidate_jumpdest:
        isa_suffix = "-cjd" + isa_suffix
    variant += isa_suffix
    mcpu = "-mcpu=generic_rv64+m" + ISA_FEATURES[a.isa]
    guest_target = [mcpu if f.startswith("-mcpu=") else f for f in GUEST_TARGET]
    defines = list(DEFINES)
    if "zbb" in a.isa and not a.host:
        # ziskethone's default for Zbb targets (zeg/bswap.hpp): plain __builtin_bswap64 -> rev8.
        defines.append("-DZEG_BSWAP_BUILTIN")
    if a.isa == "zbb_binary":
        if a.host:
            raise SystemExit("--isa zbb_binary is a guest build")
        if not a.isa_audit:
            raise SystemExit("--isa zbb_binary needs --isa-audit (the ELF must pass the admitted-subset audit)")
        # zeg::bswap64 -> __builtin_bswap64 -> rev8 (forced header); intx swaps via patch 0024.
        defines += ["-DSTWO_ZBB_BINARY", "-include", str(HERE / "glue" / "stwo_zbb_binary.h")]
        if a.zbb_builtins:
            defines += ["-DSTWO_ZBB_BINARY_BUILTINS", "-DZEG_BSWAP_BUILTIN"]
    if a.profile == "v3":
        if a.host:
            raise SystemExit("--profile v3 is a guest build (the host build emulates services only for candidates)")
        defines.append("-DADMITTED_V3")
        for svc in v3_groups:
            defines.append(f"-DADMITTED_{svc.upper()}")
    if a.candidate_jumpdest:
        defines.append("-DCANDIDATE_JUMPDEST")
    if a.eest:
        variant += "-eest"
        defines += ["-DZEG_FORK_FROM_INPUT", "-DSTWO_EEST_FORK_FROM_SCHEMA"]
    if a.profile == "candidate":
        defines.append("-DCANDIDATE_SERVICES")
        for svc in a.candidate_set.split(","):
            if svc not in ("mem", "sha", "arith", "mul", "bn", "bls", "keccak"):
                raise SystemExit(f"unknown candidate service group {svc!r}")
            defines.append(f"-DCANDIDATE_{svc.upper()}")
    if a.host:
        defines.append("-DSTWO_HOST")
        cxx = [a.opt, "-g", *COMMON_CXX, *defines, *includes(src)]
        cc = [a.opt, "-g", *defines]
    else:
        cxx = [*guest_target, a.opt, *COMMON_CXX, *GUEST_EXTRA, *defines, *includes(src)]
        cc = [*guest_target, *defines]
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
        exe = out / ("client-evmone-host-eest" if a.eest else "client-evmone-host")
        run(["zig", "c++", a.opt, "-g", *objs, "-o", exe])
    else:
        tag = a.profile if a.profile == "admitted" or (a.profile == "candidate" and a.candidate_set == "mem,sha,arith") else \
            v3_tag if a.profile == "v3" else "candidate-" + a.candidate_set.replace(",", "-")
        exe = out / f"client-evmone-{tag}{isa_suffix}{'-eest' if a.eest else ''}.elf"
        run(["zig", "c++", "-target", "riscv64-freestanding-none", mcpu, "-nostdlib",
             "-static", "-T", LINKER_SCRIPT, "-Wl,--gc-sections", "-Wl,-z,stack-size=0", *objs, "-o", exe])
    audit = None
    if a.isa_audit and not a.host:
        r = subprocess.run([a.isa_audit, "--require-subset", str(exe)], capture_output=True, text=True)
        audit = json.loads(r.stdout.strip().splitlines()[-1])
        print("isa audit:", json.dumps(audit))
        if r.returncode != 0:
            raise SystemExit(f"{exe}: ISA audit failed (non-admitted encodings present)")
        if a.isa in ("im",) and audit["zbb_binary"] != 0:
            raise SystemExit(f"{exe}: RV64IM build contains Zbb encodings")
    if a.tests:
        run_tests(src, out, work, a)
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    manifest = {
        "schema": "stwo.rv64.client-evmone-build.v1",
        "variant": variant,
        "artifact": str(exe),
        "sha256": digest,
        "zig_version": zig_version,
        "optimization": a.opt,
        "secp": a.secp,
        "isa": a.isa,
        "isa_audit": audit,
        "defines": defines,
        "pinned_sources": pinned,
        "staging": staged,
        "linker_script": str(LINKER_SCRIPT.relative_to(REPO_ROOT)),
    }
    (out / f"build-manifest-{variant}.json").write_text(json.dumps(manifest, indent=1))
    print(f"{exe} sha256={digest}")


if __name__ == "__main__":
    main()
