#!/usr/bin/env python3
"""RV64 Ethereum guest-efficiency harness.

Deterministic execution-only measurement of the RV64 Ethereum guest on a pinned
basket of mainnet blocks. The score is exact (instruction counts do not vary
between runs), so no paired timing or ABBA is needed.

Subcommands (run with `python3 -I autoresearch/guest_efficiency/bench.py ...`
from the repository root):

  prepare        fetch + verify ZisK fixtures, project to canonical SSZ, host-validate
  build-guest    build the guest ELF through the existing rv64/build.py
  build-exec     build the execution-only rv64-ethereum-execution tool
  run            execute the basket, apply guards, compute metrics, write a result
  attribute      bucket one block's PC histogram by symbol (where instructions go)
  check-scope    fail if the diff against a base ref leaves the editable paths
  compare        compare a result against the baseline and the targets

Only the Python standard library is used. See README.md for the contract.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import concurrent.futures
import fnmatch
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = ROOT / "autoresearch/benchmarks/guest_runtime"
GUEST = RUNTIME / "ethereum/rv64"
TOOLCHAIN = "nightly-2026-08-08"
SYMBOLS = ("input_start", "input_end", "halt_flag", "output_len", "output_data",
           "output_end", "stack_bottom", "stack_top", "heap_start", "heap_end")
RESULT_SCHEMA = "stwo.rv64.guest-efficiency-result.v1"


def load_json(path: Path):
    return json.loads(Path(path).read_text())


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Pure functions (unit tested in test_bench.py)
# --------------------------------------------------------------------------

def candidate_cells(calibration: dict, candidate_calls: dict | None) -> float:
    """Estimated cells for execution-only candidate services (calibration.json candidate_services).

    candidate_calls maps service name -> {"calls": n, "bytes": b}. Unknown services
    are an error: a candidate must declare its estimated cost before it can score.
    """
    if not candidate_calls:
        return 0.0
    table = calibration.get("candidate_services", {})
    cells = 0.0
    for name, use in candidate_calls.items():
        if name not in table:
            raise ValueError(f"candidate service {name!r} has no cost estimate in calibration.json")
        cost = table[name]
        cells += cost["cells_per_call"] * int(use.get("calls", 0)) + cost.get("cells_per_byte", 0.0) * int(use.get("bytes", 0))
    return cells


# ADMITTED ethereum_services_v3 services: calibration.json admitted_services key ->
# (execution-report call field, execution-report byte field or None[,
#  execution-report permutation field]). The Keccak-256 sponge is costed per
# call (call row) and per permutation (perm row + Keccak-f truth).
ADMITTED_REPORT_FIELDS = {
    "sha256_compress": ("sha256_calls", None),
    "arith256_mod": ("arith256_mod_calls", None),
    "memcpy": ("bulk_memcpy_calls", "bulk_memcpy_bytes"),
    "memset": ("bulk_memset_calls", "bulk_memset_bytes"),
    # memcpy whose source is not 8-aligned (ucopy body rows; bytes = len).
    "memcpy_unaligned": ("bulk_memcpy_unaligned_calls", "bulk_memcpy_unaligned_bytes"),
    # memcmp: bytes = 8 x examined word pairs (the proof's cmp rows), not len.
    "memcmp": ("bulk_memcmp_calls", "bulk_memcmp_bytes"),
    "keccak_sponge": ("keccak_sponge_calls", "keccak_sponge_bytes", "keccak_sponge_permutations"),
    "jumpdest_bitmap": ("jumpdest_calls", "jumpdest_bytes"),
}
# Admitted v3 curve/field services: the execution report's `curve_calls` is one
# call count per op in curves.Op order (Wire35 kinds 5..11).
ADMITTED_CURVE_OPS = ("bn254_g1_add", "bn254_g1_double", "bn254_fp2_mul", "bls12_381_fp2_mul",
                      "arith384_mont", "bls12_381_g1_add", "bls12_381_g1_double")


def admitted_usage(report: dict) -> dict | None:
    """Per-service admitted usage from one execution report (None when no admitted v3 call ran)."""
    out = {}
    for name, (calls_key, bytes_key, *perms_key) in ADMITTED_REPORT_FIELDS.items():
        calls = int(report.get(calls_key) or 0)
        if calls:
            out[name] = {"calls": calls, "bytes": int(report.get(bytes_key) or 0) if bytes_key else 0}
            if perms_key:
                out[name]["permutations"] = int(report.get(perms_key[0]) or 0)
    curve = report.get("curve_calls") or []
    if len(curve) not in (0, len(ADMITTED_CURVE_OPS)):
        raise ValueError(f"curve_calls has {len(curve)} entries, expected {len(ADMITTED_CURVE_OPS)}")
    for name, calls in zip(ADMITTED_CURVE_OPS, curve):
        if int(calls):
            out[name] = {"calls": int(calls), "bytes": 0}
    return out or None


def admitted_cells(calibration: dict, admitted_calls: dict | None) -> float:
    """Measured cells for admitted (provable) v3 services (calibration.json admitted_services)."""
    if not admitted_calls:
        return 0.0
    table = calibration.get("admitted_services", {})
    cells = 0.0
    for name, use in admitted_calls.items():
        if name not in table:
            raise ValueError(f"admitted service {name!r} has no measured cost in calibration.json")
        cost = table[name]
        cells += (cost["cells_per_call"] * int(use.get("calls", 0)) + cost.get("cells_per_byte", 0.0) * int(use.get("bytes", 0))
                  + cost.get("cells_per_permutation", 0.0) * int(use.get("permutations", 0)))
    return cells


V3_PROFILE = "ethereum_services_v3"


def keccak_coefficient(calibration: dict, profile: str | None) -> float:
    """Cells per Keccak-f truth call: the v3 profile proves Keccak-f with the
    throughput-table truth (keccak_cells_per_call_v3); every other profile
    (v2, baseline) keeps the frozen compact coefficient."""
    c = calibration["coefficients"]
    if profile == V3_PROFILE and "keccak_cells_per_call_v3" in c:
        return c["keccak_cells_per_call_v3"]
    return c["keccak_cells_per_call"]


def committed_bits(calibration: dict, instructions: int, keccak: int, secp_add: int, secp_double: int,
                   candidate_calls: dict | None = None, admitted_calls: dict | None = None,
                   profile: str | None = None) -> float:
    """Frozen linear proxy for committed witness bits at the LDE (see calibration.json).

    admitted_calls holds ADMITTED ethereum_services_v3 usage per service
    ({name: {"calls", "bytes"}}, see admitted_usage), costed by the measured
    calibration.json admitted_services table (each entry cites its derivation)."""
    c = calibration["coefficients"]
    cells = (c["cpu_cells_per_instruction"] * instructions
             + keccak_coefficient(calibration, profile) * keccak
             + c["secp_cells_per_call"] * (secp_add + secp_double)
             + candidate_cells(calibration, candidate_calls)
             + admitted_cells(calibration, admitted_calls))
    return c["bits_per_cell_at_lde"] * cells * (1.0 + c["composition_fraction"])


def aggregate(rows: list[dict], calibration: dict) -> dict:
    """Gas-weighted aggregate over completed rows: sum(x) / sum(gas)."""
    gas = sum(r["gas_used"] for r in rows)
    if not rows or gas <= 0:
        raise ValueError("aggregate needs at least one row with positive gas")
    tot = collections.Counter()
    for r in rows:
        for k in ("instructions", "keccak_f_calls", "secp_add_calls", "secp_double_calls", "sha256_calls", "loads", "stores"):
            tot[k] += int(r.get(k) or 0)
    bits = sum(committed_bits(calibration, r["instructions"], r.get("keccak_f_calls", 0),
                              r.get("secp_add_calls", 0), r.get("secp_double_calls", 0),
                              r.get("candidate_service_calls"), r.get("admitted_service_calls"),
                              r.get("execution_profile")) for r in rows)
    return {
        "blocks": len(rows),
        "gas_used": gas,
        "instructions": tot["instructions"],
        "instructions_per_gas": tot["instructions"] / gas,
        "committed_bits_per_gas": bits / gas,
        "committed_bits_per_instruction": bits / tot["instructions"],
        "keccak_f_calls_per_kgas": 1000.0 * tot["keccak_f_calls"] / gas,
        "secp_calls_per_kgas": 1000.0 * (tot["secp_add_calls"] + tot["secp_double_calls"]) / gas,
        "memory_ops_per_gas": (tot["loads"] + tot["stores"]) / gas if (tot["loads"] or tot["stores"]) else None,
    }


def baseline_rows(basket: dict, which: str) -> list[dict]:
    rows = []
    for b in basket["blocks"]:
        if which != "all" and b["set"] != which:
            continue
        rows.append({"block": b["block"], "gas_used": b["gas_used"], **b["baseline"]})
    return rows


def guards(basket: dict, rows: list[dict], which: str, policy: dict) -> list[dict]:
    """Return a list of guard results. Each is {guard, ok, detail}."""
    out = []
    want = [b for b in basket["blocks"] if which == "all" or b["set"] == which]
    by_block = {r["block"]: r for r in rows}
    missing = [b["block"] for b in want if b["block"] not in by_block]
    out.append({"guard": "G1_complete_basket", "ok": not missing, "detail": {"missing": missing}})
    bad = [r["block"] for r in rows if not (r.get("status") == "completed" and r.get("verified_output") is True
                                             and r.get("output_matches_expected") is True)]
    out.append({"guard": "G2_exact_output", "ok": not bad, "detail": {"failed": bad}})
    nondet = [r["block"] for r in rows if r.get("determinism_ok") is False]
    out.append({"guard": "G3_determinism", "ok": not nondet, "detail": {"nondeterministic": nondet}})
    # Per-block regression limit against the frozen baseline.
    limit = policy["per_block_regression_limit"]
    base = {b["block"]: b["baseline"]["instructions"] for b in basket["blocks"]}
    regress = [{"block": r["block"], "ratio": r["instructions"] / base[r["block"]]}
               for r in rows if r.get("instructions") and r["instructions"] > base[r["block"]] * (1 + limit)]
    out.append({"guard": "G4_per_block_regression", "ok": not regress, "detail": {"limit": limit, "regressed": regress}})
    # Holdout anti-overfitting: holdout must improve at least `holdout_share` of the scored improvement.
    sc = [r for r in rows if r.get("set") == "scored" and r.get("instructions")]
    ho = [r for r in rows if r.get("set") == "holdout" and r.get("instructions")]
    if sc and ho:
        def ratio(rs):
            return sum(r["instructions"] for r in rs) / sum(base[r["block"]] for r in rs)
        rs, rh = ratio(sc), ratio(ho)
        gain_s, gain_h = 1 - rs, 1 - rh
        tol = policy["holdout_noise_tolerance"]
        ok = rh <= 1.0 + tol and (gain_s <= tol or gain_h >= policy["holdout_share"] * gain_s)
        out.append({"guard": "G5_holdout_generalises", "ok": ok,
                    "detail": {"scored_ratio": rs, "holdout_ratio": rh, "required_share": policy["holdout_share"]}})
    else:
        out.append({"guard": "G5_holdout_generalises", "ok": which != "all",
                    "detail": "holdout not run" if which != "all" else "missing scored or holdout rows"})
    profiles = {r.get("execution_profile") for r in rows}
    allowed = set(policy["allowed_execution_profiles"]) | set(policy.get("candidate_execution_profiles", []))
    out.append({"guard": "G6_execution_profile", "ok": profiles <= allowed,
                "detail": {"seen": sorted(p for p in profiles if p), "allowed": sorted(allowed)}})
    return out


def level(value: float, levels: list[dict], key: str) -> str | None:
    """Highest target level reached (levels are ordered from easiest to hardest, lower is better)."""
    reached = None
    for lv in levels:
        if value <= lv[key]:
            reached = lv["name"]
    return reached


def match_scope(paths: list[str], scope: dict) -> dict:
    editable = scope["editable"]
    tiers = {}
    violations = []
    overrides = scope.get("editable_despite_lock", {})
    for p in paths:
        hit = next((t for t, gs in overrides.items() if any(fnmatch.fnmatch(p, g) for g in gs)), None)
        if hit is not None:
            tiers.setdefault(hit, []).append(p)
            continue
        if any(fnmatch.fnmatch(p, g) for g in scope["locked"]):
            violations.append(p)
            continue
        hit = None
        for tier, globs in editable.items():
            if any(fnmatch.fnmatch(p, g) for g in globs):
                hit = tier
                break
        if hit is None:
            violations.append(p)
        else:
            tiers.setdefault(hit, []).append(p)
    return {"ok": not violations, "violations": violations, "tiers": tiers}


def elf_symbols(raw: bytes) -> tuple[dict, list[tuple[int, int, str]]]:
    """Return (__abi symbols without leading underscores, sorted [(start, end, name)] for STT_FUNC)."""
    if raw[:4] != b"\x7fELF" or raw[4] != 2 or raw[5] != 1:
        raise ValueError("expected little-endian ELF64")
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    stride, count = struct.unpack_from("<HH", raw, 58)
    secs = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + i * stride) for i in range(count)]
    abi, funcs = {}, []
    for s in secs:
        if s[1] != 2:  # SHT_SYMTAB
            continue
        st = secs[s[6]]
        names = raw[st[4]:st[4] + st[5]]
        for i in range(s[5] // 24):
            no, info, _other, _shndx, value, size = struct.unpack_from("<IBBHQQ", raw, s[4] + i * 24)
            name = names[no:names.index(b"\0", no)].decode(errors="replace")
            if name.startswith("__") and name[2:] in SYMBOLS:
                abi[name[2:]] = value
            if info & 0xF == 2 and size:  # STT_FUNC
                funcs.append((value, value + size, name))
    funcs.sort()
    missing = [k for k in SYMBOLS if k not in abi]
    if missing:
        raise ValueError(f"ELF lacks ABI symbols: {missing}")
    return abi, funcs


BUCKETS = [
    ("keccak_glue", r"keccak|Keccak|sponge|tiny_keccak|sha3"),
    ("secp_ecdsa_glue", r"k256|ecdsa|secp|Secp|ProjectivePoint|AffinePoint|FieldElement|Scalar|elliptic_curve|primeorder|crypto_bigint|recover"),
    ("ssz_statement_sha256", r"sha2|sha256|Sha256"),
    ("other_crypto", r"ripemd|blake|bn254|substrate_bn|bls12|kzg|modexp|aurora|p256"),
    ("evm_interpreter", r"revm_interpreter|revm_handler|revm_context|revm|instructions|Interpreter|evm"),
    ("mpt_rlp", r"zeth_mpt|mpt|trie|Trie|alloy_rlp|rlp|nibble|Nibble"),
    ("mem_alloc", r"^memcpy|^memmove|^memset|^memcmp|^bcmp|compiler_builtins.*mem|alloc|exact_layout|hashbrown|RawVec|BTree"),
    ("ssz_input", r"ssz|Ssz|tree_hash|hash_tree_root"),
]


def attribute(pc_profile: dict, instructions: int, funcs: list[tuple[int, int, str]]) -> dict:
    starts = [f[0] for f in funcs]
    self_counts = collections.Counter()
    unknown = 0
    start = pc_profile["start"]
    for i, c in enumerate(pc_profile["counts"]):
        if not c:
            continue
        pc = start + 4 * i
        j = bisect.bisect_right(starts, pc) - 1
        best = None
        k = j
        while k >= 0 and k > j - 64:
            a, b, n = funcs[k]
            if a <= pc < b and (best is None or b - a < best[1] - best[0]):
                best = funcs[k]
            k -= 1
        if best:
            self_counts[best[2]] += c
        else:
            unknown += c
    buckets = collections.Counter()
    for name, c in self_counts.items():
        for bucket, rx in BUCKETS:
            if re.search(rx, name):
                buckets[bucket] += c
                break
        else:
            buckets["other"] += c
    buckets["unattributed"] = unknown + int(pc_profile.get("outside", 0))
    return {
        "instructions": instructions,
        "buckets": {k: {"instructions": v, "fraction": round(v / instructions, 4)} for k, v in buckets.most_common()},
        "top_functions": [{"function": n[:200], "self_instructions": c} for n, c in self_counts.most_common(60)],
    }


# --------------------------------------------------------------------------
# Effectful commands
# --------------------------------------------------------------------------

def run(cmd, cwd=None, **kw):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], cwd=cwd, check=True, **kw)


def cmd_prepare(a):
    basket = load_json(a.basket)
    cache = Path(a.cache).resolve()
    (cache / "fixtures").mkdir(parents=True, exist_ok=True)
    common = ["--locked", "--release", "-j", str(a.jobs)]
    for pkg in ("projection", "host_validation"):
        run(["cargo", "+" + TOOLCHAIN, "build", *common], RUNTIME / pkg)
    projection = RUNTIME / "projection/target/release/stwo-ethereum-input-projection"
    validator = RUNTIME / "host_validation/target/release/stwo-ethereum-host-validation"
    for b in basket["blocks"]:
        fx = cache / "fixtures" / b["fixture"]["name"]
        if not fx.exists():
            if not a.fetch:
                raise SystemExit(f"missing fixture {fx}; rerun with --fetch or copy it in")
            url = (f"https://raw.githubusercontent.com/0xPolygonHermez/zisk-eth-client/"
                   f"{basket['source']['commit']}/{b['fixture']['path']}")
            with urllib.request.urlopen(url, timeout=120) as resp:
                data = resp.read(64 * 1024 * 1024 + 1)
            if sha256(data) != b["fixture"]["sha256"]:
                raise SystemExit(f"fixture hash mismatch for block {b['block']}")
            fx.write_bytes(data)
        if sha256(fx.read_bytes()) != b["fixture"]["sha256"]:
            raise SystemExit(f"fixture hash mismatch for block {b['block']}")
        out = cache / "blocks" / str(b["block"])
        if not (out / "canonical-input.ssz").exists():
            out.parent.mkdir(parents=True, exist_ok=True)
            run([projection, "--general", fx, out], ROOT)
        canon = (out / "canonical-input.ssz").read_bytes()
        if sha256(canon) != b["canonical_input"]["sha256"] or len(canon) != b["canonical_input"]["bytes"]:
            raise SystemExit(f"canonical input mismatch for block {b['block']}")
        norm = load_json(out / "normalization-v1.json")
        if norm["new_payload_request_root"] != b["new_payload_request_root"]:
            raise SystemExit(f"request root mismatch for block {b['block']}")
        expected = out / "expected-output.bin"
        if not expected.exists():
            cand = out / "host-validation-candidate.bin"
            cand.unlink(missing_ok=True)
            run([validator, "--general", out / "canonical-input.ssz", cand], ROOT)
            proj = norm["projection"]
            want = (bytes.fromhex(b["new_payload_request_root"][2:]) + b"\x01"
                    + int(proj["block"]["chain_id"]).to_bytes(8, "little")
                    + int(proj["schema_id"]).to_bytes(2, "little"))
            got = cand.read_bytes()
            if got != want:
                raise SystemExit(f"host validator output disagrees with projection for block {b['block']}")
            cand.replace(expected)
        print(f"block {b['block']}: ready ({len(canon)} bytes)")


def cmd_build_guest(a):
    out = Path(a.out).resolve()
    run([sys.executable, "-I", GUEST / "build.py", "--artifacts", out, "--guest-profile", a.profile,
         "--input-window-mib", str(a.input_window_mib), "--jobs", str(a.jobs)], ROOT)


def cmd_build_exec(a):
    out = Path(a.out).resolve()
    run(["zig", "build", "-Doptimize=ReleaseFast", "--prefix", out], ROOT / "src/frontends/riscv/rv64")
    print(out / "bin/rv64-ethereum-execution")


def execute_block(b: dict, elf: Path, raw: bytes, abi: dict, executor: Path, cache: Path, out: Path,
                  basket: dict, keep_profile: bool, repeat: int, profile: str | None = None,
                  adapter: list[str] | None = None) -> dict:
    blk = cache / "blocks" / str(b["block"])
    inp = blk / "canonical-input.ssz"
    expected = (blk / "expected-output.bin").read_bytes()
    if adapter:
        # Client-specific private input. The adapter runs outside the guest (it is
        # untrusted prover-side preparation); the guest must verify everything it
        # relies on, and the output is still checked against the host-validated
        # expected output derived from the canonical input.
        adapted = out / "blocks" / str(b["block"]) / "adapted-input.bin"
        adapted.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([*adapter, str(inp), str(adapted)], capture_output=True, text=True)
        if r.returncode != 0:
            return {"block": b["block"], "set": b["set"], "gas_used": b["gas_used"], "status": "error",
                    "error": "input adapter failed: " + ((r.stderr.strip().splitlines() or ["?"])[-1])}
        inp = adapted
    data = inp.read_bytes()
    cfg = {"elf": str(elf), "elf_sha256": sha256(raw), "input": str(inp), "input_sha256": sha256(data),
           "expected_output": expected.hex(), "symbols": abi, **basket["execution"]}
    if profile:
        cfg["execution_profile"] = profile
    d = out / "blocks" / str(b["block"])
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.json").write_text(json.dumps(cfg, indent=1))
    reports = []
    for i in range(repeat):
        r = subprocess.run([str(executor), str(d / "config.json")], capture_output=True, text=True)
        if r.returncode != 0:
            (d / "stderr.txt").write_text(r.stderr)
            return {"block": b["block"], "set": b["set"], "gas_used": b["gas_used"], "status": "error",
                    "error": (r.stderr.strip().splitlines() or ["?"])[-1]}
        reports.append(json.loads(r.stdout))
    e = reports[0]
    if keep_profile:
        (d / "execution.json").write_text(json.dumps(e))
    row = {"block": b["block"], "set": b["set"], "gas_used": b["gas_used"],
           "status": e.get("status"), "verified_output": e.get("verified_output"),
           "output_matches_expected": e.get("verified_output") is True and cfg["expected_output"] == expected.hex(),
           "execution_profile": cfg["execution_profile"],
           "instructions": e.get("instructions"), "keccak_f_calls": e.get("keccak_calls", 0),
           "secp_add_calls": e.get("secp_add_calls", 0), "secp_double_calls": e.get("secp_double_calls", 0),
           "sha256_calls": e.get("sha256_calls", 0),
           "loads": e.get("loads"), "stores": e.get("stores"),
           "candidate_service_calls": e.get("candidate_service_calls") or None,
           "admitted_service_calls": admitted_usage(e)}
    if repeat > 1:
        keys = ("instructions", "keccak_calls", "secp_add_calls", "secp_double_calls", "sha256_calls", "arith256_mod_calls",
                "bulk_memcpy_calls", "bulk_memcpy_bytes", "bulk_memset_calls", "bulk_memset_bytes",
                "bulk_memcpy_unaligned_calls", "bulk_memcpy_unaligned_bytes", "bulk_memcmp_calls", "bulk_memcmp_bytes",
                "keccak_sponge_calls", "keccak_sponge_bytes", "keccak_sponge_permutations",
                "jumpdest_calls", "jumpdest_bytes", "curve_calls", "verified_output")
        row["determinism_ok"] = all(all(x.get(k) == e.get(k) for k in keys) for x in reports[1:])
    row["instructions_per_gas"] = row["instructions"] / b["gas_used"] if row["instructions"] else None
    return row


def cmd_run(a):
    basket = load_json(a.basket)
    cal = load_json(HERE / "calibration.json")
    policy = load_json(HERE / "targets.json")["guard_policy"]
    elf = Path(a.elf).resolve()
    raw = elf.read_bytes()
    abi, _ = elf_symbols(raw)
    cache = Path(a.cache).resolve()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    blocks = [b for b in basket["blocks"] if a.set == "all" or b["set"] == a.set]
    det = {basket["blocks"][0]["block"]} if a.determinism else set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
        futs = [pool.submit(execute_block, b, elf, raw, abi, Path(a.executor).resolve(), cache, out, basket,
                            a.keep_profiles, 2 if b["block"] in det else 1, a.profile,
                            a.input_adapter.split() if a.input_adapter else None) for b in blocks]
        rows = [f.result() for f in futs]
    rows.sort(key=lambda r: r["block"])
    ok_rows = [r for r in rows if r.get("instructions")]
    result = {"schema": RESULT_SCHEMA, "set": a.set, "elf": {"path": str(elf), "sha256": sha256(raw)},
              "executor_sha256": sha256(Path(a.executor).read_bytes()), "rows": rows,
              "guards": guards(basket, rows, a.set, policy)}
    for name in ("scored", "holdout", "all"):
        rs = [r for r in ok_rows if name == "all" or r["set"] == name]
        if rs:
            result.setdefault("metrics", {})[name] = aggregate(rs, cal)
    result["ok"] = all(g["ok"] for g in result["guards"])
    # Only admitted profiles (services the prover can prove today) are promotable.
    # Candidate profiles measure the value of a proposed service before prover work.
    used = {r.get("execution_profile") for r in rows}
    result["promotable"] = result["ok"] and used <= set(policy["allowed_execution_profiles"])
    result["client"] = a.client
    if a.input_adapter:
        exe = a.input_adapter.split()[0]
        result["input_adapter"] = {"command": a.input_adapter,
                                   "sha256": sha256(Path(exe).read_bytes()) if Path(exe).exists() else None}
    (out / "result.json").write_text(json.dumps(result, indent=1))
    summarize(result, basket, cal)
    if not result["ok"]:
        raise SystemExit(2)


def summarize(result: dict, basket: dict, cal: dict):
    targets = load_json(HERE / "targets.json")
    for g in result["guards"]:
        print(f"{'PASS' if g['ok'] else 'FAIL'} {g['guard']}")
    if "promotable" in result and not result["promotable"]:
        print("NOTE result uses a candidate (not yet provable) profile or failed a guard: not promotable")
    for name, m in result.get("metrics", {}).items():
        base = aggregate(baseline_rows(basket, name), cal)
        print(f"[{name}] instructions/gas {m['instructions_per_gas']:.3f} (baseline {base['instructions_per_gas']:.3f}, "
              f"x{base['instructions_per_gas'] / m['instructions_per_gas']:.3f})  committed bits/gas "
              f"{m['committed_bits_per_gas']:,.0f} (baseline {base['committed_bits_per_gas']:,.0f})")
        if name == "scored":
            print("  level (instructions/gas):", level(m["instructions_per_gas"], targets["levels"], "instructions_per_gas"))
            print("  level (committed bits/gas):", level(m["committed_bits_per_gas"], targets["levels"], "committed_bits_per_gas"))


def cmd_compare(a):
    basket = load_json(a.basket)
    cal = load_json(HERE / "calibration.json")
    summarize(load_json(a.result), basket, cal)


def cmd_attribute(a):
    raw = Path(a.elf).read_bytes()
    _, funcs = elf_symbols(raw)
    e = load_json(a.execution)
    if "pc_profile" not in e:
        raise SystemExit("execution report has no pc_profile (run with --keep-profiles)")
    res = attribute(e["pc_profile"], e["instructions"], funcs)
    Path(a.out).write_text(json.dumps(res, indent=1))
    for k, v in res["buckets"].items():
        print(f"{k:22s} {v['instructions']:>14,} {v['fraction']:.3f}")


def cmd_check_scope(a):
    scope = load_json(HERE / "scope.json")
    names = subprocess.run(["git", "diff", "--name-only", f"{a.base}...HEAD"], cwd=ROOT, check=True,
                           capture_output=True, text=True).stdout.split()
    if a.include_worktree:
        names += subprocess.run(["git", "diff", "--name-only", "HEAD"], cwd=ROOT, check=True,
                                capture_output=True, text=True).stdout.split()
        names += subprocess.run(["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, check=True,
                                capture_output=True, text=True).stdout.split()
    res = match_scope(sorted(set(names)), scope)
    print(json.dumps(res, indent=1))
    if not res["ok"]:
        raise SystemExit(3)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    basket_default = HERE / "basket.json"

    s = sub.add_parser("prepare")
    s.add_argument("--cache", required=True)
    s.add_argument("--basket", default=basket_default)
    s.add_argument("--fetch", action="store_true", help="download missing fixtures from the pinned commit")
    s.add_argument("--jobs", type=int, default=2)
    s.set_defaults(fn=cmd_prepare)

    s = sub.add_parser("build-guest")
    s.add_argument("--out", required=True)
    s.add_argument("--profile", default="ethereum-services-v2-lean")
    s.add_argument("--input-window-mib", type=int, choices=(4, 16), default=16)
    s.add_argument("--jobs", type=int, default=2)
    s.set_defaults(fn=cmd_build_guest)

    s = sub.add_parser("build-exec")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_build_exec)

    s = sub.add_parser("run")
    s.add_argument("--elf", required=True)
    s.add_argument("--executor", required=True)
    s.add_argument("--cache", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--basket", default=basket_default)
    s.add_argument("--set", choices=("scored", "holdout", "all"), default="all")
    s.add_argument("--jobs", type=int, default=4)
    s.add_argument("--keep-profiles", action="store_true")
    s.add_argument("--no-determinism", dest="determinism", action="store_false")
    s.add_argument("--profile", default=None,
                   help="execution profile override (admitted: ethereum_services_v2; candidate: see targets.json)")
    s.add_argument("--client", default="rust-reth", help="free-form client label recorded in the result")
    s.add_argument("--input-adapter", default=None,
                   help="command run as `CMD canonical-input.ssz OUT` to produce a client-specific private input; "
                        "the output is still checked against the host-validated expected output")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("compare")
    s.add_argument("--result", required=True)
    s.add_argument("--basket", default=basket_default)
    s.set_defaults(fn=cmd_compare)

    s = sub.add_parser("attribute")
    s.add_argument("--elf", required=True)
    s.add_argument("--execution", required=True, help="blocks/<n>/execution.json from run --keep-profiles")
    s.add_argument("--out", required=True)
    s.set_defaults(fn=cmd_attribute)

    s = sub.add_parser("check-scope")
    s.add_argument("--base", required=True)
    s.add_argument("--include-worktree", action="store_true")
    s.set_defaults(fn=cmd_check_scope)

    a = p.parse_args(argv)
    if getattr(a, "jobs", 1) < 1:
        p.error("--jobs must be positive")
    a.fn(a)


if __name__ == "__main__":
    main()
