#!/usr/bin/env python3
"""rv64-m6-native/v2 (v2-strict) adversarial tamper suite: fresh, separate,
cache-disabled, GPU-disabled receivers (same argv/env shape as nv03.py and
rv64_m5_negative_corpus.py). Each case hard-links a copy of the accepted
26235156 v2-strict proof directory, applies ONE coherent mutation (bundle.json
rewritten with matching file hashes so WideBundleFileChanged cannot be what
rejects) and runs the receiver with STWO_RV64_NATIVE_VERSION=m6-native-v2-strict.
Never touches a GPU (CUDA_VISIBLE_DEVICES="", PCS helper /bin/false).
  python3 nv_tamper.py OUT_DIR [CASE_ID,...]
"""
import concurrent.futures as cf
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

R = Path("/workspace/m3/runs/m6-native-format")
RECV = "/workspace/m3/build/m6-native-format/b4/rv64-word16-ethereum-recursion-receiver"
RUN = R / "26235156-2gpu-v2s-r5"
PROOF = RUN / "case/batch/trial-0/26235156/proof"
DONOR = R / "24628607-2gpu-v2s-r6/case/batch/trial-0/24628607/proof"
GEO = ["cpu_log", "alu_log", "alu_tail_log", "binary_log", "binary_tail_log", "shift_log", "shift_tail_log", "jalr_log",
       "division_log", "multiplication_log", "ls_log", "ls_tail_log", "boundary_log", "initial_log", "terminal_log"]
BR = ["keccak", "add", "double", "sha256", "arith256_mod", "bn254_g1_add", "bn254_g1_double", "bn254_fp2_mul",
      "bls12_381_fp2_mul", "arith384_mont", "bls12_381_g1_add", "bls12_381_g1_double"]
BULK = ["desc", "copy", "set", "ucopy", "cdesc", "cmp", "jdesc", "jscan", "jtab"]
OPTIONAL_GEO = {"alu_tail_log", "binary_tail_log", "shift_tail_log", "ls_tail_log", "initial_log", "terminal_log"}
CPU_MIDDLE_RUNG0 = [22, 18, 17, 17, 15, 16, 14, 16, 11, 16, 18, 17, 5, 5, 5, 14, 13, 12, 8, 11, 0, 0, 0, 0, 0, 0, 0, 14, 17, 17, 17, 8, 9, 6, 13, 14, 11, 12, 20, 19, 0]


def write(path, data):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)  # never write through a hard link


def load(p):
    return json.loads((p / "bundle.json").read_text())


def save(p, b):
    write(p / "bundle.json", json.dumps(b).encode())


def sha_list(path):
    return list(hashlib.sha256(path.read_bytes()).digest())


def apply_vector(decl, v):
    g, b = decl["geometry"], decl["bridges"]
    for i, n in enumerate(GEO):
        g[n] = (v[i] or None) if n in OPTIONAL_GEO else v[i]
    for i, n in enumerate(BR):
        if v[15 + i]:
            b[n] = v[15 + i]
        else:
            b.pop(n, None)
    bulk = {n: v[27 + i] for i, n in enumerate(BULK) if v[27 + i]}
    if bulk:
        b["bulk"] = bulk
    else:
        b.pop("bulk", None)
    sponge = {n: v[36 + i] for i, n in enumerate(("call", "perm")) if v[36 + i]}
    if sponge:
        b["sponge"] = sponge
    else:
        b.pop("sponge", None)
    for key, idx in (("ls_dword", 38), ("ls_dword_tail", 39), ("zbb", 40)):
        if v[idx]:
            b[key] = v[idx]
        else:
            b.pop(key, None)


def m_relabel_log(p):
    b = load(p); b["cpus"][1]["declaration"]["bridges"]["sha256"] = 9; save(p, b)


def m_rung_substitute(p):
    b = load(p)
    apply_vector(b["cpus"][1]["declaration"], CPU_MIDDLE_RUNG0)
    del b["cpus"][1]["claims"][14:16]  # arith384_mont (present-empty) leaves the declaration
    save(p, b)


def m_omit_division(p):
    b = load(p); b["cpus"][3]["declaration"]["geometry"]["omit_empty_division"] = True; save(p, b)


def m_layout_flag(p):
    b = load(p); b["cpus"][0]["declaration"]["geometry"]["cpu_compact_decode"] = False; save(p, b)


def m_activate_empty(p):
    b = load(p)
    b["cpus"][0]["request"]["arith256_mod_calls"] = 1
    b["cpus"][1]["request"]["arith256_mod_calls"] -= 1
    save(p, b)


def m_empty_claim(p):
    b = load(p); b["cpus"][0]["claims"][12] = list(b["cpus"][0]["claims"][10]); save(p, b)


def m_empty_tail_claim(p):
    b = load(p); b["cpus"][1]["claims"][3] = list(b["cpus"][1]["claims"][0]); save(p, b)


def m_drop_present_empty(p):
    """Make cpu-0's present-empty arith256_mod ABSENT (old-rule admissible) and drop its zero claims."""
    b = load(p)
    b["cpus"][0]["declaration"]["bridges"].pop("arith256_mod")
    del b["cpus"][0]["claims"][12:14]
    save(p, b)


def m_cross_block_cpu0(p):
    """Same class (cpu_first rung 0, vkhash 35369d4f) and same initial state in both blocks: replay 607's cpu-0."""
    b, d = load(p), load(DONOR)
    write(p / "cpu-0.bin", (DONOR / "cpu-0.bin").read_bytes())
    entry = json.loads(json.dumps(d["cpus"][0]))
    b["cpus"][0] = entry
    save(p, b)


def m_swap_same_class(p):
    """cpu-1 <-> cpu-2 (both cpu_middle rung 1): files + bundle entries, epochs kept at their ordinals."""
    b = load(p)
    c1, c2 = b["cpus"][1], b["cpus"][2]
    for key in ("epoch", "memory_epoch"):
        c1["request"][key], c2["request"][key] = c2["request"][key], c1["request"][key]
    b["cpus"][1], b["cpus"][2] = c2, c1
    f1, f2 = (p / "cpu-1.bin").read_bytes(), (p / "cpu-2.bin").read_bytes()
    write(p / "cpu-1.bin", f2); write(p / "cpu-2.bin", f1)
    save(p, b)


def m_swap_truth_same_class(p):
    """truth-1 <-> truth-2 (keccak rung 0, same vkhash) proofs + claims; spans (declarations) kept."""
    b = load(p)
    t1, t2 = b["truths"][1], b["truths"][2]
    for key in ("claims", "proof"):
        t1[key], t2[key] = t2[key], t1[key]
    f1, f2 = (p / "truth-1.bin").read_bytes(), (p / "truth-2.bin").read_bytes()
    write(p / "truth-1.bin", f2); write(p / "truth-2.bin", f1)
    save(p, b)


def m_truth_relabel(p):
    """truth-1 keccak log 14 -> 16 (another rung of the same family): strict class changes, proof must fail."""
    b = load(p); b["truths"][1]["declaration"]["logs"][0] = 16; save(p, b)


CPU_MIDDLE_RUNG2 = [22, 20, 18, 18, 17, 18, 15, 17, 11, 17, 19, 17, 5, 5, 5, 15, 15, 14, 16, 16, 11, 12, 15, 15, 16, 0, 0, 15, 17, 17, 18, 10, 10, 6, 13, 14, 13, 15, 20, 19, 0]


def m_rung_substitute_admissible(p):
    """cpu-1 (cpu_middle rung 1) relabelled as rung 2, whose capacities hold its counts: strict label valid,
    four curve bridges become present-empty (zero claims inserted in roster order), keys built for rung 2."""
    b = load(p)
    apply_vector(b["cpus"][1]["declaration"], CPU_MIDDLE_RUNG2)
    b["cpus"][1]["claims"][14:14] = [[0] * 8 for _ in range(8)]
    save(p, b)


def m_cross_block_cpu0_spans(p):
    """NVT09 plus truth spans re-aligned to the donor's cpu-0 call counts (so span admission passes)."""
    b, d = load(p), load(DONOR)
    old = b["cpus"][0]["request"]["calls"] + [b["cpus"][0]["request"].get("sha256_calls", 0), b["cpus"][0]["request"].get("arith256_mod_calls", 0)]
    write(p / "cpu-0.bin", (DONOR / "cpu-0.bin").read_bytes())
    b["cpus"][0] = json.loads(json.dumps(d["cpus"][0]))
    new = b["cpus"][0]["request"]["calls"] + [b["cpus"][0]["request"].get("sha256_calls", 0), b["cpus"][0]["request"].get("arith256_mod_calls", 0)]
    fam = ["keccak", "add", "double", "sha256", "arith256_mod"]
    delta = {f: n - o for f, o, n in zip(fam, old, new)}
    seen = set()
    for t in b["truths"]:
        f = t["declaration"]["family"]
        if f not in delta:
            continue
        if f in seen:
            t["declaration"]["first_id"] += delta[f]
        else:
            t["declaration"]["calls"] += delta[f]
            seen.add(f)
    save(p, b)


CASES = [
    ("NVT00-control", "accept", "unmodified v2-strict proof", None),
    ("NVT01-relabel-log", "reject", "cpu-1 sha256 log 8->9 (no rung equals it)", m_relabel_log),
    ("NVT02-rung-substitute", "reject", "cpu-1 declaration := cpu_middle rung 0 vector (strict-valid label, other VK)", m_rung_substitute),
    ("NVT03-omit-division", "reject", "cpu-3 omit_empty_division := true (0 division requests)", m_omit_division),
    ("NVT04-layout-flag", "reject", "cpu-0 cpu_compact_decode := false (rung vector unchanged, flags word changes)", m_layout_flag),
    ("NVT05-activate-empty", "reject", "present-empty arith256_mod in cpu-0 claims 1 call (cpu-1 12->11, truth span kept)", m_activate_empty),
    ("NVT06-empty-claim", "reject", "nonzero global RAM claim on cpu-0's present-empty arith256_mod", m_empty_claim),
    ("NVT07-empty-tail-claim", "reject", "nonzero global RAM claim on cpu-1's present-empty LS32 tail", m_empty_tail_claim),
    ("NVT08-drop-present-empty", "reject", "cpu-0 arith256_mod made absent (0 calls) + its zero claims dropped", m_drop_present_empty),
    ("NVT09-cross-block-same-class", "reject", "24628607 cpu-0 (same class + vkhash + initial state) replayed as 26235156 cpu-0", m_cross_block_cpu0),
    ("NVT10-swap-same-class", "reject", "cpu-1<->cpu-2 (same class) coherently, epochs fixed to ordinals", m_swap_same_class),
    ("NVT11-swap-truth-same-class", "reject", "truth-1<->truth-2 proofs+claims (same keccak class), spans kept", m_swap_truth_same_class),
    ("NVT02b-rung-substitute-admissible", "reject", "cpu-1 cpu_middle rung 1 -> rung 2 (counts fit; 4 curve bridges present-empty)", m_rung_substitute_admissible),
    ("NVT09b-cross-block-same-class-spans", "reject", "NVT09 + truth spans re-aligned to the donor counts", m_cross_block_cpu0_spans),
    ("NVT12-truth-relabel", "reject", "truth-1 keccak log 14->16 (other strict rung)", m_truth_relabel),
]


def run_case(case, out):
    cid, want, what, mutate = case
    d = out / cid
    if d.exists():
        shutil.rmtree(d)
    proof = d / "proof"
    shutil.copytree(PROOF, proof, copy_function=os.link)
    if mutate:
        mutate(proof)
    req = json.loads(sorted(RUN.glob("receiver-*/receiver-request.json"))[0].read_text())
    req["output_directory"] = str(d / "capture")
    (d / "request.json").write_text(json.dumps(req))
    env = dict(os.environ)
    env.pop("STWO_ZIG_RV64_SETUP_CACHE", None)
    env.pop("STWO_RV64_CANON_RUNGS", None)
    env["STWO_RV64_NATIVE_VERSION"] = "m6-native-v2-strict"
    env.update({"CUDA_VISIBLE_DEVICES": "", "STWO_RV64_GPU_PCS_HELPER": "/bin/false", "STWO_RV64_FOLD_CLASS_CACHE": "0"})
    argv = ["nice", "-n", "10", RECV, "--security-profile", "conjectured128_b2_q108_p20_fold4", "verify-recursion-candidate",
            str(d / "request.json"), str(proof), "12884901888", "34359738368"]
    t = time.time()
    p = subprocess.run(argv, env=env, capture_output=True, text=True, cwd="/workspace/m3/src/m6-native-format", timeout=1800)
    (d / "stdout").write_text(p.stdout)
    (d / "stderr").write_text(p.stderr[-200000:])
    err = [l for l in p.stderr.splitlines() if l.startswith("error")][:2]
    accepted = '"accepted": true' in p.stdout or '"accepted":true' in p.stdout
    crash = p.returncode < 0 or "panic" in p.stderr or "Segmentation" in p.stderr
    if want == "accept":
        passed = p.returncode == 0 and accepted
    else:
        passed = p.returncode > 0 and not crash and not accepted
    shutil.rmtree(proof)
    shutil.rmtree(d / "capture", ignore_errors=True)
    row = {"id": cid, "expect": want, "what": what, "exit_code": p.returncode, "accepted": accepted, "crash": crash,
           "first_error": err, "wall_s": round(time.time() - t, 1), "passed": passed}
    print(json.dumps(row), flush=True)
    return row


def main():
    out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
    wanted = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else None
    cases = [c for c in CASES if wanted is None or c[0] in wanted]
    load1 = os.getloadavg()[0]
    t = time.time()
    with cf.ThreadPoolExecutor(3) as pool:
        rows = list(pool.map(lambda c: run_case(c, out), cases))
    receipt = {"schema": "rv64-m6-native-v2-tamper/v1", "measured": True, "block": 26235156, "proof": str(PROOF), "donor": str(DONOR),
               "receiver": RECV, "receiver_sha256": hashlib.sha256(Path(RECV).read_bytes()).hexdigest(),
               "receiver_env": {"STWO_RV64_NATIVE_VERSION": "m6-native-v2-strict", "CUDA_VISIBLE_DEVICES": "", "STWO_RV64_FOLD_CLASS_CACHE": "0"},
               "loadavg_1m_start": load1, "loadavg_1m_end": os.getloadavg()[0], "wall_s": round(time.time() - t, 1),
               "ran": len(rows), "passed": sum(r["passed"] for r in rows),
               "unexpected_accepts": [r["id"] for r in rows if r["accepted"] and r["expect"] == "reject"],
               "crashes": [r["id"] for r in rows if r["crash"]], "cases": rows}
    (out / "tamper.json").write_text(json.dumps(receipt, indent=1))
    print(json.dumps({k: receipt[k] for k in ("ran", "passed", "unexpected_accepts", "crashes", "wall_s")}))


if __name__ == "__main__":
    main()
