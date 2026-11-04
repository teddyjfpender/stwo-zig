#!/usr/bin/env python3
"""rv64-m6-native/v2 executable reference (stream native-format): version identity and v2 class structures.

Extends scripts/rv64_m5_canon_native_ref.py (same H(tag, words) rule) with the two v2 tags and writes the golden vectors
vectors/rv64-m6/native-v2-vectors.json that `corpus NV01 ... golden` pins byte for byte in Zig:
  version_v2(mode) = H("rv64-m6-native-chi-chain/v2", [2, 10, 3, R, 32, 1, mode])
  structure_v2(f, r) = H("rv64-m6-native-structure/v2", [f, r, n, (id, log)* (present components, id ascending), flags])
for every CPU rung of src/.../ethereum/canon_native_rungs.zig with the production v3 layout flags (0x0E) and every truth rung
(ids 0, 1 = (log, aux), flags 0). Python 3 standard library only.

  python3 scripts/rv64_m6_native_v2_ref.py [--out vectors/rv64-m6/native-v2-vectors.json]
"""
import argparse, hashlib, importlib.util, json, re, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("ref", Path(__file__).with_name("rv64_m5_canon_native_ref.py"))
ref = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ref)
RUNGS_ZIG = ROOT / "src/integrations/riscv_cpu/word16_global_execution/ethereum/canon_native_rungs.zig"
V2_TAGS = {"version_v2": "rv64-m6-native-chi-chain/v2", "structure_v2": "rv64-m6-native-structure/v2"}
FAMILY_IDS = {"cpu_first": 0, "cpu_middle": 1, "cpu_last": 2, "cpu_single": 3, "truth_keccak": 16, "truth_add": 17, "truth_double": 18,
              "truth_sha256": 19, "truth_arith256_mod": 20, "truth_bn254_g1_add": 21, "truth_bn254_g1_double": 22, "truth_bn254_fp2_mul": 23,
              "truth_bls12_381_fp2_mul": 24, "truth_arith384_mont": 25, "truth_bls12_381_g1_add": 26, "truth_bls12_381_g1_double": 27}
PRODUCTION_FLAGS = 0x0E  # bits 1-3: cpu_fused_tail, cpu_u8_pairs, cpu_compact_decode (Plan.CpuLayout.forGkrProfile v3, measured in the v2 bundles); bit0 omit_empty_division never under v2


def H2(name, words):
    return hashlib.blake2s(hashlib.blake2s(V2_TAGS[name].encode()).digest() + ref.le(words)).digest()


def version_v2(mode, rungs=4):
    return H2("version_v2", [2, ref.LOCAL_RELATIONS, ref.GLOBAL_RELATIONS, rungs, 32, 1, mode])


def structure_v2(family, rung, logs_by_id, flags, keep_zero=False):
    """CPU: present components only (log != 0); truth: both (log, aux) words always (keep_zero), as v1 does."""
    items = sorted((i, l) for i, l in logs_by_id.items() if l or keep_zero)
    words = [family, rung, len(items)]
    for i, l in items:
        words += [i, l]
    return H2("structure_v2", words + [flags])


def parse_rungs():
    text = RUNGS_ZIG.read_text()
    cpu, truth = [], []
    for m in re.finditer(r"\.family = \.(cpu_\w+), \.rungs = &\[_\]C\.CpuVector\{(.*?)\} \}", text, re.S):
        vecs = [[int(x) for x in v.split(",") if x.strip()] for v in re.findall(r"\.\{([^}]*)\}", m.group(2))]
        cpu.append((m.group(1), vecs))
    for m in re.finditer(r"\.family = \.(truth_\w+), \.aux = (\d+), \.logs = &\.\{([^}]*)\}", text):
        truth.append((m.group(1), int(m.group(2)), [int(x) for x in m.group(3).split(",") if x.strip()]))
    return cpu, truth


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "vectors/rv64-m6/native-v2-vectors.json"))
    a = ap.parse_args()
    cpu, truth = parse_rungs()
    out = {"schema": "rv64-m6-native-v2-vectors/v1", "tags": {k: hashlib.blake2s(v.encode()).digest().hex() for k, v in V2_TAGS.items()},
           "version_v2_strict": version_v2(0).hex(), "version_v2_gkr": version_v2(1).hex(), "flags_production": PRODUCTION_FLAGS,
           "cpu": [], "truth": []}
    for fam, vecs in cpu:
        for r, v in enumerate(vecs):
            assert len(v) == 41, (fam, r, len(v))
            out["cpu"].append({"family": FAMILY_IDS[fam], "rung": r, "structure_v2": structure_v2(FAMILY_IDS[fam], r, dict(enumerate(v)), PRODUCTION_FLAGS).hex()})
    for fam, aux, logs in truth:
        for r, l in enumerate(logs):
            out["truth"].append({"family": FAMILY_IDS[fam], "aux": aux, "rung": r, "structure_v2": structure_v2(FAMILY_IDS[fam], r, {0: l, 1: aux}, 0, keep_zero=True).hex()})
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({"written": a.out, "cpu": len(out["cpu"]), "truth": len(out["truth"]), "version_v2_strict": out["version_v2_strict"]}))


if __name__ == "__main__":
    main()
