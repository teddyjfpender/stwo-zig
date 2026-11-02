#!/usr/bin/env python3
"""Summarise a `bench.py run --ls-histogram` result into the load/store width and
alignment histogram plus the per-opcode-class instruction mix.

  python3 -I autoresearch/guest_efficiency/notes/ls_width_histogram.py RESULT.json OUT.json
"""
import json
import sys

WIDTH = {"LB": 1, "LBU": 1, "SB": 1, "LH": 2, "LHU": 2, "SH": 2, "LW": 4, "LWU": 4, "SW": 4, "LD": 8, "SD": 8}
NAME = {1: "byte", 2: "half", 4: "word", 8: "doubleword"}
SIGNED = {"LB": "signed", "LH": "signed", "LW": "signed", "LD": "n/a",
          "LBU": "unsigned", "LHU": "unsigned", "LWU": "unsigned"}
CLASSES = {
    "alu_reg": "ADD SUB AND OR XOR ADDW SUBW".split(),
    "alu_imm": "ADDI ANDI ORI XORI ADDIW".split(),
    "shift": "SLL SRL SRA SLLI SRLI SRAI SLLW SRLW SRAW SLLIW SRLIW SRAIW".split(),
    "compare": "SLT SLTU SLTI SLTIU".split(),
    "upper_imm": "LUI AUIPC".split(),
    "branch": "BEQ BNE BLT BGE BLTU BGEU".split(),
    "jump": "JAL JALR".split(),
    "mul": "MUL MULH MULHSU MULHU MULW".split(),
    "div_rem": "DIV DIVU REM REMU DIVW DIVUW REMW REMUW".split(),
    "load": "LB LH LW LD LBU LHU LWU".split(),
    "store": "SB SH SW SD".split(),
    "ecall_service": ["ECALL"],
    "system_other": ["FENCE", "EBREAK"],
}
OP_CLASS = {op: c for c, ops in CLASSES.items() for op in ops}


def frac(a, b):
    return round(a / b, 6) if b else None


def summarise(rows):
    ops, off, mis, sp, rdz = {}, {}, {}, {}, {}
    instr = gas = 0
    for r in rows:
        instr += r["instructions"]
        gas += r["gas_used"]
        for k, v in r["opcode_counts"].items():
            ops[k] = ops.get(k, 0) + v
        h = r["ls_histogram"]
        for i, n in enumerate(h["opcode_names"]):
            off.setdefault(n, [0] * 8)
            off[n] = [a + b for a, b in zip(off[n], h["word_offset"][i])]
            mis[n] = mis.get(n, 0) + h["misaligned"][i]
            sp[n] = sp.get(n, 0) + h["sp_based"][i]
            rdz[n] = rdz.get(n, 0) + h["rd_zero"][i]
    unknown = sorted(set(ops) - set(OP_CLASS))
    if unknown:
        raise SystemExit(f"unclassified opcodes: {unknown}")
    if sum(ops.values()) != instr:
        raise SystemExit("opcode counts do not sum to instructions")
    loads = sum(ops.get(o, 0) for o in CLASSES["load"])
    stores = sum(ops.get(o, 0) for o in CLASSES["store"])
    ls = loads + stores
    for n, o in off.items():  # the histogram must cover every retired LS row
        if sum(o) != ops.get(n, 0):
            raise SystemExit(f"histogram/opcode mismatch for {n}")
    per_op = {}
    for n in WIDTH:
        c = ops.get(n, 0)
        per_op[n] = {"count": c, "kind": "store" if n[0] == "S" else "load", "width_bytes": WIDTH[n],
                     "signedness": SIGNED.get(n, "n/a"), "fraction_of_ls": frac(c, ls),
                     "naturally_aligned": c - mis[n], "misaligned": mis[n],
                     "aligned_8byte_address": off[n][0], "offset_in_dword": off[n],
                     "sp_based": sp[n], "sp_based_fraction": frac(sp[n], c)}
        if n[0] == "L":
            per_op[n]["rd_x0"] = rdz[n]
    width = {}
    for w, name in NAME.items():
        for kind, lst in (("load", CLASSES["load"]), ("store", CLASSES["store"])):
            c = sum(ops.get(o, 0) for o in lst if WIDTH[o] == w)
            width.setdefault(name, {})[kind] = c
        width[name]["total"] = width[name]["load"] + width[name]["store"]
        width[name]["fraction_of_ls"] = frac(width[name]["total"], ls)
    aligned_dword = ops.get("LD", 0) + ops.get("SD", 0)
    any_8_aligned_addr = sum(off[n][0] for n in WIDTH)
    mix = {c: {"count": (v := sum(ops.get(o, 0) for o in lst)), "fraction": frac(v, instr), "per_gas": frac(v, gas)}
           for c, lst in CLASSES.items()}
    return {
        "instructions": instr, "gas_used": gas, "loads": loads, "stores": stores, "load_store": ls,
        "ls_fraction_of_instructions": frac(ls, instr),
        "aligned_8byte_ls": aligned_dword,
        "aligned_8byte_fraction_of_ls": frac(aligned_dword, ls),
        "aligned_8byte_loads_fraction_of_loads": frac(ops.get("LD", 0), loads),
        "aligned_8byte_stores_fraction_of_stores": frac(ops.get("SD", 0), stores),
        "subword_ls_fraction_of_ls": frac(ls - aligned_dword, ls),
        "any_width_at_8byte_aligned_address_fraction_of_ls": frac(any_8_aligned_addr, ls),
        "misaligned_ls": sum(mis.values()),
        "sp_based_fraction_of_ls": frac(sum(sp.values()), ls),
        "sp_based_fraction_of_dword_ls": frac(sp["LD"] + sp["SD"], aligned_dword),
        "by_width": width, "by_opcode": per_op,
        "class_mix": mix,
        "opcode_counts": dict(sorted(ops.items(), key=lambda kv: -kv[1])),
    }


def main():
    res = json.load(open(sys.argv[1]))
    rows = [r for r in res["rows"] if r.get("instructions")]
    if len(rows) != len(res["rows"]) or not all(r.get("output_matches_expected") for r in rows):
        raise SystemExit("every block must complete with exact output")
    out = {
        "schema": "stwo.rv64.ls-width-histogram.v1",
        "elf": res["elf"], "executor_sha256": res["executor_sha256"],
        "execution_profile": sorted({r["execution_profile"] for r in rows}),
        "client": res.get("client"), "guards_ok": res["ok"],
        "note": ("All RV64 loads/stores in this machine are naturally aligned: memory.zig traps any "
                 "address % width != 0 (misaligned counts are measured, not assumed). 'aligned 8-byte' = LD/SD; "
                 "offset_in_dword[k] counts accesses at address & 7 == k. Bulk memcpy/memset/memcmp and other "
                 "ECALL services are not LS rows and are excluded. rv64-keccak-and-memory-cost-reduction.md (M1/M2) "
                 "assumed a 60% aligned-dword share."),
        "all_blocks": summarise(rows),
        "scored": summarise([r for r in rows if r["set"] == "scored"]),
        "holdout": summarise([r for r in rows if r["set"] == "holdout"]),
        "per_block": [{"block": r["block"], "set": r["set"],
                       **{k: v for k, v in summarise([r]).items()
                          if k in ("instructions", "load_store", "ls_fraction_of_instructions",
                                   "aligned_8byte_fraction_of_ls", "sp_based_fraction_of_ls")}}
                      for r in rows],
    }
    with open(sys.argv[2], "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    a = out["all_blocks"]
    print(f"LS {a['load_store']:,} = {a['ls_fraction_of_instructions']:.3f} of {a['instructions']:,} instructions")
    print(f"aligned 8-byte (LD/SD) {a['aligned_8byte_fraction_of_ls']:.4f} of LS; misaligned {a['misaligned_ls']}")
    for k, v in a["by_width"].items():
        print(f"  {k:10s} load {v['load']:>13,} store {v['store']:>13,} frac {v['fraction_of_ls']}")
    for k, v in a["class_mix"].items():
        print(f"  {k:14s} {v['fraction']:.4f}  {v['per_gas']:.4f}/gas")


if __name__ == "__main__":
    main()
