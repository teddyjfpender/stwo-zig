#!/usr/bin/env python3
"""Layout-tier exact padded LS cells: LS32 only vs LS32 + LS-D64 (head/tail).

Reproduces the planner rule of word16_global_execution/ethereum/plan.zig
(`ladder(count, reserve=1)`, one inactive terminal row per instance) for the
LS32 instances and for the LS-D64 instances, and charges every physical row
its committed MAIN+INTER width (LS32 70+32 = 102, LS-D64 39+28 = 67). Fixed
columns, CPU, ROM and range tables do not change (the U16/U8 tables are fixed
2^16/2^8; their multiplicities change, not their size).

Inputs: the complete-block report for the per-proof RAM event counts (exact),
and an LD/SD share of LS events. The share is per block from the
ls-width-histogram note (all LS of the block); per-proof shares are not
measured, so the same share is applied to every proof and a sensitivity
range is reported.

  python3 -I autoresearch/guest_efficiency/notes/ls_dword_cells.py \
      vectors/reports/rv64-ethereum-20261101/evmone-v3-block-24628607-v1.json \
      0.778869 4.060 [OUT.json]
"""
import json
import math
import sys

LS32 = 70 + 32
DWORD = 39 + 28
BITS_PER_CELL = 62 * (1 + 0.045135955755284445)  # calibration.json coefficients


def ladder(count, reserve):
    full = max(5, math.ceil(math.log2(max(32, count + reserve))))
    if full > 22:
        raise SystemExit("EthereumInstanceCapacityExceeded")
    if full <= 5:
        return [full]
    head = full - 1
    capacity = (1 << head) - reserve
    assert count > capacity
    tail = max(5, math.ceil(math.log2(max(32, count - capacity + reserve))))
    if (1 << head) + (1 << tail) >= (1 << full):
        return [full]
    return [head, tail]


def rows(logs):
    return sum(1 << l for l in logs)


def proof(events, share):
    dword = round(events * share)
    general = events - dword
    before = ladder(events, 1)
    after_general = ladder(general, 1)
    after_dword = ladder(dword, 1) if dword else []
    return {
        "ls_events": events,
        "dword_events": dword,
        "ls32_only": {"logs": before, "rows": rows(before), "cells": LS32 * rows(before)},
        "ls32": {"logs": after_general, "rows": rows(after_general), "cells": LS32 * rows(after_general)},
        "ls_dword": {"logs": after_dword, "rows": rows(after_dword), "cells": DWORD * rows(after_dword)},
    }


def block(report, share, instr_per_gas):
    active = report["cost"]["active"]
    instructions = report["guest"]["instructions_to_terminal"]
    proofs = [proof(a["ram_events"], share) for a in active]
    before = sum(p["ls32_only"]["cells"] for p in proofs)
    after = sum(p["ls32"]["cells"] + p["ls_dword"]["cells"] for p in proofs)
    events = sum(p["ls_events"] for p in proofs)
    saved = (before - after) / instructions
    return {
        "dword_share": share,
        "instructions": instructions,
        "cpu_proofs": len(proofs),
        "ls_events": events,
        "ls_cells_before": before,
        "ls_cells_after": after,
        "ls_cells_per_instruction_before": before / instructions,
        "ls_cells_per_instruction_after": after / instructions,
        "ls_cells_per_access_before": before / events,
        "ls_cells_per_access_after": after / events,
        "saved_cells_per_instruction": saved,
        "saved_bits_per_instruction": saved * BITS_PER_CELL,
        "saved_bits_per_gas": saved * BITS_PER_CELL * instr_per_gas,
        "proofs": proofs,
    }


def main():
    report = json.load(open(sys.argv[1]))
    share = float(sys.argv[2])
    instr_per_gas = float(sys.argv[3])
    out = {
        "schema": "stwo.rv64.ls-dword-cells.v1",
        "scope": "layout-tier exact padded LS cells under the plan.zig ladder rule; per-proof RAM events exact from the block report, LD/SD share per block (assumed uniform over proofs); fixed trees excluded",
        "widths": {"ls32": LS32, "ls_dword": DWORD},
        "central": block(report, share, instr_per_gas),
        "sensitivity": [block(report, s, instr_per_gas) for s in (share - 0.03, share + 0.03)],
    }
    for p in out["sensitivity"]:
        del p["proofs"]
    text = json.dumps(out, indent=1)
    if len(sys.argv) > 4:
        open(sys.argv[4], "w").write(text + "\n")
    c = out["central"]
    print(f"LS cells/instr {c['ls_cells_per_instruction_before']:.2f} -> {c['ls_cells_per_instruction_after']:.2f} "
          f"(per access {c['ls_cells_per_access_before']:.1f} -> {c['ls_cells_per_access_after']:.1f}); "
          f"saved {c['saved_cells_per_instruction']:.2f} cells/instr = {c['saved_bits_per_gas']:.0f} bits/gas at {instr_per_gas} instr/gas")
    for s in out["sensitivity"]:
        print(f"  share {s['dword_share']:.3f}: saved {s['saved_cells_per_instruction']:.2f} cells/instr, {s['saved_bits_per_gas']:.0f} bits/gas")


if __name__ == "__main__":
    main()
