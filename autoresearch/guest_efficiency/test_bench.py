#!/usr/bin/env python3
"""Unit tests for the guest-efficiency harness (stdlib only, no builds, no execution).

Run from the repository root:
    python3 -I autoresearch/guest_efficiency/test_bench.py
"""
import copy
import importlib.util
import json
import struct
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("bench", HERE / "bench.py")
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)

BASKET = json.loads((HERE / "basket.json").read_text())
CAL = json.loads((HERE / "calibration.json").read_text())
TARGETS = json.loads((HERE / "targets.json").read_text())
SCOPE = json.loads((HERE / "scope.json").read_text())
POLICY = TARGETS["guard_policy"]


def good_rows(scale=1.0, holdout_scale=None):
    rows = []
    for b in BASKET["blocks"]:
        s = scale if b["set"] == "scored" else (holdout_scale if holdout_scale is not None else scale)
        rows.append({"block": b["block"], "set": b["set"], "gas_used": b["gas_used"], "status": "completed",
                     "verified_output": True, "output_matches_expected": True,
                     "execution_profile": "ethereum_services_v2",
                     "instructions": int(b["baseline"]["instructions"] * s),
                     "keccak_f_calls": b["baseline"]["keccak_f_calls"],
                     "secp_add_calls": b["baseline"]["secp_add_calls"],
                     "secp_double_calls": b["baseline"]["secp_double_calls"]})
    return rows


def by_name(gs):
    return {g["guard"]: g for g in gs}


class Calibration(unittest.TestCase):
    def test_reproduces_calibration_block(self):
        r = CAL["calibration_run"]
        bits = bench.committed_bits(CAL, r["instructions"], r["keccak_f_calls"], r["secp_add_calls"], r["secp_double_calls"])
        self.assertAlmostEqual(bits / r["reproduces_lde_bits_excl_fixed"], 1.0, places=9)

    def test_matches_published_comparison(self):
        # committed-work-comparison-v1.json: 1,225.46 Gbit witness LDE bits excl. fixed on block 24,628,607.
        r = CAL["calibration_run"]
        bits = bench.committed_bits(CAL, r["instructions"], r["keccak_f_calls"], r["secp_add_calls"], r["secp_double_calls"])
        self.assertAlmostEqual(bits / 1e9, 1225.46, delta=0.01)

    def test_frozen(self):
        self.assertTrue(CAL["frozen"])


class Basket(unittest.TestCase):
    def test_shape(self):
        blocks = BASKET["blocks"]
        self.assertEqual(len(blocks), 15)
        self.assertEqual(len({b["block"] for b in blocks}), 15)
        self.assertEqual(sum(b["set"] == "holdout" for b in blocks), 3)
        for b in blocks:
            self.assertRegex(b["fixture"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(b["canonical_input"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(b["gas_used"], 0)
            self.assertLessEqual(b["canonical_input"]["bytes"], 16 * 1024 * 1024 - 4)

    def test_baseline_matches_published_aggregate(self):
        m = bench.aggregate(bench.baseline_rows(BASKET, "all"), CAL)
        self.assertEqual(m["gas_used"], 445399117)
        published = sum(b["comparison_receipt_instructions"] for b in BASKET["blocks"])
        self.assertEqual(published, 5995766734)  # guest-steps-comparison-v1.json
        self.assertLess(abs(m["instructions"] / published - 1), 1e-4)  # rebuild drift under 0.01%
        self.assertAlmostEqual(m["instructions_per_gas"], 13.462, places=2)

    def test_targets_baseline_consistent(self):
        m = bench.aggregate(bench.baseline_rows(BASKET, "scored"), CAL)
        self.assertAlmostEqual(m["instructions_per_gas"], TARGETS["baseline"]["scored"]["instructions_per_gas"], places=9)
        self.assertAlmostEqual(m["committed_bits_per_gas"], TARGETS["baseline"]["scored"]["committed_bits_per_gas"], places=3)


class Aggregate(unittest.TestCase):
    def test_gas_weighted_not_mean_of_ratios(self):
        rows = [{"gas_used": 1, "instructions": 10}, {"gas_used": 9, "instructions": 9}]
        m = bench.aggregate(rows, CAL)
        self.assertAlmostEqual(m["instructions_per_gas"], 1.9)

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            bench.aggregate([], CAL)


class Guards(unittest.TestCase):
    def test_baseline_passes(self):
        gs = bench.guards(BASKET, good_rows(), "all", POLICY)
        self.assertTrue(all(g["ok"] for g in gs), gs)

    def test_missing_block_fails(self):
        gs = by_name(bench.guards(BASKET, good_rows()[1:], "all", POLICY))
        self.assertFalse(gs["G1_complete_basket"]["ok"])

    def test_wrong_output_fails(self):
        rows = good_rows()
        rows[3]["verified_output"] = False
        self.assertFalse(by_name(bench.guards(BASKET, rows, "all", POLICY))["G2_exact_output"]["ok"])
        rows = good_rows()
        rows[2]["status"] = "error"
        self.assertFalse(by_name(bench.guards(BASKET, rows, "all", POLICY))["G2_exact_output"]["ok"])

    def test_nondeterminism_fails(self):
        rows = good_rows()
        rows[0]["determinism_ok"] = False
        self.assertFalse(by_name(bench.guards(BASKET, rows, "all", POLICY))["G3_determinism"]["ok"])

    def test_per_block_regression_fails(self):
        rows = good_rows(0.7)
        rows[5]["instructions"] = int(BASKET["blocks"][5]["baseline"]["instructions"] * 1.05)
        self.assertFalse(by_name(bench.guards(BASKET, rows, "all", POLICY))["G4_per_block_regression"]["ok"])

    def test_small_regression_within_limit_passes(self):
        rows = good_rows(1.0)
        rows[5]["instructions"] = int(BASKET["blocks"][5]["baseline"]["instructions"] * 1.01)
        self.assertTrue(by_name(bench.guards(BASKET, rows, "all", POLICY))["G4_per_block_regression"]["ok"])

    def test_overfit_to_scored_fails_holdout(self):
        gs = by_name(bench.guards(BASKET, good_rows(0.6, holdout_scale=0.95), "all", POLICY))
        self.assertFalse(gs["G5_holdout_generalises"]["ok"])

    def test_generalising_improvement_passes(self):
        gs = by_name(bench.guards(BASKET, good_rows(0.6, holdout_scale=0.7), "all", POLICY))
        self.assertTrue(gs["G5_holdout_generalises"]["ok"])

    def test_holdout_regression_fails(self):
        gs = by_name(bench.guards(BASKET, good_rows(1.0, holdout_scale=1.01), "all", POLICY))
        self.assertFalse(gs["G5_holdout_generalises"]["ok"])

    def test_scored_only_run_cannot_claim_holdout(self):
        rows = [r for r in good_rows() if r["set"] == "scored"]
        gs = by_name(bench.guards(BASKET, rows, "scored", POLICY))
        self.assertTrue(gs["G5_holdout_generalises"]["ok"])  # not applicable for scored-only iterate runs
        gs = by_name(bench.guards(BASKET, rows, "all", POLICY))
        self.assertFalse(gs["G1_complete_basket"]["ok"])

    def test_unknown_profile_fails(self):
        rows = good_rows()
        rows[0]["execution_profile"] = "ethereum_services_v3"
        self.assertFalse(by_name(bench.guards(BASKET, rows, "all", POLICY))["G6_execution_profile"]["ok"])


class Candidates(unittest.TestCase):
    def test_candidate_cost_added(self):
        cal = copy.deepcopy(CAL)
        cal["candidate_services"] = {"memcpy": {"cells_per_call": 100.0, "cells_per_byte": 2.0}}
        base = bench.committed_bits(cal, 1000, 0, 0, 0)
        more = bench.committed_bits(cal, 1000, 0, 0, 0, {"memcpy": {"calls": 3, "bytes": 50}})
        c = cal["coefficients"]
        self.assertAlmostEqual(more - base, c["bits_per_cell_at_lde"] * 400 * (1 + c["composition_fraction"]))

    def test_unknown_candidate_rejected(self):
        with self.assertRaises(ValueError):
            bench.committed_bits(CAL, 1, 0, 0, 0, {"teleport": {"calls": 1}})

    def test_candidate_profile_allowed_but_flagged(self):
        rows = good_rows()
        for r in rows:
            r["execution_profile"] = "ethereum_services_v3_candidate"
        self.assertTrue(by_name(bench.guards(BASKET, rows, "all", POLICY))["G6_execution_profile"]["ok"])
        self.assertNotIn("ethereum_services_v3_candidate", POLICY["allowed_execution_profiles"])


class Levels(unittest.TestCase):
    def test_levels(self):
        lv = TARGETS["levels"]
        self.assertIsNone(bench.level(13.9, lv, "instructions_per_gas"))
        self.assertEqual(bench.level(6.0, lv, "instructions_per_gas"), "L2_zisk_reth_parity")
        self.assertEqual(bench.level(1.0, lv, "instructions_per_gas"), "L4_supersede")

    def test_levels_monotone(self):
        for key in ("instructions_per_gas", "committed_bits_per_gas"):
            vals = [l[key] for l in TARGETS["levels"]]
            self.assertEqual(vals, sorted(vals, reverse=True), key)


class Scope(unittest.TestCase):
    G = "autoresearch/benchmarks/guest_runtime/ethereum/rv64/"

    def test_guest_code_editable(self):
        r = bench.match_scope([self.G + "src/main.rs", self.G + "vendor/revm-interpreter/src/x.rs"], SCOPE)
        self.assertTrue(r["ok"])
        self.assertIn("A_guest_code", r["tiers"])

    def test_locked_paths(self):
        for p in ["src/frontends/riscv/rv64/ethereum_contract.zig", self.G + "linker.ld", self.G + "service_abi/src/lib.rs",
                  "autoresearch/guest_efficiency/bench.py", "autoresearch/guest_efficiency/basket.json",
                  "autoresearch/benchmarks/guest_runtime/projection/src/main.rs", "vectors/reports/x.json"]:
            self.assertFalse(bench.match_scope([p], SCOPE)["ok"], p)

    def test_unlisted_path_rejected(self):
        self.assertFalse(bench.match_scope(["README.md"], SCOPE)["ok"])

    def test_candidate_executor_override(self):
        r = bench.match_scope(["src/frontends/riscv/rv64/ethereum_services/candidate_services.zig",
                               "src/frontends/riscv/rv64/ethereum_execution.zig"], SCOPE)
        self.assertTrue(r["ok"], r)
        self.assertIn("E_candidate_executor", r["tiers"])
        self.assertFalse(bench.match_scope(["src/frontends/riscv/rv64/ethereum_services/session.zig"], SCOPE)["ok"])
        self.assertFalse(bench.match_scope(["src/frontends/riscv/rv64/execution_profile.zig"], SCOPE)["ok"])

    def test_dependency_tier(self):
        r = bench.match_scope([self.G + "services/Cargo.lock"], SCOPE)
        self.assertTrue(r["ok"])
        self.assertIn("B_dependency_change", r["tiers"])


def tiny_elf(symbols):
    """Build a minimal little-endian ELF64 with a .symtab and .strtab."""
    strtab = b"\0"
    entries = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    for name, value, size, typ in symbols:
        off = len(strtab)
        strtab += name.encode() + b"\0"
        entries.append(struct.pack("<IBBHQQ", off, typ, 0, 1, value, size))
    symtab = b"".join(entries)
    data_off = 64
    str_off = data_off
    sym_off = str_off + len(strtab)
    sh_off = sym_off + len(symtab)
    sh_off += (-sh_off) % 8
    sections = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0),
                struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, sym_off, len(symtab), 1, 1, 8, 24)]
    header = bytearray(64)
    header[:16] = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH", header, 16, 2, 243, 1, 0, 0, sh_off, 0, 64, 0, 0, 64, len(sections), 1)
    body = bytes(header) + strtab + symtab
    body += bytes(sh_off - len(body))
    return body + b"".join(sections)


class Elf(unittest.TestCase):
    def test_symbols_and_functions(self):
        syms = [("__" + n, 0x1000 * (i + 1), 0, 0) for i, n in enumerate(bench.SYMBOLS)]
        syms += [("memcpy", 0x400, 0x40, 2), ("revm_interpreter_step", 0x440, 0x100, 2)]
        abi, funcs = bench.elf_symbols(tiny_elf(syms))
        self.assertEqual(abi["input_start"], 0x1000)
        self.assertEqual([f[2] for f in funcs], ["memcpy", "revm_interpreter_step"])

    def test_missing_abi_symbol(self):
        with self.assertRaises(ValueError):
            bench.elf_symbols(tiny_elf([("__input_start", 1, 0, 0)]))

    def test_attribution_buckets(self):
        funcs = [(0x400, 0x440, "memcpy"), (0x440, 0x540, "revm_interpreter_step")]
        prof = {"start": 0x400, "counts": [5] * 16 + [7] * 64 + [0, 3]}
        res = bench.attribute(prof, 5 * 16 + 7 * 64 + 3, funcs)
        self.assertEqual(res["buckets"]["mem_alloc"]["instructions"], 80)
        self.assertEqual(res["buckets"]["evm_interpreter"]["instructions"], 448)
        self.assertEqual(res["buckets"]["unattributed"]["instructions"], 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
