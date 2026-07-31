"""TRACKS §3.3: every frontend track declares its benchmark contract.

The function basket is the answer to "which functions does this track score,
and do they exercise the whole system?" — a validated declaration whose row
statuses derive from the vehicle that holds each row, so the published list
can never drift from what actually runs. These tests pin both the validator
(error paths) and the committed content (the four frontend groups declare
10-15 whole-pipeline functions each, and micro-tests stay out).
"""

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))

from stwo_perf import feed as feed_mod, manifest as manifest_mod
from stwo_perf.manifest import ManifestError

REPO_ROOT = Path(__file__).resolve().parents[2]

FRONTEND_GROUPS = ("riscv", "riscv_metal", "cairo_cpu", "cairo_metal")

# The coverage islands: ISA micro-tests and opcode/builtin sweep programs.
# They may stay scored workloads (smoke floor) but must never be presented
# as benchmark functions — that is the PCS-island mistake the native boards
# already paid for.
COVERAGE_ONLY = {
    "riscv": {
        "riscv_alu_test", "riscv_branch_fib", "riscv_declared_region",
        "riscv_jal_jalr", "riscv_mem_ls", "riscv_shift_logic",
        "riscv_multi_shard_addi",
    },
    "riscv_metal": {"mriscv_alu_test"},
    "cairo_cpu": {"cairo_all_opcodes", "cairo_all_builtins"},
    "cairo_metal": {"mcairo_all_opcodes", "mcairo_all_builtins"},
}


def raw_manifest() -> dict:
    return json.loads((REPO_ROOT / "autoresearch" / "MANIFEST.json").read_text())


class CommittedBasketContentTest(unittest.TestCase):
    """The committed manifest carries a quality basket on every frontend group."""

    @classmethod
    def setUpClass(cls):
        cls.m = manifest_mod.load(REPO_ROOT)
        cls.groups = {g.group_id: g for g in cls.m.groups()}

    def test_every_frontend_group_declares_ten_to_fifteen_functions(self):
        for gid in FRONTEND_GROUPS:
            basket = self.groups[gid].function_basket
            with self.subTest(group=gid):
                self.assertTrue(basket, f"{gid} has no function basket")
                count = len(basket["functions"])
                self.assertGreaterEqual(count, 10)
                self.assertLessEqual(count, 15)

    def test_coverage_islands_are_never_basket_functions(self):
        for gid, excluded in COVERAGE_ONLY.items():
            basket = self.groups[gid].function_basket
            rows = {
                rid
                for entry in basket["functions"].values()
                for rid in entry["rows"]
            }
            with self.subTest(group=gid):
                self.assertFalse(rows & excluded)

    def test_metal_lanes_mirror_their_cpu_lane_functions(self):
        # Same computation, different backend: a cross-lane comparison is
        # meaningless unless the function sets line up.
        riscv = set(self.groups["riscv"].function_basket["functions"])
        rmetal = set(self.groups["riscv_metal"].function_basket["functions"])
        self.assertEqual(riscv, rmetal)
        self.assertEqual(
            set(self.groups["cairo_cpu"].function_basket["functions"]),
            set(self.groups["cairo_metal"].function_basket["functions"]),
        )

    def test_feed_derives_a_status_for_every_basket_row(self):
        for gid in FRONTEND_GROUPS:
            view = feed_mod._function_basket_view(self.groups[gid])
            with self.subTest(group=gid):
                self.assertIsNotNone(view)
                for name, entry in view["functions"].items():
                    self.assertTrue(entry["rows"], f"{gid}:{name} has no rows")
                    for rid, row in entry["rows"].items():
                        self.assertIn(
                            row["status"], ("scored", "staged", "pending"),
                            f"{gid}:{name}:{rid}",
                        )

    def test_riscv_basket_spans_scored_and_staged_rows(self):
        view = feed_mod._function_basket_view(self.groups["riscv"])
        statuses = {
            row["status"]
            for entry in view["functions"].values()
            for row in entry["rows"].values()
        }
        self.assertEqual(statuses, {"scored", "staged"})

    def test_blocked_lanes_say_why(self):
        # riscv_metal is blocked on stwo-zig#169; cairo lanes on fixture
        # generation. The pending reasons must carry the actual blocker.
        raw = raw_manifest()["workload_registry"]["groups"]
        rm = raw["riscv_metal"]["workload_provisioning"]["pending"]
        self.assertTrue(all("#169" in e["reason"] for e in rm.values()))
        cc = raw["cairo_cpu"]["workload_provisioning"]["pending"]
        matrix_rows = {k: e for k, e in cc.items() if "source" in e}
        self.assertTrue(matrix_rows)
        self.assertTrue(
            all("cairo-compile" in e["reason"] for e in matrix_rows.values())
        )


class BasketValidatorTest(unittest.TestCase):
    """The declaration cannot lie: every row resolves, counts are bounded."""

    def _raw(self) -> dict:
        return raw_manifest()

    def _basket(self, raw: dict) -> dict:
        return raw["workload_registry"]["groups"]["riscv"]["function_basket"]

    def test_committed_manifest_validates(self):
        manifest_mod._validate(self._raw())

    def test_phantom_row_is_refused(self):
        raw = self._raw()
        self._basket(raw)["functions"]["sha256"]["rows"].append("riscv_ghost")
        with self.assertRaisesRegex(ManifestError, "exactly one of"):
            manifest_mod._validate(raw)

    def test_row_scoring_two_functions_is_refused(self):
        raw = self._raw()
        basket = self._basket(raw)
        basket["functions"]["keccak"]["rows"].append(
            basket["functions"]["sha256"]["rows"][0]
        )
        with self.assertRaisesRegex(ManifestError, "exactly one function"):
            manifest_mod._validate(raw)

    def test_a_thin_basket_is_refused(self):
        raw = self._raw()
        basket = self._basket(raw)
        names = list(basket["functions"])
        for name in names[3:]:
            del basket["functions"][name]
        with self.assertRaisesRegex(ManifestError, "quality basket"):
            manifest_mod._validate(raw)

    def test_an_overgrown_basket_is_refused(self):
        raw = self._raw()
        basket = self._basket(raw)
        for i in range(6):
            basket["functions"][f"padding_{i}"] = {
                "summary": "padding",
                "rows": [f"riscv_padding_{i}"],
            }
            raw["workload_registry"]["groups"]["riscv"]["workloads"][
                f"riscv_padding_{i}"
            ] = {
                "class": "small",
                "args": "bench --elf vectors/riscv_elfs/alu_test.elf "
                        "--backend cpu --protocol functional {admission} "
                        "--warmups {warmups} --samples {samples}",
                "native_unit": "executed instructions",
            }
        with self.assertRaisesRegex(ManifestError, "quality basket"):
            manifest_mod._validate(raw)

    def test_unknown_basket_key_is_refused(self):
        raw = self._raw()
        self._basket(raw)["status"] = "great"
        with self.assertRaisesRegex(ManifestError, "requires exactly"):
            manifest_mod._validate(raw)

    def test_declared_status_is_refused(self):
        # Status is derived, never declared — a declared status is exactly
        # the drift channel this schema exists to close.
        raw = self._raw()
        self._basket(raw)["functions"]["sha256"]["status"] = "scored"
        with self.assertRaisesRegex(ManifestError, "requires exactly"):
            manifest_mod._validate(raw)

    def test_empty_summary_is_refused(self):
        raw = self._raw()
        self._basket(raw)["functions"]["sha256"]["summary"] = "  "
        with self.assertRaisesRegex(ManifestError, "summary must be non-empty"):
            manifest_mod._validate(raw)

    def test_pending_entry_with_mixed_shape_is_refused(self):
        raw = self._raw()
        pending = raw["workload_registry"]["groups"]["riscv_metal"][
            "workload_provisioning"]["pending"]
        entry = copy.deepcopy(pending["mriscv_sieve_primes"])
        entry["vm_steps"] = 5
        pending["mriscv_sieve_primes"] = entry
        with self.assertRaisesRegex(ManifestError, "requires exactly"):
            manifest_mod._validate(raw)


if __name__ == "__main__":
    unittest.main()
