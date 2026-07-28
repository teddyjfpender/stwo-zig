import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from scripts import riscv_sail_oracle as oracle
from scripts.riscv_operand_classes_lib import audit, classes, emit, encoding, session

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "riscv_operand_classes.py"


def pinned_workspace_binary() -> Path:
    return oracle.DEFAULT_WORKSPACE / oracle.SAIL_BINARY_IN_WORKSPACE


def obs(op, **overrides) -> classes.Obs:
    base = dict(
        op=op, rs1=0, rs2=0, imm=0, rd_idx=10, rs1_idx=6, rs2_idx=7,
        pc=0x1_0000, next_pc=0x1_0004, mem_addr=0, mem_rmask=0, mem_wmask=0,
        mem_rdata=0,
    )
    base.update(overrides)
    return classes.Obs(**base)


class EncodingTests(unittest.TestCase):
    """Golden words cross-checked against constants the repository already
    trusts: the guest fixture's prologue/epilogue and the shift soundness
    guest, all of which execute in anger elsewhere."""

    def test_known_words_from_committed_fixtures(self) -> None:
        self.assertEqual(0x0070_0513, encoding.op_imm("addi", 10, 0, 7))
        self.assertEqual(0x0010_00B7, encoding.lui(1, 0x100))
        self.assertEqual(0x0002_2283, encoding.load("lw", 5, 4, 0))
        self.assertEqual(0x0020_A223, encoding.store("sw", 1, 2, 4))
        self.assertEqual(0x0062_D533, encoding.op("srl", 10, 5, 6))
        self.assertEqual(0x4062_D5B3, encoding.op("sra", 11, 5, 6))
        self.assertEqual(0x0000_006F, encoding.jal(0, 0))

    def test_decode_inverts_every_case_body_word(self) -> None:
        for case in classes.all_cases():
            for word in case.body:
                decoded = encoding.decode(word)
                self.assertIsNotNone(decoded, f"{case.name}: 0x{word:08x}")
            under_test = encoding.decode(case.body[case.under_test])
            self.assertEqual(case.op, under_test["op"], case.name)

    def test_materialize_composes_exactly_over_awkward_values(self) -> None:
        # The +0x800 carry split must be exact over all of u32; these hit
        # the sign-absorption edges where a naive split is off by 0x1000.
        for value in (0, 1, 0x7FF, 0x800, 0x801, 0xFFF, 0x1000, 0x7FFF_FFFF,
                      0x8000_0000, 0xFFFF_F800, 0xFFFF_FFFF, 0x001F_FC00):
            words = encoding.materialize(6, value)
            state = 0
            for word in words:
                decoded = encoding.decode(word)
                if decoded["op"] == "lui":
                    state = decoded["imm"] & 0xFFFF_FFFF
                else:
                    state = (state + decoded["imm"]) & 0xFFFF_FFFF
            self.assertEqual(value, state, f"materialize({value:#x})")


class EnumerationTests(unittest.TestCase):
    def test_enumeration_is_valid_and_substantial(self) -> None:
        cases = classes.all_cases()
        classes.validate_cases(cases)
        self.assertGreaterEqual(len(cases), 250)
        pairs = {(case.op, case.tag) for case in cases}
        self.assertGreaterEqual(len(pairs), 260)
        for case in cases:
            self.assertIn(emit.group_of(case.op), classes.GROUPS)

    def test_validation_rejects_fixture_register_violations(self) -> None:
        # x1 belongs to the guest fixture's epilogue; a body writing it
        # would corrupt the halt sequence, so the lint must refuse.
        bad = classes.CaseSpec(
            name="bad/writes_x1", op="addi", tag="imm_zero",
            body=(encoding.op_imm("addi", 1, 0, 0),), under_test=0,
        )
        with self.assertRaises(classes.CaseValidationError):
            classes.validate_cases([bad])

    def test_validation_rejects_reads_of_undefined_registers(self) -> None:
        bad = classes.CaseSpec(
            name="bad/undefined_read", op="add", tag="zero_operand",
            body=(encoding.op("add", 10, 6, 7),), under_test=0,
        )
        with self.assertRaises(classes.CaseValidationError):
            classes.validate_cases([bad])

    def test_predicates_decide_the_classes_they_name(self) -> None:
        self.assertTrue(classes.PREDICATES["carry_ripple"](
            obs("add", rs1=0x00FF_FFFF, rs2=1)))
        self.assertFalse(classes.PREDICATES["carry_ripple"](
            obs("add", rs1=0x00FF_FFFE, rs2=1)))
        self.assertTrue(classes.PREDICATES["cmp_signed_unsigned_disagree"](
            obs("sltu", rs1=0x8000_0000, rs2=1)))
        self.assertFalse(classes.PREDICATES["cmp_signed_unsigned_disagree"](
            obs("sltu", rs1=2, rs2=1)))
        self.assertTrue(classes.PREDICATES["div_scan_limb1"](
            obs("divu", rs1=2 * 0x0101_0101 + 0x0101_00FF, rs2=0x0101_0101)))
        self.assertTrue(classes.PREDICATES["jalr_lsb_clear"](
            obs("jalr", rs1=0x1_0000, imm=13)))
        # Branch comparisons must read rs2, not the immediate.
        self.assertTrue(classes.PREDICATES["cmp_equal_operands"](
            obs("beq", rs1=5, rs2=5, imm=8)))


class AuditBookkeepingTests(unittest.TestCase):
    def test_coverage_counts_hits_and_reports_untouched(self) -> None:
        coverage = audit.empty_coverage()
        before = len(coverage.untouched())
        coverage.record(obs("add", rs1=0x00FF_FFFF, rs2=1))
        self.assertEqual(1, coverage.enumerated[("add", "carry_ripple")])
        self.assertLess(len(coverage.untouched()), before)
        # An ordinary retirement matching no class is counted, not lost.
        coverage.record(obs("add", rs1=1234, rs2=5678))
        self.assertEqual({"add": 1}, coverage.no_class_match)

    def test_report_shape_names_the_untouched_pairs(self) -> None:
        coverage = audit.empty_coverage()
        report = audit.report(coverage, skipped=["x.elf: missing"])
        self.assertEqual("stwo-riscv-operand-class-audit-v1", report["schema"])
        self.assertEqual(report["enumerated_pairs"], len(report["untouched"]))
        self.assertIn("add/carry_ripple", report["untouched"])
        self.assertEqual(["x.elf: missing"], report["skipped_guests"])


class RenderingTests(unittest.TestCase):
    def test_zig_list_matches_zig_fmt_singleton_rule(self) -> None:
        self.assertEqual("&.{7}", emit._zig_list(["7"]))
        self.assertEqual("&.{ 7, 8 }", emit._zig_list(["7", "8"]))

    def test_cli_emit_refuses_without_sail_instead_of_substituting(self) -> None:
        # The generator must never fall back to structurally derived
        # expectations: absence is exit 3 with the reason on stderr.
        env = dict(os.environ)
        env["STWO_RISCV_SAIL_BIN"] = "/nonexistent/sail_riscv_sim"
        result = subprocess.run(
            [sys.executable, str(CLI), "emit", "--output-dir", "/tmp/never-written"],
            capture_output=True, text=True, env=env, cwd=ROOT,
        )
        self.assertEqual(3, result.returncode, result.stderr)
        self.assertIn("UNAVAILABLE", result.stderr)
        self.assertFalse(Path("/tmp/never-written").exists())

    def test_cli_list_needs_no_sail(self) -> None:
        env = dict(os.environ)
        env["STWO_RISCV_SAIL_BIN"] = "/nonexistent/sail_riscv_sim"
        result = subprocess.run(
            [sys.executable, str(CLI), "list"],
            capture_output=True, text=True, env=env, cwd=ROOT,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        listing = json.loads(result.stdout)
        self.assertGreaterEqual(listing["case_count"], 250)


@unittest.skipUnless(
    pinned_workspace_binary().is_file(),
    f"pinned Sail binary absent at {pinned_workspace_binary()}; "
    "operand-class generation was NOT checked live "
    "(python3 scripts/riscv_formal_tools.py prepare "
    f"--workspace {oracle.DEFAULT_WORKSPACE})",
)
class LivePinnedSailTests(unittest.TestCase):
    """Round-trips through the real pinned binary; ~0.1 s per session."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.sail = oracle.resolve_sail().binary
        cls.cases = {case.name: case for case in classes.all_cases()}

    def test_carry_ripple_case_observes_the_sail_result(self) -> None:
        case = self.cases["add/carry_ripple"]
        observation = session.observe_case(self.sail, case)
        self.assertEqual((0, 1, 2, 3), observation.retired)
        self.assertEqual(0x0100_0000, observation.under_test(case).rd_value)
        self.assertTrue(classes.PREDICATES[case.tag](
            observation.under_test_obs(case)))

    def test_backward_branch_follows_sails_control_flow(self) -> None:
        case = self.cases["blt/branch_backward_taken"]
        observation = session.observe_case(self.sail, case)
        # Hop, materialization, the backward-taken branch, then the pad.
        self.assertEqual((0, 3, 4, 5, 6, 7, 1, 2), observation.retired)
        ret = observation.under_test(case)
        offset = (ret.next_pc - ret.pc) & 0xFFFF_FFFF
        # A backward displacement wraps into the top half as u32.
        self.assertGreater(offset, 0x8000_0000)

    def test_jalr_base_is_marked_pc_derived(self) -> None:
        case = self.cases["jalr/jump_link"]
        observation = session.observe_case(self.sail, case)
        self.assertTrue(observation.rs1_pc_derived)
        self.assertFalse(observation.rs2_pc_derived)

    def test_store_readback_is_pinned_through_sail_loads(self) -> None:
        case = self.cases["sb/store_neighbor_preservation/zero"]
        observation = session.observe_case(self.sail, case)
        self.assertIsNotNone(case.readback)
        readback = observation.by_index[case.readback]
        self.assertEqual(0xFF00_FFFF, readback.rd_value)


if __name__ == "__main__":
    unittest.main()
