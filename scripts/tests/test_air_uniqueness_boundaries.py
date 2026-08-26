"""Boundary transcription and command contracts for AIR uniqueness."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

from scripts import air_uniqueness
from scripts.air_uniqueness_lib import smtlib, solve
from scripts.riscv_air_ir_lib import ir, tables

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "air_uniqueness"
SCHEMA_ZIG = ROOT / "src/frontends/riscv/air/lookups/tables/schema.zig"
ENTRY_ZIG = ROOT / "src/frontends/riscv/air/lookups/entry.zig"
UNDER_CONSTRAINED = FIXTURES / "sign_load_underconstrained.json"
FIXED = FIXTURES / "sign_load_fixed.json"
TIMEOUT_MS = 20_000

try:
    import z3 as _z3  # noqa: F401

    HAVE_Z3 = True
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    HAVE_Z3 = False

needs_z3 = unittest.skipUnless(HAVE_Z3, "z3 bindings are absent")


def _zig_switch_arms(text: str, function: str) -> dict[str, int]:
    """Read `.member => literal,` arms out of one Zig switch function."""
    body = re.search(rf"pub fn {function}\(.*?\n\}}", text, re.S)
    assert body is not None, f"{function} not found"
    arms: dict[str, int] = {}
    for members, value in re.findall(
        r"^\s*((?:\.\w+\s*,\s*)*\.\w+)\s*=>\s*(\d+)\s*,", body.group(0), re.M
    ):
        for member in members.split(","):
            arms[member.strip().lstrip(".")] = int(value)
    return arms


class ZigTableTranscriptionTest(unittest.TestCase):
    """The Python table schema must remain tied to its Zig protocol owner."""

    def test_box_widths_match_schema_log_sizes_and_arities(self) -> None:
        text = SCHEMA_ZIG.read_text(encoding="utf-8")
        log_sizes = _zig_switch_arms(text, "logSize")
        arities = _zig_switch_arms(text, "arity")
        self.assertEqual(
            set(log_sizes), set(tables.BOX_TABLES) | {tables.BITWISE_DOMAIN}
        )
        for name, widths in tables.BOX_TABLES.items():
            with self.subTest(table=name):
                self.assertEqual(sum(widths), log_sizes[name])
                self.assertEqual(len(widths), arities[name])
        lhs, rhs, _value, op = tables.BITWISE_WIDTHS
        self.assertEqual(lhs + rhs + op, log_sizes[tables.BITWISE_DOMAIN])
        self.assertEqual(arities[tables.BITWISE_DOMAIN], 4)

    def test_relation_domains_and_arities_match_entry_zig(self) -> None:
        text = ENTRY_ZIG.read_text(encoding="utf-8")
        enum_body = re.search(r"pub const Domain = enum\(u8\) \{(.*?)\};", text, re.S)
        assert enum_body is not None
        declared = {
            line.strip().rstrip(",").split("=", 1)[0].strip()
            for line in enum_body.group(1).splitlines()
            if line.strip() and not line.strip().startswith("//")
        }
        self.assertEqual(declared, set(tables.ARITIES))
        self.assertEqual(
            set(tables.BUS_DOMAINS) | set(tables.BOX_TABLES) | {tables.BITWISE_DOMAIN},
            declared,
        )
        self.assertEqual(_zig_switch_arms(text, "expectedArity"), tables.ARITIES)


@needs_z3
class CommandLineTest(unittest.TestCase):
    def test_explain_names_what_the_query_does_not_cover(self) -> None:
        self.assertIn("What the query does NOT cover", air_uniqueness.ENCODING_SPEC)
        for absent in ("Cross-row", "Multiset", "Completeness", "Degenerate"):
            self.assertIn(absent, air_uniqueness.ENCODING_SPEC)

    def test_check_exit_code_reports_the_verdict(self) -> None:
        self.assertEqual(air_uniqueness.main(["check", str(FIXED)]), 0)
        self.assertEqual(air_uniqueness.main(["check", str(UNDER_CONSTRAINED)]), 1)

    def test_counterexample_export_is_a_witness_pair(self) -> None:
        system = ir.load(UNDER_CONSTRAINED)
        result = solve.check(system, timeout_ms=TIMEOUT_MS)
        payload = solve.counterexample_payload(system, result)
        first, second = smtlib.COPIES
        self.assertEqual(
            payload["witnesses"][first]["witness"]["src_msb"],
            1 - payload["witnesses"][second]["witness"]["src_msb"],
        )
        self.assertTrue(payload["differing_outputs"])
        json.dumps(payload)

    def test_counterexample_export_refuses_an_unsat_result(self) -> None:
        system = ir.load(FIXED)
        result = solve.check(system, timeout_ms=TIMEOUT_MS)
        with self.assertRaises(ValueError):
            solve.counterexample_payload(system, result)


if __name__ == "__main__":
    unittest.main()
