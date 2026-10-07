"""Independent value and source-shape checks for nominal fixed-width integers."""

import sys
import unittest
from pathlib import Path

S31_SOURCE_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

from oracle import OracleError, evaluate_relation
from text_frontend import SourceError, compile_text


def limbs(value: int, width: int) -> list[int]:
    return [(value >> (16 * i)) & 0xffff for i in range(max(1, width // 16))]


class FixedWidthIntegerTests(unittest.TestCase):
    def assignment(self, relation: dict, width: int, a: int, b: int, result: int | bool) -> dict:
        return {
            "public_inputs": {},
            "private_inputs": {"a": limbs(a, width), "b": limbs(b, width)},
            "public_outputs": {relation["public_outputs"][0]:
                               [int(result)] if isinstance(result, bool) else limbs(result, width)},
        }

    def test_all_ten_types_checked_and_wrapping_add(self) -> None:
        for width in (8, 16, 32, 64, 128):
            for prefix in ("u", "i"):
                kind = f"{prefix}{width}"
                with self.subTest(kind=kind):
                    source = (f"circuit add(private a: {kind}, private b: {kind}) -> public {kind} "
                              "{ std::int::add_wrapping(a, b) }")
                    relation, _ = compile_text(source)
                    self.assertEqual([n["op"] for n in relation["nodes"]],
                                     ["int_view", "int_view", "int_add_wrapping"])
                    spec = width | (256 if prefix == "i" else 0)
                    self.assertTrue(all(n["constant"] == spec for n in relation["nodes"]))
                    a = (1 << width) - 1
                    b = 1
                    expected = 0
                    assignment = self.assignment(relation, width, a, b, expected)
                    self.assertEqual(evaluate_relation(relation, assignment), assignment["public_outputs"])

                    checked, _ = compile_text(source.replace("add_wrapping", "add_checked"))
                    if prefix == "u":
                        with self.assertRaisesRegex(OracleError, "overflow"):
                            evaluate_relation(checked, self.assignment(checked, width, a, b, expected))
                    else:
                        self.assertEqual(evaluate_relation(
                            checked, self.assignment(checked, width, a, b, expected)),
                            self.assignment(checked, width, a, b, expected)["public_outputs"])
                        high = (1 << (width - 1)) - 1
                        with self.assertRaisesRegex(OracleError, "overflow"):
                            evaluate_relation(checked, self.assignment(checked, width, high, 1, high + 1))

    def test_subtraction_and_signed_order(self) -> None:
        for kind, width, a, b, expected_le in (("u8", 8, 255, 1, False),
                                                ("i8", 8, 255, 1, True),
                                                ("u128", 128, 1 << 127, 1, False),
                                                ("i128", 128, 1 << 127, 1, True)):
            with self.subTest(kind=kind):
                compare, _ = compile_text(
                    f"circuit compare(private a: {kind}, private b: {kind}) -> public bit "
                    "{ std::int::le(a, b) }")
                assignment = self.assignment(compare, width, a, b, expected_le)
                self.assertEqual(evaluate_relation(compare, assignment), assignment["public_outputs"])
                subtract, _ = compile_text(
                    f"circuit subtract(private a: {kind}, private b: {kind}) -> public {kind} "
                    "{ std::int::sub_wrapping(a, b) }")
                result = (a - b) % (1 << width)
                assignment = self.assignment(subtract, width, a, b, result)
                self.assertEqual(evaluate_relation(subtract, assignment), assignment["public_outputs"])

    def test_byte_range_and_explicit_limb_conversion(self) -> None:
        relation, _ = compile_text(
            "circuit from_limbs(public raw: [u16; 1]) -> public u8 "
            "{ std::int::from_limbs_u8(raw) }")
        output = relation["public_outputs"][0]
        self.assertEqual(relation["nodes"][0]["op"], "int_view")
        self.assertEqual(evaluate_relation(relation, {"public_inputs": {"raw": [255]},
                          "private_inputs": {}, "public_outputs": {output: [255]}}), {output: [255]})
        with self.assertRaisesRegex(OracleError, "exceeds 8 bits"):
            evaluate_relation(relation, {"public_inputs": {"raw": [256]},
                               "private_inputs": {}, "public_outputs": {output: [256]}})
        with self.assertRaisesRegex(SourceError, "requires \\[u16; 1\\]"):
            compile_text("circuit bad(private x: [u16; 2]) -> public u8 { std::int::from_limbs_u8(x) }")

    def test_nominal_mismatch_and_reinterpret(self) -> None:
        with self.assertRaisesRegex(SourceError, "equally typed"):
            compile_text("circuit bad(private a: u16, private b: i16) -> public u16 "
                         "{ std::int::add_checked(a, b) }")
        relation, _ = compile_text(
            "circuit reinterpret(private a: i8, private b: i8) -> public u8 "
            "{ std::int::reinterpret_u8(std::int::add_wrapping(a, b)) }")
        assignment = self.assignment(relation, 8, 255, 0, 255)
        self.assertEqual(evaluate_relation(relation, assignment), assignment["public_outputs"])


if __name__ == "__main__":
    unittest.main()
