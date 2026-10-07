"""Adversarial and reference-value checks for the independent relation oracle."""

import copy
import json
import random
import unittest
from pathlib import Path

from oracle import P, OracleError, UnsupportedOperation, evaluate_relation


EXAMPLES = Path(__file__).resolve().parent / "examples"


def fixture(name: str) -> tuple[dict, dict]:
    return (json.loads((EXAMPLES / f"{name}.s31.json").read_text()),
            json.loads((EXAMPLES / f"{name}.valid.json").read_text()))


class OracleTests(unittest.TestCase):
    def test_repository_arithmetic_examples(self) -> None:
        for name in ("arith4", "mathlib4", "math_polynomial4", "static_matvec", "static_matmul", "array_views",
                     "preimage4", "lane_stats4", "affine4_v1"):
            with self.subTest(name=name):
                relation, assignment = fixture(name)
                self.assertEqual(evaluate_relation(relation, assignment),
                                 assignment["public_outputs"])

    def test_forgeries_fail_on_every_arithmetic_example(self) -> None:
        for name in ("arith4", "mathlib4", "math_polynomial4", "static_matvec", "static_matmul", "array_views", "preimage4",
                     "lane_stats4", "affine4_v1"):
            with self.subTest(name=name):
                relation, assignment = fixture(name)
                wrong = copy.deepcopy(assignment)
                first = relation["public_outputs"][0]
                wrong["public_outputs"][first][0] = (wrong["public_outputs"][first][0] + 1) % P
                with self.assertRaisesRegex(OracleError, "does not match"):
                    evaluate_relation(relation, wrong)

    def test_field_wrap_and_packed_lane_lengths(self) -> None:
        for length in (1, 3, 4, 5, 8, 63, 64, 65):
            with self.subTest(length=length):
                values = [P - 1 if i % 2 else i * 104729 % P for i in range(length)]
                relation = {
                    "version": 1, "name": "reduce", "inputs": [
                        {"name": "x", "kind": "m31", "length": length, "visibility": "private"}],
                    "nodes": [{"name": "total", "op": "sum_lanes", "lhs": "x"}],
                    "assertions": [], "public_outputs": ["total"],
                }
                assignment = {"public_inputs": {}, "private_inputs": {"x": values},
                              "public_outputs": {"total": [sum(values) % P]}}
                self.assertEqual(evaluate_relation(relation, assignment),
                                 assignment["public_outputs"])

    def test_array_views_preserve_exact_position_and_kind(self) -> None:
        relation = {
            "version": 1, "name": "arrays", "inputs": [
                {"name": "left", "kind": "m31", "length": 3, "visibility": "private"},
                {"name": "right", "kind": "m31", "length": 2, "visibility": "private"}],
            "nodes": [
                {"name": "both", "op": "array_concat", "lhs": "left", "rhs": "right"},
                {"name": "edge", "op": "array_get", "lhs": "both", "index": 3}],
            "assertions": [], "public_outputs": ["edge"],
        }
        assignment = {"public_inputs": {}, "private_inputs": {
            "left": [1, 2, 3], "right": [P - 1, 5]}, "public_outputs": {"edge": [P - 1]}}
        self.assertEqual(evaluate_relation(relation, assignment), {"edge": [P - 1]})
        bad_claim = copy.deepcopy(assignment)
        bad_claim["public_outputs"]["edge"] = [3]
        with self.assertRaisesRegex(OracleError, "does not match"):
            evaluate_relation(relation, bad_claim)
        for bad_index in (-1, 5, True):
            forged = copy.deepcopy(relation)
            forged["nodes"][1]["index"] = bad_index
            with self.subTest(bad_index=bad_index), self.assertRaises(OracleError):
                evaluate_relation(forged, assignment)
        forged = copy.deepcopy(relation)
        forged["nodes"][0]["index"] = 0
        with self.assertRaisesRegex(OracleError, "unexpected index"):
            evaluate_relation(forged, assignment)

        u16 = {"version": 1, "name": "bytes", "inputs": [
            {"name": "bytes", "kind": "u16", "length": 2, "visibility": "private"}],
            "nodes": [{"name": "word", "op": "array_get", "lhs": "bytes", "index": 1}],
            "assertions": [], "public_outputs": ["word"]}
        self.assertEqual(evaluate_relation(u16, {"public_inputs": {},
                                            "private_inputs": {"bytes": [7, 65535]},
                                            "public_outputs": {"word": [65535]}}),
                         {"word": [65535]})

    def test_randomized_arithmetic_mix(self) -> None:
        rng = random.Random(0x531)
        relation = {
            "version": 1, "name": "mix", "inputs": [
                {"name": "x", "kind": "m31", "length": 5, "visibility": "private"},
                {"name": "y", "kind": "m31", "length": 5, "visibility": "private"}],
            "nodes": [
                {"name": "twice", "op": "mul_const", "lhs": "x", "constant": 2},
                {"name": "added", "op": "add", "lhs": "twice", "rhs": "y"},
                {"name": "square", "op": "mul", "lhs": "added", "rhs": "added"},
                {"name": "offset", "op": "add_const", "lhs": "square", "constant": P - 7},
                {"name": "total", "op": "sum_lanes", "lhs": "offset"}],
            "assertions": [], "public_outputs": ["total"],
        }
        for _ in range(40):
            x = [rng.randrange(P) for _ in range(5)]
            y = [rng.randrange(P) for _ in range(5)]
            expected = sum(((2 * a + b) ** 2 - 7) for a, b in zip(x, y)) % P
            assignment = {"public_inputs": {}, "private_inputs": {"x": x, "y": y},
                          "public_outputs": {"total": [expected]}}
            self.assertEqual(evaluate_relation(relation, assignment), {"total": [expected]})

    def test_constant_cast_select_repeat_and_assertion(self) -> None:
        relation = {
            "version": 1, "name": "choice", "inputs": [
                {"name": "x", "kind": "u16", "length": 2, "visibility": "private"},
                {"name": "bit", "kind": "m31", "length": 1, "visibility": "private"}],
            "nodes": [
                {"name": "field", "op": "cast_m31", "lhs": "x"},
                {"name": "sevens", "op": "constant", "constant": 7, "length": 2},
                {"name": "chosen", "op": "select", "selector": "bit", "lhs": "field", "rhs": "sevens"},
                {"name": "iterated", "op": "repeat", "lhs": "chosen", "rounds": 3,
                 "body": [{"op": "square"}, {"op": "add_const", "constant": 1},
                          {"op": "mul_const", "constant": 3}]},
                {"name": "assert_copy", "op": "add_const", "lhs": "chosen", "constant": 0}],
            "assertions": [{"lhs": "chosen", "rhs": "assert_copy"}],
            "public_outputs": ["iterated"],
        }
        def iterate(v: int) -> int:
            for _ in range(3):
                v = ((v * v + 1) * 3) % P
            return v
        for bit, chosen in ((0, [0, 65535]), (1, [7, 7])):
            assignment = {"public_inputs": {}, "private_inputs": {"x": [0, 65535], "bit": [bit]},
                          "public_outputs": {"iterated": list(map(iterate, chosen))}}
            self.assertEqual(evaluate_relation(relation, assignment), assignment["public_outputs"])
        invalid = copy.deepcopy(assignment)
        invalid["private_inputs"]["bit"] = [2]
        with self.assertRaisesRegex(OracleError, "selector must be 0 or 1"):
            evaluate_relation(relation, invalid)
        failing = copy.deepcopy(relation)
        failing["nodes"][-1]["constant"] = 1
        with self.assertRaisesRegex(OracleError, r"assertions\[0\] failed"):
            evaluate_relation(failing, assignment)

    def test_reject_malformed_values_and_relation_shapes(self) -> None:
        relation, assignment = fixture("preimage4")
        cases = [
            ("noncanonical public input", ("public_inputs", "target", 0), P),
            ("noncanonical public output", ("public_outputs", "square", 0), P),
            ("negative private input", ("private_inputs", "secret", 0), -1),
            ("u16 overflow", ("private_inputs", "secret", 0), 65536),
            ("boolean word", ("private_inputs", "secret", 0), True),
        ]
        for label, (group, name, index), value in cases:
            with self.subTest(label=label):
                bad = copy.deepcopy(assignment)
                bad[group][name][index] = value
                with self.assertRaises(OracleError):
                    evaluate_relation(relation, bad)
        bad = copy.deepcopy(assignment)
        bad["private_inputs"]["extra"] = [0]
        with self.assertRaisesRegex(OracleError, "fields must be exactly"):
            evaluate_relation(relation, bad)
        bad = copy.deepcopy(assignment)
        del bad["public_outputs"]["square"]
        with self.assertRaises(OracleError):
            evaluate_relation(relation, bad)
        bad_relation = copy.deepcopy(relation)
        bad_relation["nodes"][1]["rhs"] = "target"  # u16 and m31 shapes differ.
        with self.assertRaises(OracleError):
            evaluate_relation(bad_relation, assignment)
        bad_relation = copy.deepcopy(relation)
        bad_relation["nodes"][1]["ignored"] = "secret"
        with self.assertRaisesRegex(OracleError, "unknown fields"):
            evaluate_relation(bad_relation, assignment)

    def test_independent_hash_and_merkle_values(self) -> None:
        for name in ("hash4", "merkle2", "merkle_path1",
                     "merkle2_poseidon", "merkle_path1_poseidon"):
            with self.subTest(name=name):
                relation, assignment = fixture(name)
                self.assertEqual(evaluate_relation(relation, assignment),
                                 assignment["public_outputs"])
                wrong = copy.deepcopy(assignment)
                output = relation["public_outputs"][0]
                wrong["public_outputs"][output][0] = (wrong["public_outputs"][output][0] + 1) % P
                with self.assertRaisesRegex(OracleError, "does not match"):
                    evaluate_relation(relation, wrong)

    def test_u256_carry_order_and_commitment(self) -> None:
        relation, assignment = fixture("wide_order")
        self.assertEqual(evaluate_relation(relation, assignment), assignment["public_outputs"])
        limbs = assignment["private_inputs"]
        self.assertEqual(limbs["digest_bytes"][:2], [65535, 0])
        self.assertEqual(limbs["target"][:2], [0, 1])
        self.assertEqual(limbs["target"][15], 32768)
        bad = copy.deepcopy(assignment)
        bad["private_inputs"]["target"][1] = 0
        with self.assertRaisesRegex(OracleError, r"assertions\[0\] failed"):
            evaluate_relation(relation, bad)
        bad = copy.deepcopy(assignment)
        bad["private_inputs"]["increment"] = [0] * 16
        with self.assertRaisesRegex(OracleError, r"assertions\[0\] failed"):
            evaluate_relation(relation, bad)
        bad = copy.deepcopy(assignment)
        bad["private_inputs"]["digest_bytes"][0] = 65536
        with self.assertRaisesRegex(OracleError, "0..65535"):
            evaluate_relation(relation, bad)

    def test_checked_u256_add_rejects_final_carry_and_comparison_is_boolean(self) -> None:
        relation = {
            "version": 1, "name": "checked", "inputs": [
                {"name": key, "kind": "u16", "length": 16, "visibility": "private"}
                for key in ("a", "b")],
            "nodes": [
                {"name": "sum", "op": "u256_add_checked", "lhs": "a", "rhs": "b"},
                {"name": "less", "op": "u256_le", "lhs": "sum", "rhs": "b"}],
            "assertions": [], "public_outputs": ["less"],
        }
        assignment = {"public_inputs": {}, "private_inputs": {
            "a": [1] + [0] * 15, "b": [2] + [0] * 15},
            "public_outputs": {"less": [0]}}
        self.assertEqual(evaluate_relation(relation, assignment), {"less": [0]})
        assignment["private_inputs"]["a"] = [65535] * 16
        assignment["private_inputs"]["b"] = [1] + [0] * 15
        with self.assertRaisesRegex(OracleError, "256-bit addition overflow"):
            evaluate_relation(relation, assignment)

    def test_u256_subtraction_borrow_and_wrap(self) -> None:
        relation = {
            "version": 1, "name": "sub", "inputs": [
                {"name": key, "kind": "u16", "length": 16, "visibility": "private"}
                for key in ("a", "b")],
            "nodes": [{"name": "difference", "op": "u256_sub", "lhs": "a", "rhs": "b"},
                      {"name": "less", "op": "u256_le", "lhs": "difference", "rhs": "a"}],
            "assertions": [], "public_outputs": ["less"],
        }
        assignment = {"public_inputs": {}, "private_inputs": {
            "a": [0] * 16, "b": [1] + [0] * 15},
            "public_outputs": {"less": [0]}}
        self.assertEqual(evaluate_relation(relation, assignment), {"less": [0]})
        relation["nodes"][0]["op"] = "u256_sub_checked"
        with self.assertRaisesRegex(OracleError, "256-bit subtraction underflow"):
            evaluate_relation(relation, assignment)
        assignment["private_inputs"]["a"] = [0, 1] + [0] * 14
        assignment["public_outputs"]["less"] = [1]
        self.assertEqual(evaluate_relation(relation, assignment), {"less": [1]})

    def test_unknown_hash_or_future_node_never_counts_as_a_check(self) -> None:
        relation, assignment = fixture("hash4")
        relation["nodes"][0]["op"] = "hash_unreviewed"
        with self.assertRaisesRegex(UnsupportedOperation, "unsupported relation operation"):
            evaluate_relation(relation, assignment)


if __name__ == "__main__":
    unittest.main()
