"""Semantic and lowering checks for the proof-aware S31 text core."""

import json
import unittest
from pathlib import Path

import generate_merkle_path
from s31_stdlib import (P, decode_m31_words_le, encode_m31_words_le, reference_digest,
                        reference_iterate, reference_m31_binary, reference_m31_from_u16,
                        reference_merkle_path, reference_select)
from text_frontend import Parser, SourceError, compile_file, compile_text


EXAMPLES = Path(__file__).resolve().parent / "examples"


class TextFrontendTests(unittest.TestCase):
    def test_field_cast_arithmetic_and_selection(self) -> None:
        self.assertEqual(reference_m31_from_u16([0, 65535]), [0, 65535])
        with self.assertRaises(ValueError):
            reference_m31_from_u16([65536])
        self.assertEqual(reference_m31_binary("add", [P - 1, 2], [1, 3]), [0, 5])
        self.assertEqual(reference_m31_binary("mul", [P - 1, 2], [2, 3]), [P - 2, 6])
        self.assertEqual(reference_select(0, [1, 2], [3, 4]), [1, 2])
        self.assertEqual(reference_select(1, [1, 2], [3, 4]), [3, 4])
        with self.assertRaises(ValueError):
            reference_select(2, [1], [3])

    def test_canonical_word_encoding(self) -> None:
        self.assertEqual(encode_m31_words_le([0x01020304, 1]),
                         bytes([4, 3, 2, 1, 1, 0, 0, 0]))
        self.assertEqual(decode_m31_words_le(bytes([4, 3, 2, 1, 1, 0, 0, 0])),
                         [0x01020304, 1])
        with self.assertRaises(ValueError):
            decode_m31_words_le(P.to_bytes(4, "little"))

    def test_existing_relations_are_identical(self) -> None:
        for name in ("arith4_m31", "merkle_path1_poseidon", "merkle_path1",
                     "affine4_v1", "preimage4", "math_polynomial4"):
            with self.subTest(name=name):
                relation, source_map = compile_file(EXAMPLES / f"{name}.s31")
                reference = json.loads((EXAMPLES / f"{name}.s31.json").read_text())
                self.assertEqual(relation, reference)
                self.assertEqual(set(source_map), {node["name"] for node in relation["nodes"]})

    def test_math_library_lowers_to_existing_field_gates(self) -> None:
        relation, _ = compile_file(EXAMPLES / "math_polynomial4.s31")
        self.assertEqual([node["op"] for node in relation["nodes"]],
                         ["mul", "mul", "mul", "mul_const", "add", "add_const"])
        self.assertEqual(relation["nodes"][-1]["constant"], P - 7)
        assignment = json.loads((EXAMPLES / "math_polynomial4.valid.json").read_text())
        self.assertEqual(assignment["public_outputs"]["result"],
                         [(pow(x, 5, P) + 3 * x - 7) % P
                          for x in assignment["public_inputs"]["x"]])

    def test_versioned_static_math_lowers_to_existing_gates(self) -> None:
        source = (EXAMPLES / "mathlib4.s31").read_text()
        relation, _ = compile_text(source)
        self.assertEqual([node["op"] for node in relation["nodes"]],
                         ["mul_const", "add_const", "mul", "add_const", "mul",
                          "add_const", "mul_const", "mul_const", "add", "add_const"])
        self.assertEqual(compile_text(source.replace("use std@1;", ""))[0], relation)
        assignment = json.loads((EXAMPLES / "mathlib4.valid.json").read_text())
        values = assignment["public_inputs"]["x"]
        polynomial = lambda x: (2 * x ** 3 + 3 * x ** 2 + 5 * x + 7) % P
        self.assertEqual(assignment["public_outputs"]["result"],
                         [(2 * x + 3 * polynomial(x) + 11) % P for x in values])
        parser = Parser(source, "mathlib4.s31")
        parser.parse()
        self.assertTrue(parser.stdlib_explicit)

    def test_static_math_checks_shapes_and_term_counts(self) -> None:
        cases = (
            ("std::math::sum(x)", "requires a static array"),
            ("std::math::sum([x, splat<2>(1_m31)])", "equally shaped"),
            ("std::math::dot([x, x], [x])", "equal static array lengths"),
            ("std::math::poly_eval(x, [splat<2>(1_m31)])", "must match x"),
        )
        for expression, message in cases:
            with self.subTest(expression=expression), self.assertRaisesRegex(SourceError, message):
                compile_text(f"circuit bad(private x: [m31; 1]) -> public [m31; 1] {{ {expression} }}")
        too_many = ", ".join(["x"] * 65)
        with self.assertRaisesRegex(SourceError, "1..64 terms"):
            compile_text(f"circuit bad(private x: [m31; 1]) -> public [m31; 1] {{ std::math::sum([{too_many}]) }}")

    def test_static_sum_uses_balanced_dependencies(self) -> None:
        relation, _ = compile_text("""
circuit balanced(private a: [m31; 1], private b: [m31; 1],
                 private c: [m31; 1], private d: [m31; 1]) -> public [m31; 1] {
    std::math::sum([a, b, c, d])
}
""")
        nodes = relation["nodes"]
        self.assertEqual(len(nodes), 3)
        self.assertEqual((nodes[0]["lhs"], nodes[0]["rhs"]), ("a", "b"))
        self.assertEqual((nodes[1]["lhs"], nodes[1]["rhs"]), ("c", "d"))
        self.assertEqual((nodes[2]["lhs"], nodes[2]["rhs"]), (nodes[0]["name"], nodes[1]["name"]))

    def test_std_import_rejects_unsupported_versions_and_packages(self) -> None:
        circuit = "circuit math(private x: [m31; 1]) -> public [m31; 1] { x }"
        for import_line in ("use std@2;", "use other@1;"):
            with self.subTest(import_line=import_line), self.assertRaisesRegex(SourceError, "std@1"):
                compile_text(import_line + "\n" + circuit)

    def test_math_square_is_valid_inside_iterate(self) -> None:
        old = (EXAMPLES / "arith4_m31.s31").read_text()
        new = "use std@1;\n" + old.replace("v .* v", "std::math::square(v)")
        self.assertEqual(compile_text(new)[0], compile_text(old)[0])

    def test_math_identity_and_constant_folding(self) -> None:
        source = """circuit math(private x: [m31; 1]) -> public [m31; 1] {
    let a = std::math::pow<1>(x);
    let b = std::math::pow<0>(a);
    let c = std::math::neg(b);
    std::math::sub(std::math::square(a), c)
}"""
        relation, _ = compile_text(source)
        self.assertEqual([node["op"] for node in relation["nodes"]],
                         ["mul", "add_const"])
        self.assertEqual(relation["nodes"][1]["constant"], 1)

    def test_standard_hash_alias_has_identical_relation(self) -> None:
        source = (EXAMPLES / "merkle_path1_poseidon.s31").read_text()
        qualified = source.replace("poseidon2_leaf(", "std::hash::poseidon2_leaf(")
        qualified = qualified.replace("poseidon2_pair(", "std::hash::poseidon2_pair(")
        self.assertEqual(compile_text(source)[0], compile_text(qualified)[0])

    def test_math_rejects_unsupported_types_and_exponents(self) -> None:
        cases = (
            ("m31", "std::math::pow<2147483647>(x)", "exponent must be"),
            ("u16", "std::math::square(x)", "std::math requires"),
            ("m31", "std::math::sub(x, splat<2>(1_m31))", "equally shaped"),
        )
        for kind, body, expected in cases:
            with self.subTest(body=body), self.assertRaisesRegex(SourceError, expected):
                compile_text(f"circuit bad(private x: [{kind}; 1]) -> public [m31; 1] {{ {body} }}")

    def test_independent_recurrence_values(self) -> None:
        assignment = json.loads((EXAMPLES / "arith4.valid.json").read_text())
        expected = reference_iterate(assignment["public_inputs"]["x"], 256,
                                     ({"op": "square"}, {"op": "add_const", "constant": 7}))
        self.assertEqual(expected, assignment["public_outputs"]["result"])
        self.assertEqual(reference_iterate([1, 2, 3, 65535], 1,
                                           ({"op": "square"}, {"op": "add_const", "constant": 7})),
                         [8, 11, 16, 2147352585])

    def test_independent_hash_and_path_values(self) -> None:
        assignment = json.loads((EXAMPLES / "merkle_path1_poseidon.valid.json").read_text())
        private = assignment["private_inputs"]
        root = reference_merkle_path("poseidon2", private["leaf"],
                                     [private["sibling"]], private["direction"])
        self.assertEqual(root, assignment["public_outputs"]["root"])
        self.assertEqual(reference_merkle_path(
            "poseidon2", reference_digest("poseidon2", "leaf", private["leaf"]),
            [private["sibling"]], private["direction"], prehashed=True), root)
        blake_assignment = json.loads((EXAMPLES / "merkle_path1.valid.json").read_text())
        blake_private = blake_assignment["private_inputs"]
        self.assertEqual(reference_merkle_path("blake2s_reduced", blake_private["leaf"],
                                              [blake_private["sibling"]], blake_private["direction"]),
                         blake_assignment["public_outputs"]["root"])
        for family in ("poseidon2", "blake2s_reduced"):
            with self.subTest(family=family):
                a = reference_digest(family, "leaf", list(range(1, 9)))
                b = reference_digest(family, "leaf", list(range(9, 17)))
                self.assertEqual(len(a), 8)
                self.assertTrue(all(0 <= word < P for word in a + b))
                self.assertNotEqual(reference_digest(family, "pair", a, b),
                                    reference_digest(family, "pair", b, a))

    def test_fixed_depth_merkle_builtin(self) -> None:
        relation, _ = compile_file(EXAMPLES / "merkle_path2_poseidon.s31")
        self.assertEqual([node["op"] for node in relation["nodes"]],
                         ["hash_poseidon2_leaf", "select", "select", "hash_poseidon2_pair",
                          "select", "select", "hash_poseidon2_pair"])
        generated, assignment = generate_merkle_path.generate(2, 1, "poseidon2")
        self.assertEqual(len(generated["nodes"]), len(relation["nodes"]))
        private = assignment["private_inputs"]
        self.assertEqual(reference_merkle_path("poseidon2", private["leaf"],
                                              [private["sibling_0"], private["sibling_1"]],
                                              [private["direction_0"][0], private["direction_1"][0]]),
                         assignment["public_outputs"]["parent_1"])

    def test_repeated_function_calls_use_distinct_local_nodes(self) -> None:
        relation, _ = compile_text("""
fn add7(x: [m31; 1]) -> [m31; 1] {
    let local = x + splat<1>(7_m31);
    local
}
circuit two(private x: [m31; 1]) -> public [m31; 1] {
    let a = add7(x);
    let b = add7(a);
    b
}
""")
        self.assertEqual(len(relation["nodes"]), 2)
        self.assertEqual([node["name"] for node in relation["nodes"]], ["a", "b"])

    def test_generated_names_do_not_capture_later_bindings(self) -> None:
        relation, _ = compile_text("""
circuit names(private leaf: [m31; 8], private sibling: Digest<Poseidon2>,
              private direction: bit) -> public Digest<Poseidon2> {
    let root = merkle_path_poseidon2(leaf, [sibling], [direction]);
    let _s31_0 = root;
    _s31_0
}
""")
        self.assertEqual(relation["public_outputs"], ["root"])
        self.assertNotIn("_s31_0", {node["name"] for node in relation["nodes"]})

    def test_rejects_wrong_digest_family(self) -> None:
        with self.assertRaisesRegex(SourceError, "same family"):
            compile_text("""
circuit bad(private a: Digest<Poseidon2>, private b: Digest<Blake2sReduced>)
    -> public Digest<Poseidon2> {
    poseidon2_pair(a, b)
}
""")

    def test_static_group_cannot_be_a_witness_array(self) -> None:
        with self.assertRaisesRegex(SourceError, "expected a circuit value"):
            compile_text("""
fn pretend(a: Digest<Poseidon2>, b: Digest<Poseidon2>) -> [m31; 2] {
    [a, b]
}
circuit bad(private a: Digest<Poseidon2>, private b: Digest<Poseidon2>)
    -> public [m31; 2] {
    pretend(a, b)
}
""")

    def test_rejects_unconstrained_bit(self) -> None:
        with self.assertRaisesRegex(ValueError, "every bit input must be constrained"):
            compile_text("""
circuit bad(private bit_input: bit, private value: [m31; 1]) -> public [m31; 1] {
    value
}
""")

    def test_rejects_dynamic_loop_and_reports_location(self) -> None:
        with self.assertRaisesRegex(SourceError, r"loop.s31:3:\d+: expected a compile-time natural number"):
            compile_text("""fn step(v: [m31; 1]) -> [m31; 1] { v .* v }
circuit bad(private x: [m31; 1]) -> public [m31; 1] {
    iterate<x>(step, x)
}
""", "loop.s31")

    def test_rejects_recursive_function(self) -> None:
        with self.assertRaisesRegex(SourceError, "recursive"):
            compile_text("""
fn again(x: [m31; 1]) -> [m31; 1] { again(x) }
circuit bad(private x: [m31; 1]) -> public [m31; 1] { again(x) }
""")

    def test_rejects_wrong_step_helper_type(self) -> None:
        with self.assertRaisesRegex(SourceError, "step helper argument type mismatch"):
            compile_text("""
fn helper(v: [m31; 3]) -> [m31; 3] { v .* v }
fn step(v: [m31; 4]) -> [m31; 4] { helper(v) }
circuit bad(public x: [m31; 4]) -> public [m31; 4] {
    iterate<16>(step, x)
}
""")


if __name__ == "__main__":
    unittest.main()
