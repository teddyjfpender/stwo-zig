"""Semantic and lowering checks for the proof-aware S31 text core."""

import json
import copy
import unittest
from pathlib import Path

import generate_merkle_path
from s31_stdlib import (P, decode_header80, encode_header80, decode_m31_words_le, decode_u256_le, encode_m31_words_le, encode_u256_le, reference_digest,
                        reference_iterate, reference_m31_binary, reference_m31_from_u16,
                        reference_merkle_path, reference_select)
from text_frontend import Parser, SourceError, compile_file, compile_text
from oracle import OracleError, evaluate_relation


EXAMPLES = Path(__file__).resolve().parent / "examples"


class TextFrontendTests(unittest.TestCase):
    def test_computed_zero_bit_controls_selection(self) -> None:
        relation, _ = compile_file(EXAMPLES / "computed_choice.s31")
        self.assertEqual([node["op"] for node in relation["nodes"]],
                         ["is_zero", "select"])
        for x, expected in ((0, 23), (1, 17), (P - 1, 17)):
            assignment = {
                "public_inputs": {"x": [x], "left": [17], "right": [23]},
                "private_inputs": {}, "public_outputs": {"result": [expected]},
            }
            with self.subTest(x=x):
                self.assertEqual(evaluate_relation(relation, assignment),
                                 assignment["public_outputs"])
        with self.assertRaisesRegex(SourceError, "one \\[m31; 1\\]"):
            compile_text("circuit bad(public x: [m31; 2]) -> public bit { std::field::is_zero(x) }")
        constant_relation, _ = compile_text("""use std@1;
circuit constant_choice(public left: [m31; 1], public right: [m31; 1]) -> public [m31; 1] {
    let zero = std::field::is_zero(splat<1>(0_m31));
    std::field::select(zero, left, right)
}""")
        self.assertEqual([node["op"] for node in constant_relation["nodes"]],
                         ["constant", "select"])

    def test_field_inverse_division_and_zero_rejection(self) -> None:
        relation, _ = compile_file(EXAMPLES / "field_div4.s31")
        self.assertEqual([node["op"] for node in relation["nodes"]],
                         ["inv", "mul", "add"])
        self.assertEqual(relation["nodes"][1]["rhs"], relation["nodes"][0]["name"])
        assignment = json.loads((EXAMPLES / "field_div4.valid.json").read_text())
        self.assertEqual(evaluate_relation(relation, assignment), assignment["public_outputs"])
        invalid = copy.deepcopy(assignment)
        invalid["private_inputs"]["denominator"][2] = 0
        with self.assertRaisesRegex(OracleError, "division by zero"):
            evaluate_relation(relation, invalid)
        with self.assertRaisesRegex(SourceError, "inverse of zero"):
            compile_text("circuit bad() -> public [m31; 1] { std::math::inv(splat<1>(0_m31)) }")
        with self.assertRaisesRegex(SourceError, "equally shaped"):
            compile_text("circuit bad(private x: [m31; 1]) -> public [m31; 1] { std::math::div(x, splat<2>(1_m31)) }")

    def test_bitcoin_header_sha256d_and_compact_pow(self) -> None:
        hash_relation, _ = compile_file(EXAMPLES / "bitcoin_header_hash.s31")
        pow_relation, _ = compile_file(EXAMPLES / "bitcoin_header_pow.s31")
        assignment = json.loads((EXAMPLES / "bitcoin_header_hash.valid.json").read_text())
        header_bytes = encode_header80(assignment["private_inputs"]["header"])
        self.assertEqual(len(header_bytes), 80)
        self.assertEqual(header_bytes[72:76], bytes.fromhex("ffff001d"))
        self.assertEqual(decode_header80(header_bytes), assignment["private_inputs"]["header"])
        self.assertEqual([node["op"] for node in hash_relation["nodes"]],
                         ["hash_sha256d_header", "cast_m31", "hash_poseidon2_leaf"])
        self.assertEqual([node["op"] for node in pow_relation["nodes"][:3]],
                         ["hash_sha256d_header", "bitcoin_target_mainnet", "u256_le"])
        self.assertEqual(evaluate_relation(pow_relation, assignment), assignment["public_outputs"])
        for limb, value in ((37, 0x1d80), (37, 0x2100), (39, assignment["private_inputs"]["header"][39] + 1)):
            changed = copy.deepcopy(assignment)
            changed["private_inputs"]["header"][limb] = value
            with self.subTest(limb=limb, value=value), self.assertRaises(OracleError):
                evaluate_relation(pow_relation, changed)
        with self.assertRaisesRegex(SourceError, "requires a serialized Bytes80"):
            compile_text("circuit bad(private x: Bytes32) -> public Bytes32 { std::hash::sha256d_header(x) }")

    def test_two_real_headers_link_and_keep_nonretarget_bits(self) -> None:
        relation, _ = compile_file(EXAMPLES / "bitcoin_header_pair.s31")
        self.assertEqual(relation, json.loads((EXAMPLES / "bitcoin_header_pair.s31.json").read_text()))
        assignment = json.loads((EXAMPLES / "bitcoin_header_pair.valid.json").read_text())
        self.assertEqual(evaluate_relation(relation, assignment), assignment["public_outputs"])
        parent = encode_header80(assignment["private_inputs"]["parent"])
        child = encode_header80(assignment["private_inputs"]["child"])
        import hashlib
        self.assertEqual(child[4:36], hashlib.sha256(hashlib.sha256(parent).digest()).digest())
        self.assertEqual(hashlib.sha256(hashlib.sha256(child).digest()).digest()[::-1].hex(),
                         "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048")
        swapped = copy.deepcopy(assignment)
        swapped["private_inputs"]["parent"], swapped["private_inputs"]["child"] = (
            swapped["private_inputs"]["child"], swapped["private_inputs"]["parent"])
        with self.assertRaisesRegex(OracleError, r"assertions\[0\] failed"):
            evaluate_relation(relation, swapped)
        broken_link = copy.deepcopy(assignment)
        broken_link["private_inputs"]["child"][2] ^= 1
        with self.assertRaisesRegex(OracleError, r"assertions\[1\] failed"):
            evaluate_relation(relation, broken_link)
        changed_bits = copy.deepcopy(assignment)
        changed_bits["private_inputs"]["child"][37] = 0x1c00
        with self.assertRaisesRegex(OracleError, r"assertions\[2\] failed"):
            evaluate_relation(relation, changed_bits)
        equal_time = copy.deepcopy(assignment)
        equal_time["private_inputs"]["child"][34:36] = equal_time["private_inputs"]["parent"][34:36]
        with self.assertRaisesRegex(OracleError, r"assertions\[3\] failed"):
            evaluate_relation(relation, equal_time)
        wrong_parent = copy.deepcopy(assignment)
        wrong_parent["private_inputs"]["parent"][39] ^= 1
        with self.assertRaisesRegex(OracleError, r"assertions\[0\] failed"):
            evaluate_relation(relation, wrong_parent)

    def test_strict_u32_limb_comparison(self) -> None:
        relation, _ = compile_text("""use std@1;
circuit strict_time(private a: [u16; 2], private b: [u16; 2]) -> public [m31; 1] {
    std::math::lt_u32(a, b)
}""")
        self.assertEqual(relation["nodes"][0]["op"], "u32_lt")
        for left, right in ((0, 1), (0xffff, 0x10000), (0xffffffff, 0),
                            (0xffffffff, 0xffffffff), (7, 3)):
            with self.subTest(left=left, right=right):
                assignment = {
                    "public_inputs": {},
                    "private_inputs": {
                        "a": [left & 0xffff, left >> 16],
                        "b": [right & 0xffff, right >> 16],
                    },
                    "public_outputs": {relation["public_outputs"][0]: [int(left < right)]},
                }
                self.assertEqual(evaluate_relation(relation, assignment), assignment["public_outputs"])

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
        wide = [0xffff, 0x0102] + [0] * 13 + [0x8000]
        self.assertEqual(decode_u256_le(encode_u256_le(wide)), wide)
        self.assertEqual(encode_u256_le(wide)[:4], bytes([0xff, 0xff, 2, 1]))
        with self.assertRaises(ValueError):
            encode_u256_le([65536] + [0] * 15)
        with self.assertRaises(ValueError):
            decode_u256_le(bytes(31))

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

    def test_lane_reductions_lower_to_constrained_relation_ops(self) -> None:
        relation, _ = compile_file(EXAMPLES / "lane_stats4.s31")
        self.assertEqual([node["op"] for node in relation["nodes"]],
                         ["sum_lanes", "mul", "sum_lanes", "add"])
        self.assertEqual(relation["nodes"][0]["lhs"], "x")
        self.assertEqual(relation["nodes"][2]["lhs"], relation["nodes"][1]["name"])
        assignment = json.loads((EXAMPLES / "lane_stats4.valid.json").read_text())
        x = assignment["private_inputs"]["x"]
        weights = assignment["private_inputs"]["weights"]
        self.assertEqual(assignment["public_outputs"]["result"],
                         [(sum(x) + sum(a * b for a, b in zip(x, weights))) % P])

    def test_lane_reductions_validate_types_and_fold_static_cases(self) -> None:
        source = "circuit fold(private x: [m31; 1]) -> public [m31; 1] { std::math::sum_lanes(x) }"
        self.assertEqual(compile_text(source)[0]["nodes"], [])
        constant, _ = compile_text("circuit fold() -> public [m31; 1] { std::math::sum_lanes(splat<4>(7_m31)) }")
        self.assertEqual(constant["nodes"][0]["constant"], 28)
        with self.assertRaisesRegex(SourceError, r"requires \[m31; N\]"):
            compile_text("circuit bad(private x: [u16; 1]) -> public [m31; 1] { std::math::sum_lanes(x) }")
        with self.assertRaisesRegex(SourceError, "equally shaped"):
            compile_text("circuit bad(private x: [m31; 1]) -> public [m31; 1] { std::math::dot_lanes(x, splat<2>(1_m31)) }")

    def test_u256_types_lower_to_range_checked_limbs_and_carry_nodes(self) -> None:
        relation, _ = compile_file(EXAMPLES / "wide_order.s31")
        self.assertEqual(relation, json.loads((EXAMPLES / "wide_order.s31.json").read_text()))
        self.assertEqual({item["kind"] for item in relation["inputs"]}, {"u16"})
        self.assertEqual([node["op"] for node in relation["nodes"][:2]],
                         ["u256_add", "u256_le"])
        self.assertEqual([node["op"] for node in relation["nodes"]].count("cast_m31"), 2)
        self.assertEqual(relation["public_outputs"], ["root"])
        with self.assertRaisesRegex(SourceError, "requires two UInt256"):
            compile_text("""
circuit bad(private bytes: Bytes32, private integer: UInt256) -> public [m31; 1] {
    std::math::le_u256(bytes, integer)
}
""")
        with self.assertRaisesRegex(SourceError, "use std::bytes::limbs_m31"):
            compile_text("circuit bad(private bytes: Bytes32) -> public [m31; 16] { m31_from_u16(bytes) }")
        with self.assertRaisesRegex(ValueError, "current public ABI allows at most eight words"):
            compile_text("circuit wide(private x: UInt256) -> public UInt256 { x }")

    def test_checked_u256_addition_has_distinct_relation_node(self) -> None:
        source = """use std@1;
circuit checked(private a: UInt256, private b: UInt256) -> public [m31; 1] {
    let sum = std::math::add_u256_checked(a, b);
    std::math::le_u256(sum, b)
}"""
        relation, _ = compile_text(source)
        self.assertEqual([node["op"] for node in relation["nodes"]],
                         ["u256_add_checked", "u256_le"])
        bytes_source = """circuit retyped(private x: UInt256) -> public Digest<Poseidon2> {
    let bytes = std::bytes::from_u256_le(x);
    std::hash::poseidon2_leaf(std::bytes::limbs_m31(bytes))
}"""
        retyped, _ = compile_text(bytes_source)
        self.assertEqual([node["op"] for node in retyped["nodes"]],
                         ["cast_m31", "hash_poseidon2_leaf"])

    def test_u256_subtraction_has_explicit_underflow_modes(self) -> None:
        for function, op in (("sub_u256", "u256_sub"),
                             ("sub_u256_checked", "u256_sub_checked")):
            relation, _ = compile_text(f"""use std@1;
circuit subtract(private a: UInt256, private b: UInt256) -> public [m31; 1] {{
    let difference = std::math::{function}(a, b);
    std::math::le_u256(difference, a)
}}""")
            self.assertEqual([node["op"] for node in relation["nodes"]],
                             [op, "u256_le"])
        with self.assertRaisesRegex(SourceError, "requires two UInt256"):
            compile_text("circuit bad(private a: Bytes32, private b: UInt256) -> public [m31; 1] { std::math::sub_u256(a, b) }")

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

    def test_static_matrix_vector_lowers_to_existing_arithmetic(self) -> None:
        self.assertEqual(compile_file(EXAMPLES / "static_matvec.s31")[0],
                         json.loads((EXAMPLES / "static_matvec.s31.json").read_text()))
        relation, source_map = compile_text("""use std@1;
circuit matrix(private a: [m31; 1], private b: [m31; 1]) -> public [m31; 1] {
    let vector = [a, b];
    let rows = [[splat<1>(2_m31), splat<1>(3_m31)],
                [splat<1>(5_m31), splat<1>(7_m31)]];
    let products = std::math::matvec(rows, vector);
    let first = std::array::get<0>(products);
    let second = std::array::get<1>(products);
    let total = std::math::sum(std::array::concat([first], [second]));
    total
}""")
        nodes = relation["nodes"]
        self.assertEqual([node["op"] for node in nodes],
                         ["mul_const", "mul_const", "add", "mul_const", "mul_const", "add", "add"])
        self.assertEqual(nodes[-1]["name"], "total")
        self.assertEqual(set(source_map), {node["name"] for node in nodes})
        self.assertEqual(relation["public_outputs"], ["total"])

    def test_runtime_array_get_and_concat_have_explicit_relation_nodes(self) -> None:
        self.assertEqual(compile_file(EXAMPLES / "array_views.s31")[0],
                         json.loads((EXAMPLES / "array_views.s31.json").read_text()))
        for name in ("array_views_private", "array_views_u16"):
            with self.subTest(name=name):
                self.assertEqual(compile_file(EXAMPLES / f"{name}.s31")[0],
                                 json.loads((EXAMPLES / f"{name}.s31.json").read_text()))
        relation, _ = compile_text("""use std@1;
circuit joined(private a: [m31; 3], private b: [m31; 2]) -> public [m31; 1] {
    let both = std::array::concat(a, b);
    std::array::get<4>(both)
}""")
        self.assertEqual(relation["nodes"], [
            {"name": "both", "op": "array_concat", "lhs": "a", "rhs": "b"},
            {"name": "_s31_0", "op": "array_get", "lhs": "both", "index": 4},
        ])
        u16, _ = compile_text("""circuit byte(private a: [u16; 2]) -> public [u16; 1] {
    std::array::get<1>(a)
}""")
        self.assertEqual(u16["nodes"][0]["op"], "array_get")
        shifted = compile_file(EXAMPLES / "array_views_private.s31")[0]
        self.assertEqual([node["op"] for node in shifted["nodes"]],
                         ["array_concat", "add", "array_get", "array_get", "array_get", "add", "add"])
        self.assertEqual([node["index"] for node in shifted["nodes"] if node["op"] == "array_get"],
                         [3, 4, 5])

    def test_static_matmul_views_lower_to_constrained_arithmetic(self) -> None:
        relation, source_map = compile_file(EXAMPLES / "static_matmul.s31")
        self.assertEqual(len(relation["nodes"]), 19)
        self.assertEqual(set(source_map), {node["name"] for node in relation["nodes"]})
        self.assertEqual({node["op"] for node in relation["nodes"]}, {"mul_const", "add"})
        self.assertEqual(relation["nodes"][-1], {
            "name": "result", "op": "add", "lhs": "weighted_front", "rhs": "weighted_back"})

        lanes, _ = compile_text("""circuit lanes(private a: [m31; 4], private b: [m31; 4])
            -> public [m31; 4] {
            let product = std::math::matmul([[a,b]],
                [[splat<4>(2_m31),splat<4>(3_m31)],
                 [splat<4>(5_m31),splat<4>(7_m31)]]);
            std::math::sum(std::array::flatten(product))
        }""")
        a, b = [0, 1, P - 1, 17], [7, 2, 3, P - 1]
        expected = [(5 * x + 12 * y) % P for x, y in zip(a, b)]
        output = lanes["public_outputs"][0]
        self.assertEqual(evaluate_relation(lanes, {
            "public_inputs": {}, "private_inputs": {"a": a, "b": b},
            "public_outputs": {output: expected},
        }), {output: expected})

    def test_static_views_and_matmul_reject_bad_shapes(self) -> None:
        cases = (
            ("std::array::take<0>([a,b])", "take count"),
            ("std::array::drop<2>([a,b])", "drop count"),
            ("std::array::reshape<2>([a,b,a])", "exact divisibility"),
            ("std::array::reshape<2>([[a],[b]])", "flat static array"),
            ("std::array::flatten([[a,b],[a]])", "rectangular static rows"),
            ("std::math::matmul([[a,b]], [[a]])", "inner matrix dimensions"),
            ("std::math::matmul([[a,b],[a]], [[a],[b]])", "rectangular static rows"),
            ("std::math::matmul([[a,b]], [[a],[c]])", "equally shaped"),
            ("std::array::take<1>(a)", "requires a static array"),
        )
        for expression, message in cases:
            with self.subTest(expression=expression), self.assertRaisesRegex(SourceError, message):
                compile_text(f"""circuit invalid(private a: [m31; 1], private b: [m31; 1],
                    private c: [m31; 2]) -> public [m31; 1] {{ {expression} }}""")

    def test_static_views_only_reuse_existing_references(self) -> None:
        relation, source_map = compile_text("""circuit views(public a: [m31; 1],
            public b: [m31; 1], public c: [m31; 1], public d: [m31; 1])
            -> public [m31; 1] {
            let rows = std::array::reshape<2>([a,b,c,d]);
            let flat = std::array::flatten(rows);
            let first = std::array::take<3>(flat);
            let last = std::array::drop<1>(first);
            std::array::get<0>(last)
        }""")
        self.assertEqual(relation["nodes"], [])
        self.assertEqual(relation["public_outputs"], ["b"])
        self.assertEqual(source_map, {})

    def test_array_and_matrix_shapes_are_checked_before_relation_emission(self) -> None:
        cases = (
            ("std::array::get<2>([a, b])", "outside the static array"),
            ("std::array::get<2>(a)", "outside the runtime array"),
            ("std::array::concat(a, b)", "same m31 or u16 element type"),
            ("std::math::matvec([[a]], [a, a])", "rectangular rows"),
            ("std::math::sum([[a]])", "static array of"),
        )
        for expression, message in cases:
            with self.subTest(expression=expression), self.assertRaisesRegex(SourceError, message):
                compile_text(f"circuit invalid(private a: [m31; 1], private b: [u16; 1]) -> public [m31; 1] {{ {expression} }}")

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
