#!/usr/bin/env python3
"""Check copied S31 examples, hash constants, and local documentation links."""

import hashlib
import json
import re
import statistics
import struct
import sys
from pathlib import Path
from xml.etree import ElementTree


DOCS = Path(__file__).resolve().parent
S31 = DOCS.parent
ROOT = S31.parents[2]
sys.path.insert(0, str(S31))

import poseidon2_oracle as poseidon  # noqa: E402
from oracle import OracleError, evaluate_relation  # noqa: E402
from s31_stdlib import P, decode_u256_le, encode_u256_le, reference_iterate  # noqa: E402
from text_frontend import compile_text  # noqa: E402


def text_block(path: Path, prefix: str) -> str:
    for block in re.findall(r"(?:```|~~~)(?:text|s31)\n(.*?)\n(?:```|~~~)", path.read_text(), re.S):
        if block.lstrip().startswith(prefix):
            return block
    raise AssertionError(f"{path}: missing {prefix!r} example")


def text_block_containing(path: Path, marker: str) -> str:
    for block in re.findall(r"(?:```|~~~)(?:text|s31)\n(.*?)\n(?:```|~~~)", path.read_text(), re.S):
        if marker in block:
            return block
    raise AssertionError(f"{path}: missing {marker!r} example")


def json_block_containing(path: Path, marker: str) -> dict:
    for block in re.findall(r"```json\n(.*?)\n```", path.read_text(), re.S):
        if marker in block:
            return json.loads(block)
    raise AssertionError(f"{path}: missing JSON example containing {marker!r}")


def check_historical_source_hashes(sources: dict[str, str]) -> None:
    """Validate historical measurement provenance without rewriting its date.

    A measurement's source digests describe the files used for that run. New
    source revisions do not make old proof sizes or row counts current. Current
    compiler behavior is checked separately by the text/oracle/proof corpus.
    """
    assert sources
    for name, digest in sources.items():
        assert isinstance(name, str) and name and not Path(name).is_absolute()
        assert ".." not in Path(name).parts and (S31 / name).is_file()
        assert isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)


def check_examples() -> None:
    walkthrough, _ = compile_text(
        text_block(DOCS / "walkthrough.md", "circuit square_plus_seven"), "walkthrough.md"
    )
    assert [node["op"] for node in walkthrough["nodes"]] == ["mul", "add_const"]
    assert walkthrough["nodes"][1]["constant"] == 7
    assert [(x * x + 7) % P for x in [1, 2, 3, 4]] == [8, 11, 16, 23]
    # The chapter's two-row interpolation and quotient identities are exact.
    for t in range(5):
        a, b, c = 3 + 6 * t, 3 + 4 * t, 9 + 7 * t
        z = t * (t - 1)
        assert ((1 - t) * (c - a * b) - z * (24 * t + 23)) % P == 0
        assert (t * (c - a - b) - z * (-3)) % P == 0

    for chapter, prefix, fixture in (
        ("source.md", "circuit preimage4", "preimage4"),
        ("recursion.md", "circuit preimage4", "preimage4"),
        ("circuits.md", "circuit math_polynomial4", "math_polynomial4"),
        ("air.md", "fn step", "arith4_m31"),
    ):
        relation, _ = compile_text(text_block(DOCS / chapter, prefix), chapter)
        expected = json.loads((S31 / "examples" / f"{fixture}.s31.json").read_text())
        assert relation == expected, f"{chapter}: example differs from checked relation"

    hash_relation, _ = compile_text(
        text_block(DOCS / "hashes.md", "circuit merkle_path1_poseidon"), "hashes.md"
    )
    assert [node["op"] for node in hash_relation["nodes"]] == [
        "hash_poseidon2_leaf", "select", "select", "hash_poseidon2_pair"
    ]
    library_relation, _ = compile_text(
        text_block_containing(DOCS / "library.md", "circuit mathlib4"), "library.md"
    )
    checked_library, _ = compile_text((S31 / "examples/mathlib4.s31").read_text())
    assert library_relation == checked_library
    library_assignment = json.loads((S31 / "examples/mathlib4.valid.json").read_text())
    assert library_assignment["public_outputs"]["result"] == [
        (2 * x + 3 * (2 * x**3 + 3 * x**2 + 5 * x + 7) + 11) % P
        for x in library_assignment["public_inputs"]["x"]
    ]
    matrix_source = text_block_containing(DOCS / "library.md", "circuit static_matvec")
    matrix_relation, _ = compile_text(matrix_source, "library.md")
    assert matrix_relation == json.loads((S31 / "examples/static_matvec.s31.json").read_text())
    matrix_assignment = json.loads((S31 / "examples/static_matvec.valid.json").read_text())
    assert evaluate_relation(matrix_relation, matrix_assignment) == {"total": [44]}
    views_source = text_block_containing(DOCS / "library.md", "circuit array_views")
    views_relation, _ = compile_text(views_source, "library.md")
    assert views_relation == json.loads((S31 / "examples/array_views.s31.json").read_text())
    views_assignment = json.loads((S31 / "examples/array_views.valid.json").read_text())
    assert evaluate_relation(views_relation, views_assignment) == {"result": [18]}
    assert [node["op"] for node in views_relation["nodes"]] == [
        "array_concat", "array_get", "array_get", "add"]
    lane_source = text_block_containing(DOCS / "library.md", "circuit lane_stats4")
    lane_relation, _ = compile_text(lane_source, "library.md")
    fixture_relation, _ = compile_text((S31 / "examples/lane_stats4.s31").read_text())
    assert lane_relation == fixture_relation
    assert [node["op"] for node in lane_relation["nodes"]] == [
        "sum_lanes", "mul", "sum_lanes", "add"
    ]
    lane_assignment = json.loads((S31 / "examples/lane_stats4.valid.json").read_text())
    xs = lane_assignment["private_inputs"]["x"]
    weights = lane_assignment["private_inputs"]["weights"]
    assert lane_assignment["public_outputs"]["result"] == [
        (sum(xs) + sum(x * w for x, w in zip(xs, weights))) % P
    ]
    assert evaluate_relation(lane_relation, lane_assignment) == {"result": [296]}
    division_relation, _ = compile_text(
        text_block_containing(DOCS / "library.md", "circuit field_div4"), "library.md"
    )
    checked_division = json.loads((S31 / "examples/field_div4.s31.json").read_text())
    assert division_relation == checked_division
    division_assignment = json.loads((S31 / "examples/field_div4.valid.json").read_text())
    assert evaluate_relation(division_relation, division_assignment) == division_assignment["public_outputs"]
    division_assignment["private_inputs"]["denominator"][3] = 0
    try:
        evaluate_relation(division_relation, division_assignment)
    except OracleError:
        pass
    else:
        raise AssertionError("division by zero accepted by independent oracle")
    zero_relation, _ = compile_text(
        text_block_containing(DOCS / "library.md", "circuit computed_choice"), "library.md"
    )
    assert zero_relation == json.loads((S31 / "examples/computed_choice.s31.json").read_text())
    zero_assignment = json.loads((S31 / "examples/computed_choice.valid.json").read_text())
    assert evaluate_relation(zero_relation, zero_assignment) == zero_assignment["public_outputs"]
    bitcoin_relation, _ = compile_text(
        text_block_containing(DOCS / "bitcoin-sha256d.md", "circuit bitcoin_header_pow"),
        "bitcoin-sha256d.md",
    )
    checked_bitcoin, _ = compile_text((S31 / "examples/bitcoin_header_pow.s31").read_text())
    assert bitcoin_relation == checked_bitcoin
    bitcoin_assignment = json.loads((S31 / "examples/bitcoin_header_hash.valid.json").read_text())
    assert evaluate_relation(bitcoin_relation, bitcoin_assignment) == bitcoin_assignment["public_outputs"]
    pair_relation, _ = compile_text(
        text_block_containing(DOCS / "bitcoin-sha256d.md", "circuit bitcoin_header_pair"),
        "bitcoin-sha256d.md",
    )
    checked_pair, _ = compile_text((S31 / "examples/bitcoin_header_pair_typed.s31").read_text())
    assert pair_relation == checked_pair
    old_pair, _ = compile_text((S31 / "examples/bitcoin_header_pair.s31").read_text())
    assert pair_relation == old_pair
    assert pair_relation == json.loads((S31 / "examples/bitcoin_header_pair.s31.json").read_text())
    pair_assignment = json.loads((S31 / "examples/bitcoin_header_pair.valid.json").read_text())
    assert evaluate_relation(pair_relation, pair_assignment) == pair_assignment["public_outputs"]
    link_relation, _ = compile_text(
        text_block_containing(DOCS / "bitcoin-sha256d.md", "circuit bitcoin_header_link"),
        "bitcoin-sha256d.md",
    )
    checked_link, _ = compile_text((S31 / "examples/bitcoin_header_link.s31").read_text())
    assert link_relation == checked_link
    link_assignment = json.loads((S31 / "examples/bitcoin_header_link.valid.json").read_text())
    assert evaluate_relation(link_relation, link_assignment) == link_assignment["public_outputs"]
    worked = DOCS / "worked-proofs.md"
    worked_lane, _ = compile_text(text_block(worked, "use std@1;"), "worked-proofs.md")
    assert worked_lane == lane_relation
    assert json_block_containing(worked, '"name": "lane_stats4"') == lane_relation
    recurrence, _ = compile_text(text_block(worked, "fn step"), "worked-proofs.md")
    assert recurrence == json_block_containing(worked, '"name": "square7_16"')
    assert recurrence["nodes"] == [{
        "name": "result", "op": "repeat", "lhs": "x", "rounds": 16,
        "body": [{"op": "square"}, {"op": "add_const", "constant": 7}],
    }]
    states = [[1, 2, 3, 4]]
    for _ in range(16):
        states.append([(x * x + 7) % P for x in states[-1]])
    assert states[1:4] == [
        [8, 11, 16, 23], [71, 128, 263, 536], [5048, 16391, 69176, 287303]
    ]
    assert states[16] == [1737765234, 2070257821, 1388597838, 1651172055]
    recurrence_assignment = json_block_containing(worked, '"public_inputs": {"x"')
    assert recurrence_assignment == {
        "public_inputs": {"x": states[0]}, "private_inputs": {},
        "public_outputs": {"result": states[16]},
    }
    assert evaluate_relation(recurrence, recurrence_assignment) == {"result": states[16]}

    # This example crosses source, normalized relation, bit gate, two valid
    # assignments, and a hand-factorized constraint polynomial.
    choice_doc = DOCS / "worked-choice.md"
    choice, _ = compile_text(
        text_block(choice_doc, "circuit choose_square_plus_seven"), "worked-choice.md"
    )
    assert choice == json_block_containing(choice_doc, '"name": "choose_square_plus_seven"')
    assert [node["op"] for node in choice["nodes"]] == [
        "mul", "mul", "add_const", "add_const", "select"
    ]
    chosen = json_block_containing(choice_doc, '"public_inputs": {"x"')
    assert chosen == {
        "public_inputs": {"x": [3], "y": [4]},
        "private_inputs": {"direction": [1]},
        "public_outputs": {"result": [23]},
    }
    assert evaluate_relation(choice, chosen) == {"result": [23]}
    for bit, result in [(0, 16), (1, 23)]:
        alternative = {
            **chosen, "private_inputs": {"direction": [bit]},
            "public_outputs": {"result": [result]},
        }
        assert evaluate_relation(choice, alternative) == {"result": [result]}
        assert (bit * bit - bit) % P == 0
        assert (result - (1 - bit) * 16 - bit * 23) % P == 0
    for t in range(5):
        a, b, c = 3 + t, 3 + t, 9 + 7 * t
        assert (c - a * b - (-t * (t - 1))) % P == 0

    wide_doc = DOCS / "wide-values.md"
    wide_relation, _ = compile_text(
        text_block_containing(wide_doc, "circuit wide_order"), "wide-values.md"
    )
    assert wide_relation == json.loads((S31 / "examples/wide_order.s31.json").read_text())
    wide_assignment = json.loads((S31 / "examples/wide_order.valid.json").read_text())
    wide_values = wide_assignment["private_inputs"]
    h = wide_values["digest_bytes"]
    target = wide_values["target"]
    assert h == [65535] + [0] * 14 + [32768]
    assert target == [0, 1] + [0] * 13 + [32768]
    assert int.from_bytes(encode_u256_le(h), "little") + 1 == int.from_bytes(encode_u256_le(target), "little")
    assert decode_u256_le(encode_u256_le(h)) == h
    assert evaluate_relation(wide_relation, wide_assignment) == wide_assignment["public_outputs"]
    assert wide_assignment["public_outputs"]["root"] == [
        1516562408, 720678098, 331586352, 1266462312,
        857462184, 360942592, 889867968, 271788129,
    ]

    sub_relation, _ = compile_text(
        text_block_containing(wide_doc, "circuit u256_sub_checked"), "wide-values.md"
    )
    sub_source, _ = compile_text(
        (S31 / "examples/u256_sub_checked.s31").read_text(), "u256_sub_checked.s31"
    )
    assert sub_relation == sub_source
    sub_assignment = json.loads((S31 / "examples/u256_sub_checked.valid.json").read_text())
    operands = sub_assignment["private_inputs"]
    assert int.from_bytes(encode_u256_le(operands["total"]), "little") - int.from_bytes(
        encode_u256_le(operands["previous"]), "little") == 8
    assert evaluate_relation(sub_relation, sub_assignment) == sub_assignment["public_outputs"]
    assert sub_assignment["public_outputs"]["root"] == [
        552785778, 528026874, 1337939194, 1238002988,
        529560134, 669980742, 1274389821, 1249346016,
    ]
    wrap_relation, _ = compile_text(
        (S31 / "examples/u256_sub_wrap.s31").read_text(), "u256_sub_wrap.s31"
    )
    wrap_assignment = json.loads((S31 / "examples/u256_sub_wrap.valid.json").read_text())
    assert evaluate_relation(wrap_relation, wrap_assignment) == wrap_assignment["public_outputs"]
    assert int.from_bytes(encode_u256_le(wrap_assignment["private_inputs"]["total"]), "little") - int.from_bytes(
        encode_u256_le(wrap_assignment["private_inputs"]["previous"]), "little") == -1
    subtraction_record = json.loads((ROOT / "design/s31/measurements/u256-subtraction-v1-2026-10-07.json").read_text())
    assert subtraction_record["schema"] == "s31-u256-subtraction-v1"
    assert all(subtraction_record[name] is True for name in (
        "checked_underflow_rejected", "cross_key_replay_rejected",
        "same_claim_cross_key_replay_rejected", "damaged_proofs_rejected",
        "changed_public_statements_rejected"))
    assert [subtraction_record["profiles"][mode]["proof_bytes"]
            for mode in ("checked", "wrap")] == [231674, 238493]
    assert [subtraction_record["profiles"][mode]["raw"]["qm31_ops"]
            for mode in ("checked", "wrap")] == [7744, 7743]
    assert all(subtraction_record["profiles"][mode]["padded"]["eq"] == 32
               for mode in ("checked", "wrap"))
    check_historical_source_hashes(subtraction_record["source_sha256"])
    for filename, digest in subtraction_record["fixture_sha256"].items():
        mode, extension = filename.split(".", 1)
        assert hashlib.sha256((S31 / "examples" / f"u256_sub_{mode}.{extension}").read_bytes()).hexdigest() == digest

    # Check the packed-reduction witness values written in the teaching gate table.
    inverse_five = pow(5, -1, P)
    dual = (1, P - 1, inverse_five, (-3 * inverse_five) % P)
    assert dual == (1, 2147483646, 858993459, 1717986917)

    def qm31_mul(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[int, ...]:
        # i²=-1, u²=2+i, with coordinate basis (1,i,u,iu).
        def cmul(x: tuple[int, int], y: tuple[int, int]) -> tuple[int, int]:
            return ((x[0] * y[0] - x[1] * y[1]) % P,
                    (x[0] * y[1] + x[1] * y[0]) % P)
        low = cmul(a[:2], b[:2])
        high = cmul(a[2:], b[2:])
        cross_a = cmul(a[:2], b[2:])
        cross_b = cmul(a[2:], b[:2])
        return ((low[0] + 2 * high[0] - high[1]) % P,
                (low[1] + high[0] + 2 * high[1]) % P,
                (cross_a[0] + cross_b[0]) % P,
                (cross_a[1] + cross_b[1]) % P)

    products = [x * w % P for x, w in zip(xs, weights)]
    assert qm31_mul(tuple(xs), dual) == (17, 3, 858993473, 1717986919)
    assert qm31_mul(tuple(products), dual) == (279, 65, 1288490434, 429496772)
    for t in range(5):
        a, b, c = 2 + 15 * t, 11 + 268 * t, 22 + 274 * t
        z = t * (t - 1)
        assert ((1 - t) * (c - a * b) - z * (427 + 4020 * t)) % P == 0
        assert (t * (c - a - b) - z * (-9)) % P == 0
    assignment = json.loads((S31 / "examples/math_polynomial4.valid.json").read_text())
    assert assignment["public_outputs"]["result"] == [
        (pow(x, 5, P) + 3 * x - 7) % P for x in assignment["public_inputs"]["x"]
    ]
    first = reference_iterate([1, 2, 3, 4], 1, ({"op": "square"}, {"op": "add_const", "constant": 7}))
    second = reference_iterate(first, 1, ({"op": "square"}, {"op": "add_const", "constant": 7}))
    assert first == [8, 11, 16, 23] and second == [71, 128, 263, 536]
    secret = [1, 2, 3, 42]
    assert [x * x % P for x in secret] == [1, 4, 9, 1764]
    assert [(x * x + 7) % P for x in secret] == [8, 11, 16, 1771]


def check_hashes() -> None:
    fixture = json.loads((DOCS / "poseidon2-constants.json").read_text())
    assert fixture["source_sha256"] == poseidon.CONSTANTS_SHA256
    assert fixture["external_round"] == poseidon.EXTERNAL
    assert fixture["internal_round"] == poseidon.INTERNAL
    assert fixture["internal_matrix"] == poseidon.DIAGONAL
    leaf = poseidon.leaf(list(range(1, 9)))
    sibling = [100 * x for x in range(1, 9)]
    assert leaf == [1028419626, 840344419, 441147974, 1658139767,
                    1562726555, 572367908, 1125001664, 1414944824]
    assignment = json.loads((S31 / "examples/merkle_path1_poseidon.valid.json").read_text())
    assert poseidon.pair(sibling, leaf) == assignment["public_outputs"]["root"]
    merkle_relation, _ = compile_text(
        (S31 / "examples/merkle_path1_poseidon.s31").read_text(), "merkle_path1_poseidon.s31"
    )
    assert evaluate_relation(merkle_relation, assignment) == assignment["public_outputs"]
    changed_merkle = json.loads(json.dumps(assignment))
    changed_merkle["public_outputs"]["root"][0] += 1
    try:
        evaluate_relation(merkle_relation, changed_merkle)
    except OracleError:
        pass
    else:
        raise AssertionError("changed Merkle root passed the independent oracle")
    blake_relation = json.loads((S31 / "examples/hash4.s31.json").read_text())
    blake_assignment = json.loads((S31 / "examples/hash4.valid.json").read_text())
    assert evaluate_relation(blake_relation, blake_assignment) == blake_assignment["public_outputs"]

    chapter = (DOCS / "hashes.md").read_text()
    iv_text = re.search(r"IV words:\n\n```text\n(.*?)\n```", chapter, re.S)
    sigma_text = re.search(r"The ten `sigma` rows are:\n\n```text\n(.*?)\n```", chapter, re.S)
    assert iv_text and sigma_text
    documented_iv = [int(word, 16) for word in re.findall(r"[0-9A-F]{8}", iv_text.group(1))]
    blake_source = (ROOT / "src/frontends/circuit/builder/blake.zig").read_text()
    source_iv = re.search(r"pub const blake2s_iv = \[8\]u32\{([^}]+)\}", blake_source)
    assert source_iv
    assert documented_iv == [int(word, 16) for word in re.findall(r"0x[0-9A-F]+", source_iv.group(1))]

    documented_sigma = [[int(word) for word in re.findall(r"\d+", row.split(":", 1)[1])]
                        for row in sigma_text.group(1).splitlines()]
    sigma_source = (ROOT / "src/core/crypto/blake_sigma.zig").read_text()
    sigma_body = sigma_source.split("pub const BLAKE_SIGMA =", 1)[1].split("\n};", 1)[0]
    source_sigma = [[int(word) for word in re.findall(r"\d+", row)]
                    for row in re.findall(r"\.\{([^{}]+)\}", sigma_body)]
    assert documented_sigma == source_sigma


def check_documented_measurement() -> None:
    report = json.loads((ROOT / "design/s31/measurements/packed-reduction-2026-10-06.json").read_text())
    assert report["case"]["lowering"] == "direct-gate"
    assert report["case"]["measured_trials_per_version"] == 10
    before, after = report["results"]["baseline"], report["results"]["packed"]
    assert before["canonical_ir_sha256"] == after["canonical_ir_sha256"]
    assert (before["raw"]["qm31_ops"], after["raw"]["qm31_ops"]) == (639, 474)
    assert (before["padded"]["qm31_ops"], after["padded"]["qm31_ops"]) == (1024, 512)
    assert (before["median_proof_bytes"], after["median_proof_bytes"]) == (73567.5, 55578.0)
    assert round(before["median_prove_excluding_pow_seconds"] * 1000, 3) == 1.983
    assert round(after["median_prove_excluding_pow_seconds"] * 1000, 3) == 1.358
    assert round(before["median_wall_proving_seconds"] * 1000) == 117
    assert round(after["median_wall_proving_seconds"] * 1000) == 111
    assert all(result["valid_proof_accepted"] and result["changed_public_output_rejected"]
               for result in (before, after))

    input_report = json.loads((ROOT / "design/s31/measurements/packed-inputs-2026-10-06.json").read_text())
    assert input_report["case"]["lowering"] == "direct-gate"
    assert input_report["case"]["measured_proofs_per_version"] == 7
    old, new = input_report["scalar_input"], input_report["packed_input"]
    assert old["canonical_ir_sha256"] == new["canonical_ir_sha256"]
    assert (old["raw"]["qm31_ops"], new["raw"]["qm31_ops"]) == (650, 361)
    assert (old["padded"]["qm31_ops"], new["padded"]["qm31_ops"]) == (1024, 512)
    assert (old["preprocessed_cells"], new["preprocessed_cells"]) == (8192, 4096)
    assert (old["median_proof_bytes"], new["median_proof_bytes"]) == (72944, 55719)
    assert round(old["median_prove_excluding_pow_seconds"] * 1000, 3) == 2.305
    assert round(new["median_prove_excluding_pow_seconds"] * 1000, 3) == 1.490
    assert round(old["median_wall_proving_seconds"] * 1000) == 94
    assert round(new["median_wall_proving_seconds"] * 1000) == 152
    assert all(result["valid_proof_accepted"] and result["changed_public_output_rejected"]
               for result in (old, new))


def check_recursive_examples() -> None:
    records = ROOT / "design/s31/measurements"

    def documented_words(chapter: str, label: str) -> list[int]:
        match = re.search(rf"{label} = \[([^]]+)\]", chapter, re.S)
        assert match, f"missing documented {label} words"
        return [int(word) for word in re.findall(r"\d+", match.group(1))]

    def digest(prefix: bytes, words: list[int], person: bytes) -> list[int]:
        message = prefix + struct.pack("<8I", *words)
        return list(struct.unpack("<8I", hashlib.blake2s(message, person=person).digest()))

    gate = json.loads((records / "fixed-fold-u32-hand-example-2026-10-07.json").read_text())
    gate_doc = (DOCS / "recursion-fold.md").read_text()
    gate_source = S31 / "examples/arith4_m31.s31"
    assert gate["source_sha256"] == hashlib.sha256(gate_source.read_bytes()).hexdigest()
    assert gate["first_wrapper_digest_d1"] == digest(
        bytes.fromhex(gate["leaf_key_sha256"]), gate["leaf_public_words_w0"], b"S31RCV2!"
    )
    assert documented_words(gate_doc, "D1") == gate["first_wrapper_digest_d1"]
    outer_doc = (DOCS / "recursion.md").read_text()
    outer_match = re.search(r"For this fixture the outer digest.*?```text\n(.*?)\n```", outer_doc, re.S)
    assert outer_match
    assert [int(word) for word in re.findall(r"\d+", outer_match.group(1))] == gate["first_wrapper_digest_d1"]
    assert gate["fold_preprocessed_root"] in gate_doc
    for step, words in gate["fold_public_words_by_step"].items():
        assert words == digest(bytes.fromhex(gate["fold_preprocessed_root"]) +
                               struct.pack("<I", int(step)),
                               gate["first_wrapper_digest_d1"], b"S31FOL2!")
    for step in ("0", "1", "2", "3", "65536"):
        assert str(gate["fold_public_words_by_step"][step][0]) in gate_doc
    assert gate["native_fold0_verified"] is True

    chain = json.loads((records / "preimage-chain-hand-example-2026-10-07.json").read_text())
    chain_doc = (DOCS / "recursion-chain.md").read_text()
    assert chain["source_sha256"] == hashlib.sha256((S31 / "examples/preimage4.s31").read_bytes()).hexdigest()
    assert chain["first_wrapper_digest_d1"] == digest(
        bytes.fromhex(chain["leaf_key_sha256"]), chain["leaf_public_words_w0"], b"S31RCV2!"
    )
    assert chain["second_wrapper_digest_d2"] == digest(
        bytes.fromhex(chain["first_key_sha256"]), chain["first_wrapper_digest_d1"], b"S31RCV2!"
    )
    assert documented_words(chain_doc, "D1") == chain["first_wrapper_digest_d1"]
    assert documented_words(chain_doc, "D2") == chain["second_wrapper_digest_d2"]
    assert chain["native_two_level_verified"] is True

    wide = json.loads((records / "sparse-wide-fold-u32-v1-2026-10-07.json").read_text())
    wide_doc = (DOCS / "recursion-wide-fold.md").read_text()
    assert gate["compiler_sha256"] == chain["compiler_sha256"] == wide["compiler_sha256"]
    assert wide["source_sha256"] == hashlib.sha256((S31 / "examples/wide_order.s31").read_bytes()).hexdigest()
    assert wide["fold_preprocessed_root"] in wide_doc
    wide_d2_match = re.search(r"The checked `D2` is\s*```text\n(.*?)\n```", wide_doc, re.S)
    assert wide_d2_match
    assert [int(word) for word in re.findall(r"\d+", wide_d2_match.group(1))] == wide["base_public_words_d2"]
    assert wide["fold_public_words_first_words"] == [
        digest(bytes.fromhex(wide["fold_preprocessed_root"]) + struct.pack("<I", step),
               wide["base_public_words_d2"], b"S31FOL2!")[0] for step in range(3)
    ]
    wide_rows = [line for line in wide_doc.splitlines() if line.startswith("| `F")]
    assert [int(re.search(r"\| (\d+) \|$", line).group(1)) for line in wide_rows] == wide["fold_public_words_first_words"]

    bitcoin = json.loads((records / "bitcoin-sparse-wide-fold-u32-v1-2026-10-07.json").read_text())
    assert bitcoin["source_sha256"] == hashlib.sha256((S31 / "examples/bitcoin_header_pair.s31").read_bytes()).hexdigest()
    assert bitcoin["compiler_sha256"] == wide["compiler_sha256"]
    assert bitcoin["base_and_next_audit_rejections"] == [24, 24]
    assert "u32_counter_overflow_before_output" in bitcoin["host_negative_checks"]
    assert bitcoin["fold_geometry"]["padded_rows"] == wide["fold_geometry"]["padded_rows"]
    for step, first_word in enumerate(bitcoin["fold_public_words_first_words"]):
        assert digest(bytes.fromhex(bitcoin["fold_preprocessed_root"]) + struct.pack("<I", step),
                      bitcoin["base_public_words_d2"], b"S31FOL2!")[0] == first_word
    assert all(f"{size:,}" in wide_doc for size in
               bitcoin["proof_bytes_leaf_first_second_fold0_fold1_fold2"][3:])

    direct_step = json.loads((records / "bitcoin-direct-fold-step-v1-2026-10-07.json").read_text())
    assert direct_step["sha256d_sha256"] == hashlib.sha256((S31 / "sha256d.zig").read_bytes()).hexdigest()
    check_historical_source_hashes({"bitcoin_fold_step.zig": direct_step["source_sha256"]})
    assert direct_step["naive_additive_qm31_ops"] == (
        direct_step["existing_bitcoin_claim_fold_reference"]["qm31_ops"]
        + direct_step["direct_step"]["raw"]["qm31_ops"]
    )
    old_bitcoin_fold = json.loads((records / "bitcoin-chain-fold-topology-v1-2026-10-07.json").read_text())
    assert old_bitcoin_fold["schema"] == "s31-bitcoin-chain-fold-topology-v1"
    check_historical_source_hashes(old_bitcoin_fold["source_sha256"])
    bitcoin_fold = json.loads((records / "bitcoin-chain-fold-topology-v2-2026-10-07.json").read_text())
    assert bitcoin_fold["schema"] == "s31-bitcoin-chain-fold-topology-v2"
    assert bitcoin_fold["projection_sha256"] == hashlib.sha256(
        (ROOT / "vectors/circuit/official/compiled_air_constraints_v1.bin").read_bytes()
    ).hexdigest()
    assert bitcoin_fold["reference_sha256"] == hashlib.sha256(
        (records / "bitcoin-sparse-wide-fold-stages-v1-2026-10-07.json").read_bytes()
    ).hexdigest()
    check_historical_source_hashes(bitcoin_fold["source_sha256"])
    fold_cases = {case["case"]: case for case in bitcoin_fold["cases"]}
    base_fold = fold_cases["candidate-base"]
    assert len(fold_cases) == 8
    assert base_fold["fixed_point"] is True
    assert base_fold["raw"]["qm31_ops"] == 1150616
    assert base_fold["raw"]["eq"] == 32077
    assert base_fold["raw_vars"] == 5953038
    assert base_fold["padded"] == bitcoin_fold["candidate_padded_rows"]
    assert base_fold["preprocessed_root"] == bitcoin_fold["candidate_preprocessed_root"]
    assert base_fold["anchor_root"] == bitcoin_fold["anchor_preprocessed_root"]
    assert all(case["anchor_root"] == bitcoin_fold["anchor_preprocessed_root"]
               for case in bitcoin_fold["cases"])
    current_bitcoin_fold = json.loads((records / "bitcoin-chain-fold-topology-v3-2026-10-07.json").read_text())
    assert current_bitcoin_fold["schema"] == "s31-bitcoin-chain-fold-topology-v3"
    assert current_bitcoin_fold["source_sha256"] == {
        name: hashlib.sha256((S31 / name).read_bytes()).hexdigest()
        for name in current_bitcoin_fold["source_sha256"]
    }
    current_cases = {case["case"]: case for case in current_bitcoin_fold["cases"]}
    assert len(current_cases) == 8
    assert current_cases["candidate-base"]["fixed_point"] is True
    assert current_cases["candidate-base"]["preprocessed_root"] == current_bitcoin_fold["candidate_preprocessed_root"]
    assert current_cases["candidate-base"]["padded"] == current_bitcoin_fold["candidate_padded_rows"]
    assert all(current_cases[name]["preprocessed_root"] == current_bitcoin_fold["candidate_preprocessed_root"]
               for name in ("candidate-recursive", "candidate-u16-carry", "candidate-u32-max"))
    assert all(current_cases[name]["preprocessed_root"] != current_bitcoin_fold["candidate_preprocessed_root"]
               for name in ("changed-checkpoint", "changed-base-root"))
    assert all(fold_cases[name]["preprocessed_root"] == base_fold["preprocessed_root"]
               for name in ("candidate-recursive", "candidate-u16-carry", "candidate-u32-max"))
    assert all(fold_cases[name]["preprocessed_root"] != base_fold["preprocessed_root"]
               for name in ("changed-checkpoint", "changed-base-root"))
    bitcoin_doc = (DOCS / "bitcoin-sha256d.md").read_text()
    assert all(f"{value:,}" in bitcoin_doc for value in (
        direct_step["direct_step"]["raw_vars"],
        direct_step["direct_step"]["raw"]["qm31_ops"],
    ))
    current_base_fold = current_cases["candidate-base"]
    assert all(f"{value:,}" in bitcoin_doc for value in
               (current_base_fold["raw_vars"], current_base_fold["raw"]["qm31_ops"],
                current_base_fold["padded"]["qm31_ops"], current_base_fold["padded"]["eq"]))

    old_two_step = json.loads((records / "bitcoin-chain-two-step-proof-v1-2026-10-07.json").read_text())
    assert old_two_step["schema"] == "s31-bitcoin-chain-two-step-proof-v1"
    check_historical_source_hashes(old_two_step["source_sha256"])
    two_step = json.loads((records / "bitcoin-chain-two-step-proof-v2-2026-10-07.json").read_text())
    assert two_step["schema"] == "s31-bitcoin-chain-two-step-proof-v2"
    assert two_step["topology_record_sha256"] == hashlib.sha256(
        (records / "bitcoin-chain-fold-topology-v2-2026-10-07.json").read_bytes()
    ).hexdigest()
    assert two_step["air_bundle_sha256"] == hashlib.sha256(
        (ROOT / "vectors/circuit/official/circuit_air.air_programs_v1.bin").read_bytes()
    ).hexdigest()
    assert two_step["projection_sha256"] == bitcoin_fold["projection_sha256"]
    check_historical_source_hashes(two_step["source_sha256"])
    assert two_step["native_verification_passed"] is True
    assert two_step["changed_public_statement_rejected_at_both_fold_steps"] is True
    assert two_step["forged_prior_state_rejected_by_full_circuit"] is True
    assert two_step["standalone_key_statement_and_replay_checks_passed"] is True
    assert len(bytes.fromhex(two_step["sealed_key_sha256"])) == 32
    observations = two_step["observations"]
    assert observations["checkpoint anchor"]["preprocessed_root"] == bitcoin_fold["anchor_preprocessed_root"]
    assert all(observations[name]["preprocessed_root"] == bitcoin_fold["candidate_preprocessed_root"]
               for name in ("chain fold step 0", "chain fold step 1"))
    current_two_step = json.loads((records / "bitcoin-chain-two-step-proof-v3-2026-10-07.json").read_text())
    assert current_two_step["schema"] == "s31-bitcoin-chain-two-step-proof-v3"
    assert current_two_step["topology_record_sha256"] == hashlib.sha256(
        (records / "bitcoin-chain-fold-topology-v3-2026-10-07.json").read_bytes()
    ).hexdigest()
    assert current_two_step["source_sha256"] == {
        name: hashlib.sha256((S31 / name).read_bytes()).hexdigest()
        for name in current_two_step["source_sha256"]
    }
    assert current_two_step["native_verification_passed"] is True
    assert current_two_step["changed_public_statement_rejected_at_both_fold_steps"] is True
    assert current_two_step["changed_timestamp_window_rejected"] is True
    assert current_two_step["forged_prior_state_rejected_by_full_circuit"] is True
    assert current_two_step["standalone_key_statement_and_replay_checks_passed"] is True
    assert current_two_step["wrong_step_replay_rejected"] is True
    assert current_two_step["sealed_key_sha256"] in bitcoin_doc
    current_observations = current_two_step["observations"]
    assert current_observations["checkpoint anchor"]["preprocessed_root"] == current_bitcoin_fold["anchor_preprocessed_root"]
    assert all(current_observations[name]["preprocessed_root"] == current_bitcoin_fold["candidate_preprocessed_root"]
               for name in ("chain fold step 0", "chain fold step 1"))
    assert all(f"{item['proof_bytes']:,}" in bitcoin_doc and
               f"{item['prove_seconds']:.3f}" in bitcoin_doc for item in current_observations.values())
    block2 = json.loads((S31 / "examples/bitcoin_block2_header.valid.json").read_text())
    block2_header = bytes.fromhex(block2["header_hex"])
    assert len(block2_header) == 80
    sha256d = lambda data: hashlib.sha256(hashlib.sha256(data).digest()).digest()
    block1_fixture = json.loads((S31 / "examples/bitcoin_header_link.valid.json").read_text())
    block1_header = b"".join(struct.pack("<H", word) for word in block1_fixture["private_inputs"]["child"])
    assert block2_header[4:36] == sha256d(block1_header)
    assert sha256d(block1_header)[::-1].hex() == block2["previous_display_hash"]
    assert sha256d(block2_header)[::-1].hex() == block2["display_hash"]
    assert block2["source"] in bitcoin_doc

    benchmark = json.loads((records / "sparse-wide-fold-u32-batch-memory-2026-10-07.json").read_text())
    assert benchmark["compiler_sha256"] == wide["compiler_sha256"]
    assert benchmark["proofs_and_statements_byte_identical"] is True
    assert benchmark["median_separate_wall_seconds"] == statistics.median(
        trial["separate"]["wall_seconds"] for trial in benchmark["trials"])
    assert benchmark["median_batch_wall_seconds"] == statistics.median(
        trial["batch"]["wall_seconds"] for trial in benchmark["trials"])
    for label in ("median_separate_wall_seconds", "median_batch_wall_seconds"):
        assert f"{benchmark[label]:.3f}" in wide_doc

    topology = json.loads((records / "fold-counter-topology-invariance-2026-10-07.json").read_text())
    assert topology["schema"] == "s31-recursive-counter-topology-invariance-v1"
    assert topology["steps"] == [0, 1, 65535, 65536, 0x80000000, 0xffffffff]
    profiles = {profile["profile"]: profile for profile in topology["profiles"]}
    assert set(profiles) == {"gate-fixed", "gate-state", "sparse-wide-fixed"}
    assert profiles["gate-fixed"]["fold_preprocessed_root"] == gate["fold_preprocessed_root"]
    assert profiles["sparse-wide-fixed"]["fold_preprocessed_root"] == wide["fold_preprocessed_root"]
    assert profiles["sparse-wide-fixed"]["raw_vars"] == wide["fold_geometry"]["raw_vars"]
    assert all(profile["all_report_fields_equal_excluding_step"] is True for profile in profiles.values())
    assert "--step 65536" in gate_doc and "--step 65536" in wide_doc
    assert "--step 65536" in (DOCS / "state-fold.md").read_text()


def check_links() -> None:
    for chapter in DOCS.glob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", chapter.read_text()):
            if target.startswith(("http:", "https:", "#")):
                continue
            path = (chapter.parent / target.split("#", 1)[0]).resolve()
            assert path.exists(), f"{chapter.name}: broken link {target}"

    for figure in (DOCS / "figures").glob("*.svg"):
        root = ElementTree.parse(figure).getroot()
        assert root.tag.endswith("svg"), f"{figure.name}: invalid SVG root"
        assert root.find("{http://www.w3.org/2000/svg}title") is not None


if __name__ == "__main__":
    check_examples()
    check_hashes()
    check_documented_measurement()
    check_recursive_examples()
    check_links()
    print("S31 docs: examples, hash constants, links, and figures agree")
