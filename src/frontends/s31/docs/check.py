#!/usr/bin/env python3
"""Check copied S31 examples, hash constants, and local documentation links."""

import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree


DOCS = Path(__file__).resolve().parent
S31 = DOCS.parent
ROOT = S31.parents[2]
sys.path.insert(0, str(S31))

import poseidon2_oracle as poseidon  # noqa: E402
from s31_stdlib import P, reference_iterate  # noqa: E402
from text_frontend import compile_text  # noqa: E402


def text_block(path: Path, prefix: str) -> str:
    for block in re.findall(r"(?:```|~~~)(?:text|s31)\n(.*?)\n(?:```|~~~)", path.read_text(), re.S):
        if block.lstrip().startswith(prefix):
            return block
    raise AssertionError(f"{path}: missing {prefix!r} example")


def check_examples() -> None:
    for chapter, prefix, fixture in (
        ("source.md", "circuit preimage4", "preimage4"),
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
        text_block(DOCS / "library.md", "use std@1;"), "library.md"
    )
    checked_library, _ = compile_text((S31 / "examples/mathlib4.s31").read_text())
    assert library_relation == checked_library
    library_assignment = json.loads((S31 / "examples/mathlib4.valid.json").read_text())
    assert library_assignment["public_outputs"]["result"] == [
        (2 * x + 3 * (2 * x**3 + 3 * x**2 + 5 * x + 7) + 11) % P
        for x in library_assignment["public_inputs"]["x"]
    ]
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
    check_links()
    print("S31 docs: examples, hash constants, links, and figures agree")
