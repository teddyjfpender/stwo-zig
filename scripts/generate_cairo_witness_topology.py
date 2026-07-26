#!/usr/bin/env python3
"""Generate the source-derived feed topology for official Cairo witnesses."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPILER_ROOT = ROOT / "tools/cairo-witness-compiler"
sys.path.insert(0, str(COMPILER_ROOT))

import orchestrator as witness_compiler  # noqa: E402


SCHEMA = "stwo-zig-cairo-witness-feed-topology-v1"
VERSION = 1
NAME_PATTERN = r"[a-z][a-z0-9_]*"
SUB_WORDS_RE = re.compile(
    r"pub\(crate\) const N_SUB_INPUT_WORDS:\s*usize\s*=\s*(?P<count>\d+);"
)
FEED_BLOCK_RE = re.compile(
    r"pub\(crate\) const SUB_FEED_LAYOUT:.*?=\s*&\[(?P<body>.*?)\];",
    re.DOTALL,
)
FEED_RE = re.compile(
    r"\(\s*"
    rf'"(?P<field>{NAME_PATTERN})"\s*,\s*'
    r"(?P<instance>\d+)\s*,\s*"
    rf'"(?P<target>{NAME_PATTERN})_state"\s*,\s*'
    r"(?P<relation>\d+)\s*,\s*"
    r"(?P<base>\d+)\s*,\s*"
    r"(?P<width>\d+)\s*,?\s*"
    r"\)",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Feed:
    field: str
    instance: int
    target: str
    relation: int
    word_base: int
    words_per_instance: int


@dataclass(frozen=True)
class Component:
    producer: str
    sub_words_per_row: int
    feeds: tuple[Feed, ...]


def _run(args: list[str | Path], *, cwd: Path) -> str:
    result = subprocess.run(
        [str(value) for value in args],
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostics"
        raise RuntimeError(f"{Path(args[0]).name} failed: {detail}")
    return result.stdout


def parse_component(source: str, producer: str) -> Component:
    sub_words_match = SUB_WORDS_RE.search(source)
    feed_block = FEED_BLOCK_RE.search(source)
    if sub_words_match is None or feed_block is None:
        raise ValueError(f"{producer}: generated topology constants are missing")

    feeds = tuple(
        Feed(
            field=match["field"],
            instance=int(match["instance"]),
            target=match["target"],
            relation=int(match["relation"]),
            word_base=int(match["base"]),
            words_per_instance=int(match["width"]),
        )
        for match in FEED_RE.finditer(feed_block["body"])
    )
    if re.sub(r"\s+", "", feed_block["body"]) and not feeds:
        raise ValueError(f"{producer}: feed topology could not be parsed")

    sub_words = int(sub_words_match["count"])
    seen: set[tuple[str, int]] = set()
    for feed in feeds:
        identity = (feed.field, feed.instance)
        if identity in seen:
            raise ValueError(f"{producer}: duplicate feed {identity!r}")
        seen.add(identity)
        if (
            feed.words_per_instance == 0
            or feed.word_base + feed.words_per_instance > sub_words
        ):
            raise ValueError(f"{producer}: feed exceeds flattened sub-input words")
    return Component(
        producer=producer,
        sub_words_per_row=sub_words,
        feeds=feeds,
    )


def generate(source: Path) -> dict[str, object]:
    identity = witness_compiler.authenticate_source(source)
    rewriter = witness_compiler._build_rewriter()
    components_root = source / "crates/prover/src/witness/components"

    with tempfile.TemporaryDirectory(prefix="cairo-witness-topology-") as temporary:
        emitted = Path(temporary)
        _run([rewriter, "--emit-dir", emitted, components_root], cwd=ROOT)
        actual = tuple(sorted(path.stem for path in emitted.glob("*.rs")))
        expected = tuple(sorted(witness_compiler.COMPONENTS))
        if actual != expected:
            raise RuntimeError(
                f"rewriter emitted {len(actual)} components; expected {len(expected)}"
            )
        components = [
            parse_component(
                (emitted / f"{producer}.rs").read_text(encoding="utf-8"),
                producer,
            )
            for producer in actual
        ]

    return {
        "components": [asdict(component) for component in components],
        "generator": {
            "path": "scripts/generate_cairo_witness_topology.py",
            "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "rewriter_closure_sha256": witness_compiler.closure_sha256(
                witness_compiler.REWRITER
            ),
        },
        "schema": SCHEMA,
        "source": asdict(identity),
        "version": VERSION,
    }


def publish(path: Path, value: dict[str, object]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to replace existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.unlink(missing_ok=True)
    try:
        temporary.write_bytes(encoded)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    publish(args.output.resolve(), generate(args.source.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
