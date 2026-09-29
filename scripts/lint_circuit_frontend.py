#!/usr/bin/env python3
"""Reject order-unstable constructs in the circuit recursion frontend.

The circuit frontend (``src/frontends/circuit``) is a call-order-exact port of
StarkWare's circuit recursion stage: variable numbering, constant interning and
gate order are the byte-parity contract (design §3.3 of
``design/starknet-proving-pipeline/recursion/02-design.md``). Any construct
whose output order depends on hashing or on an unstable sort can silently
renumber wires. This lint rejects, outside comments:

* unstable sorts: ``std.sort.pdq``, ``std.sort.heap``, ``sortUnstable`` and
  their ``*Context`` forms. ``std.mem.sort`` is Zig's stable block sort and is
  allowed; it matches Rust's stable ``sort``/``sorted_by_key``;
* hash-map iteration: ``.iterator()``, ``.keyIterator()``,
  ``.valueIterator()``. Ordered (array) hash maps are walked through
  ``keys()``/``values()`` instead. A line that iterates an ordered map on
  purpose carries the waiver comment ``circuit-lint: ordered-iteration``;
* an import of ``stwo_cairo_frontend``: Cairo facts reach the circuit
  frontend only through the committed compiled-AIR projection.

Usage: ``python3 scripts/lint_circuit_frontend.py [--root DIR]``. Exits 1 and
lists every violation as ``path:line: rule: text``.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path("src/frontends/circuit")
WAIVER = "circuit-lint: ordered-iteration"
EXCLUDED_DIRS = {".zig-cache", "zig-cache", "zig-out"}

RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "unstable-sort",
        re.compile(r"\bstd\.sort\.(?:pdq|heap)(?:Context)?\b|\bsortUnstable(?:Context)?\b"),
    ),
    (
        "hash-map-iteration",
        re.compile(r"\.(?:iterator|keyIterator|valueIterator)\(\s*\)"),
    ),
    (
        "cairo-frontend-import",
        re.compile(r'@import\(\s*"stwo_cairo_frontend"\s*\)'),
    ),
)


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    rule: str
    text: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: {self.rule}: {self.text.strip()}"


def strip_comment(line: str) -> str:
    """The code part of a Zig line: everything before a `//` outside a string."""
    in_string = False
    escaped = False
    for i, char in enumerate(line):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif line.startswith("//", i):
            return line[:i]
    return line


def lint_source(path: Path, source: str) -> list[Violation]:
    violations = []
    for number, line in enumerate(source.splitlines(), start=1):
        code = strip_comment(line)
        for rule, pattern in RULES:
            if not pattern.search(code):
                continue
            if rule == "hash-map-iteration" and WAIVER in line:
                continue
            violations.append(Violation(path, number, rule, line))
    return violations


def zig_sources(package_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in package_dir.rglob("*.zig")
        if not EXCLUDED_DIRS.intersection(path.relative_to(package_dir).parts)
    )


def lint_tree(root: Path) -> list[Violation]:
    package_dir = root / PACKAGE
    if not package_dir.is_dir():
        raise FileNotFoundError(f"{package_dir} is not a directory")
    violations = []
    for path in zig_sources(package_dir):
        violations.extend(lint_source(path.relative_to(root), path.read_text(encoding="utf-8")))
    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root")
    args = parser.parse_args(argv)
    violations = lint_tree(args.root)
    for violation in violations:
        print(violation)
    if violations:
        print(f"circuit-lint: {len(violations)} violation(s)", file=sys.stderr)
        return 1
    print(f"circuit-lint: {len(zig_sources(args.root / PACKAGE))} files clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
