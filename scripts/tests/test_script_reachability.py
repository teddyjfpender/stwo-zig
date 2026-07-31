"""Anti-sprawl ratchet: every script must be reachable from a live entry point.

A script in scripts/ earns its place by being wired into the build graph, a
hosted workflow, a conformance policy, a hook, the docs, or another reachable
script — or by being declared in OPERATOR_TOOLS below with an owner and a
one-line purpose. Anything else is dead code and fails this test, so orphans
can never accumulate silently again. Deletion is cheap: everything is
restorable from history.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"

# Operator tools invoked by humans, not gates. Each entry must carry a
# purpose; remove the entry in the same commit that deletes the tool.
OPERATOR_TOOLS: dict[str, str] = {
    # Owner: soundness. Per-row witness-uniqueness checking of an AIR family
    # via z3, from a serialisable constraint IR. Deliberately un-gated: it
    # needs z3, which hosted CI does not install, and no family's IR is
    # emitted from the real modules yet. Its own contracts do run, through
    # scripts/tests/test_air_uniqueness.py in the discovered suite.
    "air_uniqueness.py": "SMT witness-uniqueness checker for AIR families",
    # Owner: soundness. Schedules `air_uniqueness.py` across every emitted
    # family and folds the shard verdicts into one board. Un-gated for the same
    # two reasons as the checker it drives, plus a third: a board is a budgeted
    # measurement, and a gate that fails on a solver timeout would be a gate on
    # the machine it ran on. Its contracts run through
    # scripts/tests/test_air_uniqueness_board.py in the discovered suite.
    "air_uniqueness_board.py": "witness-uniqueness board over every AIR family",
    # Owner: soundness. Constructively proves active-narrow Poseidon2 main-row
    # rigidity and the exact deterministic/conditional-functional relations of
    # all six fixed lookup-table components. It is an operator certificate,
    # not a proof-wire verifier; its exhaustive and mutation contracts run in
    # scripts/tests/test_riscv_poseidon_table_uniqueness.py.
    "riscv_poseidon_table_uniqueness.py":
        "Poseidon2 and fixed-table row-local rigidity certificate",
    # Owner: soundness. Separates row-local infrastructure functionality from
    # the exact LogUp-closure premises needed by program, offline-memory,
    # Merkle, and clock recurrences. Its exhaustive small models, concrete
    # overclaim counterexamples, and production-source mutation contracts run
    # in scripts/tests/test_riscv_infrastructure_uniqueness.py.
    "riscv_infrastructure_uniqueness.py":
        "conditional AIR-infrastructure uniqueness and recurrence certificate",
    # Owner: soundness. Checks the all-path Merkle index/parity induction and
    # the field-depth cycle bound, pinned to the shipped relation and statement
    # guard. Contracts run in scripts/tests/test_riscv_merkle_recurrence.py.
    "riscv_merkle_recurrence.py":
        "sparse-Merkle index and detached-cycle recurrence certificate",
    # Owner: soundness. Checks state-clock cycle order, bounded synthetic clock
    # updates, and the historical wrapped-cycle counterexample. Contracts run
    # in scripts/tests/test_riscv_state_chain_recurrence.py.
    "riscv_state_chain_recurrence.py":
        "state-chain and clock-window recurrence certificate",
}

ENTRY_POINT_GLOBS = (
    "build.zig",
    "build_support/**/*.zig",
    ".github/**/*.yml",
    "conformance/*.json",
    "conformance/*.md",
    "CONTRIBUTING.md",
    "README.md",
    "autoresearch/**/*.py",
    "autoresearch/**/*.yml",
    "autoresearch/**/*.json",
    "autoresearch/**/*.md",
)

REFERENCE_RE = re.compile(r"scripts/([a-z_0-9]+\.py)|\"([a-z_0-9]+\.py)\"")
# A test module invoked directly by an entry point (e.g. hosted CI running
# scripts.tests.test_x as the gate) anchors its subject script.
TEST_MODULE_RE = re.compile(r"scripts\.tests\.test_([a-z_0-9]+)")
IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+(?:scripts\.)?([a-z_0-9]+)", re.MULTILINE
)
FROM_SCRIPTS_GROUP_RE = re.compile(
    r"^\s*from\s+scripts\s+import\s*\((.*?)^\s*\)",
    re.MULTILINE | re.DOTALL,
)
FROM_SCRIPTS_LINE_RE = re.compile(
    r"^\s*from\s+scripts\s+import\s+([^\n(]+)$",
    re.MULTILINE,
)


def _references(text: str, universe: set[str]) -> set[str]:
    found: set[str] = set()
    for match in REFERENCE_RE.finditer(text):
        name = match.group(1) or match.group(2)
        if name in universe:
            found.add(name)
    for match in IMPORT_RE.finditer(text):
        name = f"{match.group(1)}.py"
        if name in universe:
            found.add(name)
    for imports in FROM_SCRIPTS_GROUP_RE.findall(text):
        for module in re.findall(r"\b([a-z_0-9]+)\b", imports):
            name = f"{module}.py"
            if name in universe:
                found.add(name)
    for imports in FROM_SCRIPTS_LINE_RE.findall(text):
        for module in re.findall(r"\b([a-z_0-9]+)\b", imports):
            name = f"{module}.py"
            if name in universe:
                found.add(name)
    return found


class ScriptReachabilityTest(unittest.TestCase):
    def test_every_script_is_reachable_or_declared(self) -> None:
        universe = {p.name for p in SCRIPTS.glob("*.py")}

        seeds: set[str] = set()
        for pattern in ENTRY_POINT_GLOBS:
            for path in ROOT.glob(pattern):
                if not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
                seeds |= _references(text, universe)
                for match in TEST_MODULE_RE.finditer(text):
                    subject = f"{match.group(1)}.py"
                    if subject in universe:
                        seeds.add(subject)

        reachable = set(seeds)
        frontier = list(seeds)
        lib_dirs = [
            p for p in SCRIPTS.iterdir()
            if p.is_dir() and p.name not in ("tests", "__pycache__")
        ]
        # Library packages transitively extend the frontier: a lib used by a
        # reachable script may itself dispatch further scripts (e.g. the
        # architecture host-gate plan).
        lib_texts = {
            lib.name: "\n".join(
                f.read_text(encoding="utf-8", errors="ignore")
                for f in lib.rglob("*.py")
            )
            for lib in lib_dirs
        }
        visited_libs: set[str] = set()
        while frontier:
            current = frontier.pop()
            text = (SCRIPTS / current).read_text(encoding="utf-8", errors="ignore")
            new = _references(text, universe) - reachable
            for lib_name, lib_text in lib_texts.items():
                if lib_name in visited_libs:
                    continue
                if re.search(
                    rf"(?:import|from)\s+(?:scripts\.)?{lib_name}\b", text
                ):
                    visited_libs.add(lib_name)
                    new |= _references(lib_text, universe) - reachable
            reachable |= new
            frontier.extend(new)

        declared = set(OPERATOR_TOOLS)
        undeclared_dead = sorted(universe - reachable - declared)
        self.assertEqual(
            undeclared_dead,
            [],
            "unreachable scripts (wire them into a gate, declare them in "
            f"OPERATOR_TOOLS with a purpose, or delete them): {undeclared_dead}",
        )

        # The declaration list may not shelter reachable scripts: entries must
        # actually be unreachable operator tools, and must exist.
        for name in sorted(declared):
            self.assertIn(name, universe, f"OPERATOR_TOOLS entry gone: {name}")
        sheltered = sorted(declared & reachable)
        self.assertEqual(
            sheltered,
            [],
            f"OPERATOR_TOOLS entries are gate-reachable; remove them: {sheltered}",
        )
