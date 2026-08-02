"""Production anti-sprawl ratchet for top-level ``scripts/`` entrypoints.

A production script earns its place through an installed workflow, build edge,
machine-readable policy, current owner guide, hook, or another reachable
script. Historical conformance prose and ``autoresearch/`` are deliberately
not roots: mentioning retired code must not keep it alive forever, and research
utilities belong under their own tree. Human-only production/soundness tools
must be declared below with an owner and purpose.
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
    # Owner: release-performance. Produces and validates authenticated host
    # performance receipts; architecture promotion is operator driven.
    "performance_epoch_gate.py":
        "operator performance-epoch receipt and promotion gate",
    # Owner: riscv-soundness. Regenerates and audits Sail-selected operand
    # classes; committed outputs are consumed by the frontend tests.
    "riscv_operand_classes.py":
        "Sail-derived RV32IM operand-class corpus generator and auditor",
}

ENTRY_POINT_GLOBS = (
    "build.zig",
    "build_support/**/*.zig",
    ".github/**/*.yml",
    "conformance/*.json",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
    ".githooks/*",
    "soundness/**/*.md",
    "src/**/README.md",
    "vectors/**/README.md",
    "formal/**/*.md",
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

        declared = set(OPERATOR_TOOLS)
        reachable = set(seeds)
        # Declared operator tools are legitimate roots for their support
        # packages, but remain outside ``reachable`` so stale declarations are
        # still detected below.
        frontier = list(seeds | declared)
        lib_dirs = [
            p for p in SCRIPTS.iterdir()
            if p.is_dir() and p.name not in ("tests", "__pycache__")
            and any(p.rglob("*.py"))
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
            new = _references(text, universe) - reachable - declared
            library_frontier: list[str] = []
            for lib_name, lib_text in lib_texts.items():
                if lib_name in visited_libs:
                    continue
                if re.search(
                    rf"(?:import|from)\s+(?:scripts\.)?{lib_name}\b", text
                ):
                    visited_libs.add(lib_name)
                    library_frontier.append(lib_name)
            while library_frontier:
                lib_name = library_frontier.pop()
                lib_text = lib_texts[lib_name]
                new |= _references(lib_text, universe) - reachable - declared
                for dependency in lib_texts:
                    if dependency in visited_libs:
                        continue
                    if re.search(
                        rf"(?:import|from)\s+(?:scripts\.)?{dependency}\b",
                        lib_text,
                    ):
                        visited_libs.add(dependency)
                        library_frontier.append(dependency)
            reachable |= new
            frontier.extend(new)

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

        unreachable_libraries = sorted(set(lib_texts) - visited_libs)
        self.assertEqual(
            unreachable_libraries,
            [],
            "unreachable script support packages (wire them to a production "
            f"entrypoint or delete them): {unreachable_libraries}",
        )
