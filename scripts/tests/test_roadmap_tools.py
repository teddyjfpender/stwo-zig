#!/usr/bin/env python3
"""Unit tests for roadmap closure tooling parsers."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROADMAP_AUDIT_PATH = ROOT / "scripts" / "roadmap_audit.py"
ROADMAP_BASELINE_PATH = ROOT / "scripts" / "roadmap_baseline.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RoadmapToolsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = load_module(ROADMAP_AUDIT_PATH, "roadmap_audit")
        self.baseline = load_module(ROADMAP_BASELINE_PATH, "roadmap_baseline")

    def test_parse_roadmap_rows_extracts_table(self) -> None:
        markdown = """
### 15.1 Roadmap Table

| Rust crate | Zig target area | Current status | Remaining required scope | Hard exit criteria |
|---|---|---|---|---|
| `crates/stwo` | `src/core/**` | Partial | complete core path | interop green |
| `crates/examples` | `src/examples/**` | Complete | done | all examples pass |

### 15.2 Required Sequencing
"""
        rows = self.audit.parse_roadmap_rows(markdown)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["rust_crate"], "`crates/stwo`")
        self.assertEqual(rows[0]["current_status"], "Partial")
        self.assertEqual(rows[1]["rust_crate"], "`crates/examples`")
        self.assertEqual(rows[1]["current_status"], "Complete")

    def test_baseline_and_audit_parser_agree(self) -> None:
        markdown = """
### 15.1 Roadmap Table

| Rust crate | Zig target area | Current status | Remaining required scope | Hard exit criteria |
|---|---|---|---|---|
| `crates/std-shims` | `src/std_shims/**` | Partial | add behavior checks | std-shims behavior parity |

### 15.2 Required Sequencing
"""
        audit_rows = self.audit.parse_roadmap_rows(markdown)
        baseline_rows = self.baseline.parse_roadmap_rows(markdown)
        self.assertEqual(audit_rows, baseline_rows)


if __name__ == "__main__":
    unittest.main()
