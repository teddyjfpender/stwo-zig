from __future__ import annotations

import unittest
from pathlib import Path

from scripts import check_package_workspace as subject


ROOT = Path(__file__).resolve().parents[2]


class PackageWorkspaceTests(unittest.TestCase):
    def test_repository_contracts_pass(self) -> None:
        self.assertEqual([], subject.check_repository(ROOT))

    def test_dependency_cycles_are_reported(self) -> None:
        self.assertEqual(
            [["core", "prover", "core"]],
            subject.dependency_cycles(
                {
                    "core": {"prover"},
                    "prover": {"core"},
                }
            ),
        )

    def test_api_parser_uses_only_top_level_public_declarations(self) -> None:
        self.assertEqual(
            ["Root", "run"],
            subject.top_level_api(
                """
pub const Root = struct {
    pub const nested = 1;
};
pub fn run() void {}
"""
            ),
        )

    def test_comment_imports_are_not_dependencies(self) -> None:
        text = """
//! const ignored = @import("legacy");
const std = @import("std");
/* @import("also_ignored") */
"""
        self.assertEqual(["std"], subject.IMPORT_RE.findall(subject.strip_comments(text)))


if __name__ == "__main__":
    unittest.main()
