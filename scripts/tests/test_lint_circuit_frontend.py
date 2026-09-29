"""Tests of the circuit frontend order-stability lint."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from scripts import lint_circuit_frontend as lint


def rules(source: str) -> list[str]:
    return [v.rule for v in lint.lint_source(Path("x.zig"), source)]


class LintCircuitFrontendTest(unittest.TestCase):
    def test_repository_package_is_clean(self) -> None:
        self.assertEqual([], [str(v) for v in lint.lint_tree(lint.ROOT)])

    def test_unstable_sorts_are_rejected(self) -> None:
        self.assertEqual(["unstable-sort"], rules("std.sort.pdq(u32, xs, {}, lt);"))
        self.assertEqual(["unstable-sort"], rules("std.sort.heapContext(0, n, ctx);"))
        self.assertEqual(["unstable-sort"], rules("std.mem.sortUnstable(u32, xs, {}, lt);"))

    def test_stable_sort_is_allowed(self) -> None:
        self.assertEqual([], rules("std.mem.sort(QM31, out, {}, lessByU);"))
        self.assertEqual([], rules("std.sort.insertion(u32, xs, {}, lt);"))

    def test_hash_map_iteration_needs_a_waiver(self) -> None:
        self.assertEqual(["hash-map-iteration"], rules("var it = map.iterator();"))
        self.assertEqual(["hash-map-iteration"], rules("var it = map.keyIterator();"))
        self.assertEqual([], rules("var it = map.iterator(); // circuit-lint: ordered-iteration"))
        self.assertEqual([], rules("for (map.keys(), map.values()) |k, v| {}"))

    def test_cairo_frontend_import_is_rejected(self) -> None:
        self.assertEqual(["cairo-frontend-import"], rules('const cairo = @import("stwo_cairo_frontend");'))

    def test_comments_and_strings_are_ignored(self) -> None:
        self.assertEqual([], rules("// never call std.sort.pdq here"))
        self.assertEqual([], rules('const url = "https://x"; // map.iterator()'))
        self.assertEqual([], rules("//! `stwo_cairo_frontend` is not a dependency"))

    def test_tree_walk_skips_build_caches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / lint.PACKAGE
            (package / ".zig-cache").mkdir(parents=True)
            (package / ".zig-cache" / "gen.zig").write_text("std.sort.pdq(a, b, c, d);\n")
            (package / "mod.zig").write_text("var it = m.valueIterator();\n")
            violations = lint.lint_tree(root)
            self.assertEqual(["hash-map-iteration"], [v.rule for v in violations])
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, lint.main(["--root", tmp]))


if __name__ == "__main__":
    unittest.main()
