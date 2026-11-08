from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.repo import ci_scope_push
OID_A = "a" * 40
OID_B = "b" * 40
ZERO = "0" * 40


class FocusedPushTests(unittest.TestCase):
    def test_parse_updates_accepts_pushes_and_ignores_deletions(self) -> None:
        self.assertEqual(
            [(OID_B, OID_A)],
            ci_scope_push.parse_updates(
                [
                    f"refs/heads/main {OID_A} refs/heads/main {OID_B}\n",
                    f"(delete) {ZERO} refs/heads/old {OID_A}\n",
                ]
            ),
        )

    def test_parse_updates_rejects_malformed_protocol_input(self) -> None:
        for line in ("three fields only\n", "local not-an-oid remote also-bad\n"):
            with self.subTest(line=line):
                with self.assertRaises(ci_scope_push.PlanError):
                    ci_scope_push.parse_updates([line])

    def test_changed_paths_requires_one_checked_out_head(self) -> None:
        with mock.patch.object(ci_scope_push, "git_output", return_value=OID_A):
            with self.assertRaisesRegex(ci_scope_push.PlanError, "checked-out HEAD"):
                ci_scope_push.changed_paths(Path("."), [(OID_A, OID_B)])
            with self.assertRaisesRegex(ci_scope_push.PlanError, "one update"):
                ci_scope_push.changed_paths(
                    Path("."), [(OID_B, OID_A), (OID_A, "c" * 40)]
                )

    def test_changed_paths_unions_every_ref_diff(self) -> None:
        with (
            mock.patch.object(ci_scope_push, "git_output", return_value=OID_A),
            mock.patch.object(
                ci_scope_push,
                "git_changed_paths",
                side_effect=[["src/core/a.zig"], ["src/prover/b.zig"]],
            ),
        ):
            head, paths = ci_scope_push.changed_paths(
                Path("."), [(OID_B, OID_A), ("c" * 40, OID_A)]
            )
        self.assertEqual(OID_A, head)
        self.assertEqual(["src/core/a.zig", "src/prover/b.zig"], paths)

    def test_new_ref_uses_main_merge_base_then_parent(self) -> None:
        with mock.patch.object(
            ci_scope_push, "git_output", side_effect=[OID_B]
        ) as output:
            self.assertEqual(OID_B, ci_scope_push.new_ref_base(Path("."), OID_A))
        output.assert_called_once_with(
            Path("."), "merge-base", OID_A, "refs/remotes/origin/main"
        )

    def test_local_support_is_explicit(self) -> None:
        self.assertTrue(
            ci_scope_push.locally_runnable("core", "linux", "run", "linux", False)
        )
        self.assertTrue(
            ci_scope_push.locally_runnable("core", "linux", "run", "macos", False)
        )
        self.assertFalse(
            ci_scope_push.locally_runnable(
                "native_metal", "macos", "run", "linux", False
            )
        )
        self.assertFalse(
            ci_scope_push.locally_runnable(
                "metal_aot", "macos", "run", "macos", False
            )
        )
        self.assertTrue(
            ci_scope_push.locally_runnable(
                "metal_aot", "macos", "run", "macos", True
            )
        )
        self.assertFalse(
            ci_scope_push.locally_runnable(
                "aggregate_cpu", "linux", "hosted", "linux", False
            )
        )
        self.assertFalse(
            ci_scope_push.locally_runnable(
                "build_graph", "linux", "hosted", "linux", False
            )
        )

    def test_dirty_worktree_is_rejected(self) -> None:
        completed = mock.Mock(stdout="?? generated.py\n")
        with mock.patch.object(ci_scope_push.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ci_scope_push.PlanError, "clean worktree"):
                ci_scope_push.require_clean(Path("."))

    def test_no_push_updates_is_a_noop(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch.object(sys, "stdin", []):
                self.assertEqual(
                    0,
                    ci_scope_push.main(["--root", raw]),
                )


if __name__ == "__main__":
    unittest.main()
