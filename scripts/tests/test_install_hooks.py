import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.repo.install_hooks import HOOK_NAMES, install

ROOT = Path(__file__).resolve().parents[2]


class InstallHooksTests(unittest.TestCase):
    def test_install_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            hooks = repo / ".githooks"
            hooks.mkdir()
            for name in HOOK_NAMES:
                hook = hooks / name
                hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                hook.chmod(0o755)

            install(repo)
            install(repo)
            configured = subprocess.run(
                ["git", "config", "--local", "--get", "core.hooksPath"],
                cwd=repo,
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertEqual(".githooks", configured.stdout.strip())
            resolved = subprocess.run(
                ["git", "rev-parse", "--path-format=absolute", "--git-path", "hooks/pre-commit"],
                cwd=repo,
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                (repo / ".githooks/pre-commit").resolve(),
                Path(resolved.stdout.strip()).resolve(),
            )

    def test_install_rejects_missing_or_non_executable_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            hooks = repo / ".githooks"
            hooks.mkdir()

            with self.assertRaisesRegex(RuntimeError, "missing versioned hook"):
                install(repo)

            for name in HOOK_NAMES:
                hook = hooks / name
                hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                hook.chmod(0o755)
            (hooks / HOOK_NAMES[0]).chmod(0o644)

            with self.assertRaisesRegex(RuntimeError, "hook is not executable"):
                install(repo)

    def test_versioned_hooks_are_executable_and_syntactically_valid(self) -> None:
        for name in HOOK_NAMES:
            hook = ROOT / ".githooks" / name
            self.assertTrue(hook.stat().st_mode & stat.S_IXUSR)
            subprocess.run(["sh", "-n", str(hook)], check=True)

    def test_versioned_hooks_enforce_the_documented_gate_contract(self) -> None:
        pre_commit = (ROOT / ".githooks/pre-commit").read_text(encoding="utf-8")
        self.assertIn("git diff --cached --check", pre_commit)
        self.assertIn("zig fmt --check build.zig src tools", pre_commit)
        self.assertIn("python3 scripts/repo/check_source_conformance.py", pre_commit)

        pre_push = (ROOT / ".githooks/pre-push").read_text(encoding="utf-8")
        self.assertIn("exec python3 scripts/repo/ci_scope_push.py", pre_push)
        self.assertNotIn("zig build", pre_push)

        policy = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("emergency local bypass with `--no-verify`", policy)
        self.assertIn("Hosted CI is authoritative", policy)


if __name__ == "__main__":
    unittest.main()
