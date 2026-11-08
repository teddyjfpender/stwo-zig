"""toolchain.json is the single source of toolchain pins; everything else must agree."""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PINS = json.loads((ROOT / "toolchain.json").read_text(encoding="utf-8"))


def tracked(pattern: str) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", pattern], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [ROOT / line for line in out.splitlines() if line]


class ToolchainPinTests(unittest.TestCase):
    def test_every_zon_declares_the_minimum_zig_version(self) -> None:
        want = PINS["zig"]["minimum_zig_version"]
        for zon in tracked("*build.zig.zon"):
            with self.subTest(zon=zon.relative_to(ROOT).as_posix()):
                found = re.findall(r'\.minimum_zig_version = "([^"]+)"', zon.read_text())
                self.assertEqual([want], found)

    def test_workflows_install_the_pinned_zig_and_python(self) -> None:
        for workflow in tracked(".github/workflows/*.yml"):
            text = workflow.read_text(encoding="utf-8")
            name = workflow.relative_to(ROOT).as_posix()
            for version in re.findall(r"python-version:\s*\"?([0-9.]+)\"?", text):
                self.assertEqual(PINS["python"]["version"], version, name)
            for version in re.findall(r"setup-zig@\S+\s+with:\s+version:\s*([0-9.]+)", text):
                self.assertEqual(PINS["zig"]["version"], version, name)

    def test_every_tool_crate_pins_its_rust_toolchain(self) -> None:
        crates = PINS["rust"]["crates"]
        for manifest in tracked("tools/*/Cargo.toml") + tracked("tools/*/*/Cargo.toml"):
            crate = manifest.parent.relative_to(ROOT).as_posix()
            with self.subTest(crate=crate):
                self.assertIn(crate, crates)
                toolchain = manifest.parent / "rust-toolchain.toml"
                self.assertTrue(toolchain.is_file(), f"{crate} lacks rust-toolchain.toml")
                channel = tomllib.loads(toolchain.read_text())["toolchain"]["channel"]
                self.assertEqual(crates[crate], channel)

    def test_lean_pins_match_lean_toolchain_files(self) -> None:
        for project, version in PINS["lean"].items():
            text = (ROOT / project / "lean-toolchain").read_text(encoding="utf-8").strip()
            self.assertEqual(version, text, project)


if __name__ == "__main__":
    unittest.main()
