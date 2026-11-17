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
    def test_supported_cpu_distributions_have_immutable_versions_and_hashes(self) -> None:
        self.assertRegex(PINS["python"]["version"], r"^\d+\.\d+\.\d+$")
        version = PINS["zig"]["version"]
        hosts = set(PINS["profiles"]["cpu"]["hosts"])
        self.assertEqual(hosts, set(PINS["zig"]["distributions"]))
        for host, dist in PINS["zig"]["distributions"].items():
            self.assertEqual(f"https://ziglang.org/download/{version}/zig-{host}-{version}.tar.xz", dist["url"])
            self.assertRegex(dist["sha256"], r"^[0-9a-f]{64}$")
        for channel in PINS["rust"]["crates"].values():
            self.assertRegex(channel, r"^(nightly-\d{4}-\d{2}-\d{2}|\d+\.\d+\.\d+)$")

    def assert_installer_pins(self, text: str, action: str, key: str, want: str, name: str) -> None:
        action = re.escape(action)
        installs = re.findall(rf"(?m)^\s*(?:-\s+)?uses:\s+{action}@[^\n]+", text)
        versions = re.findall(
            rf"(?m)uses:\s+{action}@[^\n]+\n\s+with:\s*\n\s+{key}:\s*['\"]?([0-9.]+)['\"]?[ \t]*(?:#[^\n]*)?$",
            text,
        )
        self.assertEqual([want] * len(installs), versions, name)

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
            self.assert_installer_pins(text, "actions/setup-python", "python-version", PINS["python"]["version"], name)
            self.assert_installer_pins(text, "mlugg/setup-zig", "version", PINS["zig"]["version"], name)

    def test_installer_comments_cannot_hide_wrong_or_missing_versions(self) -> None:
        fixture = '        uses: mlugg/setup-zig@pinned # v2\n        with:\n          version: "0.15.2"\n'
        self.assert_installer_pins(fixture, "mlugg/setup-zig", "version", "0.15.2", "fixture")
        for invalid in (fixture.replace("0.15.2", "0.15.1"), fixture.replace('          version: "0.15.2"\n', "")):
            with self.subTest(invalid=invalid), self.assertRaises(AssertionError):
                self.assert_installer_pins(invalid, "mlugg/setup-zig", "version", "0.15.2", "fixture")

    def test_every_tool_crate_pins_its_rust_toolchain(self) -> None:
        crates = PINS["rust"]["crates"]
        manifests = set(tracked("tools/*/Cargo.toml") + tracked("tools/*/*/Cargo.toml"))
        self.assertEqual(set(crates), {p.parent.relative_to(ROOT).as_posix() for p in manifests})
        for manifest in manifests:
            crate = manifest.parent.relative_to(ROOT).as_posix()
            with self.subTest(crate=crate):
                self.assertIn(crate, crates)
                toolchain = manifest.parent / "rust-toolchain.toml"
                self.assertTrue(toolchain.is_file(), f"{crate} lacks rust-toolchain.toml")
                channel = tomllib.loads(toolchain.read_text())["toolchain"]["channel"]
                self.assertEqual(crates[crate], channel)

    def test_guest_toolchains_match_the_declared_inventory(self) -> None:
        guests = PINS["rust"]["guests"]
        paths = tracked("vectors/riscv_guests/*/rust-toolchain.toml")
        self.assertEqual(set(guests), {p.parent.relative_to(ROOT).as_posix() for p in paths})
        for path in paths:
            channel = tomllib.loads(path.read_text())["toolchain"]["channel"]
            self.assertEqual(guests[path.parent.relative_to(ROOT).as_posix()], channel)

    def test_lean_pins_match_lean_toolchain_files(self) -> None:
        for project, version in PINS["lean"].items():
            text = (ROOT / project / "lean-toolchain").read_text(encoding="utf-8").strip()
            self.assertEqual(version, text, project)

    def test_sail_pins_match_the_formal_profile_authority(self) -> None:
        profile = json.loads((ROOT / "conformance/riscv/rv32im-sail-profile.json").read_text())
        authority = profile["authorities"]["sail"]
        self.assertEqual(PINS["sail"]["compiler"], authority["compiler"])
        self.assertEqual(PINS["sail"]["sail_riscv_commit"], authority["revision"])


if __name__ == "__main__":
    unittest.main()
