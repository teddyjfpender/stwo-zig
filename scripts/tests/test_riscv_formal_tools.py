from __future__ import annotations

import dataclasses
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_formal_tools as formal


class RiscvFormalToolsTests(unittest.TestCase):
    def test_machine_profile_owns_all_external_authorities(self) -> None:
        profile = formal.load_profile()
        self.assertEqual("rv32im-zkvm-v1", profile.name)
        self.assertEqual(0x0001_0000, profile.rvfi_entry)
        self.assertEqual(40, len(profile.sail.revision))
        self.assertEqual(40, len(profile.spike.revision))
        self.assertEqual(40, len(profile.arch_test.revision))
        self.assertEqual(
            profile.rvfi_patch_sha256,
            formal._sha256_file(profile.rvfi_patch),
        )

    def test_sail_patch_application_accepts_only_the_one_transport_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            target = source / formal.SAIL_PATCHED_SOURCE
            target.parent.mkdir(parents=True)
            target.write_text(
                "rvfi_handler::rvfi_handler(int port, ModelImpl &model) : "
                "dii_port(port), m_model(model) {\n"
                "  fprintf(stderr, \"using %d as RVFI port.\\n\", port);\n"
                "}\n\n"
                "uint64_t rvfi_handler::get_entry() {\n"
                "  return 0x80000000;\n"
                "}\n\n"
                "// returns zero on success\n",
                encoding="utf-8",
            )
            self._git(source, "init")
            self._git(source, "config", "user.email", "formal@example.invalid")
            self._git(source, "config", "user.name", "Formal Test")
            self._git(source, "add", ".")
            self._git(source, "commit", "-m", "base")
            revision = self._git(source, "rev-parse", "HEAD").stdout.strip()
            profile = dataclasses.replace(
                formal.load_profile(),
                sail=formal.Authority("https://example.invalid/sail", revision),
            )

            formal.ensure_patched_sail(source, profile)
            self.assertIn("return 0x00010000;", target.read_text(encoding="utf-8"))

            target.write_text(
                target.read_text(encoding="utf-8") + "// unrelated change\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                formal.FormalToolsError,
                "changes beyond the RVFI patch",
            ):
                formal.ensure_patched_sail(source, profile)

    def test_device_tree_compiler_preflight_is_actionable(self) -> None:
        with mock.patch.object(formal.shutil, "which", return_value=None):
            with self.assertRaisesRegex(
                formal.FormalToolsError,
                r"brew install dtc",
            ):
                formal.require_device_tree_compiler()

    def test_device_tree_compiler_preflight_checks_identity(self) -> None:
        with (
            mock.patch.object(formal.shutil, "which", return_value="/tool/dtc"),
            mock.patch.object(
                formal,
                "_output",
                return_value="unidentified compiler 1.8.1",
            ),
        ):
            with self.assertRaisesRegex(
                formal.FormalToolsError,
                "unexpected device-tree compiler identity",
            ):
                formal.require_device_tree_compiler()

        with (
            mock.patch.object(formal.shutil, "which", return_value="/tool/dtc"),
            mock.patch.object(
                formal,
                "_output",
                return_value="Version: DTC 1.8.1",
            ),
        ):
            self.assertEqual(Path("/tool/dtc"), formal.require_device_tree_compiler())

    def test_pinned_spike_identity_comes_from_help_banner(self) -> None:
        formal._validate_spike_identity(
            Path("/tool/spike"),
            (
                "Spike RISC-V ISA Simulator 1.1.1-dev\n\n"
                "usage: spike [host options] <target program>"
            ),
        )
        with self.assertRaisesRegex(formal.FormalToolsError, "unexpected Spike identity"):
            formal._validate_spike_identity(Path("/tool/spike"), "not Spike")

    @staticmethod
    def _git(source: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ("git", "-C", str(source), *args),
            check=True,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
