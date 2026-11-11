from __future__ import annotations

import hashlib
import json
import platform
import shutil
import stat
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from scripts.architecture import architecture_native_oracle as oracle
def _target_triple() -> str:
    architecture = {
        "arm64": "aarch64",
        "aarch64": "aarch64",
        "x86_64": "x86_64",
    }[platform.machine()]
    suffix = "-apple-darwin" if platform.system() == "Darwin" else "-unknown-linux-gnu"
    return architecture + suffix


def _toolchain() -> dict[str, object]:
    triple = _target_triple()
    return {
        "channel": oracle.TOOLCHAIN,
        "rustc": {
            "release": oracle.RUSTC_RELEASE,
            "commit": oracle.RUSTC_COMMIT,
            "target_triple": triple,
        },
        "cargo": {
            "release": oracle.CARGO_RELEASE,
            "commit": oracle.CARGO_COMMIT,
            "target_triple": triple,
        },
    }


class ArchitectureNativeOracleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        package = self.root / "tools/stwo-interop-rs"
        (package / "src").mkdir(parents=True)
        (package / "Cargo.toml").write_text("[package]\nname='oracle'\n", encoding="utf-8")
        (package / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (package / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
        workflows = self.root / ".github/workflows"
        workflows.mkdir(parents=True)
        self.workflow = workflows / "native-oracle.yml"
        self.workflow.write_text("name: protected native oracle\n", encoding="utf-8")
        self.binary = self.root / "built-oracle"
        self.binary.write_text("#!/bin/sh\nprintf 'oracle-ready\\n'\n", encoding="utf-8")
        self.binary.chmod(0o755)
        self.role = "macos" if platform.system() == "Darwin" else "linux"
        self.producer = {
            "repository": "teddyjfpender/stwo-zig",
            "repository_id": 1152389958,
            "candidate": "1" * 40,
            "tree": "2" * 40,
            "workflow_sha": "3" * 40,
            "workflow_path": ".github/workflows/native-oracle.yml",
            "workflow_definition_sha256": hashlib.sha256(
                self.workflow.read_bytes()
            ).hexdigest(),
            "producer_job": f"native-oracle-producer-{self.role}",
            "run_id": 123,
            "run_attempt": 2,
        }
        self.bundle = self.root / "bundle"
        with mock.patch.object(oracle, "_toolchain_identity", return_value=_toolchain()):
            oracle.build(
                self.binary,
                self.root,
                self.bundle,
                self.producer,
                self.root,
            )
        self.bundle_template = self.root / "bundle-template"
        shutil.copytree(self.bundle, self.bundle_template, copy_function=shutil.copy2)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _manifest(self) -> dict[str, object]:
        return json.loads((self.bundle / oracle.MANIFEST_NAME).read_text(encoding="utf-8"))

    def _rewrite(
        self,
        mutate: Callable[[dict[str, object]], None],
        *,
        resign: bool = True,
    ) -> None:
        manifest = self._manifest()
        mutate(manifest)
        if resign:
            manifest["content_sha256"] = oracle._content_address(manifest)
        (self.bundle / oracle.MANIFEST_NAME).write_bytes(oracle._canonical(manifest) + b"\n")

    def _reset(self) -> None:
        shutil.rmtree(self.bundle)
        shutil.copytree(self.bundle_template, self.bundle, copy_function=shutil.copy2)
        source = self.root / "tools/stwo-interop-rs/src/main.rs"
        if source.is_symlink():
            source.unlink()
        source.write_text("fn main() {}\n", encoding="utf-8")
        self.workflow.write_text("name: protected native oracle\n", encoding="utf-8")

    def test_verified_bundle_is_reusable_without_rust_tooling(self) -> None:
        with mock.patch.object(
            oracle.subprocess,
            "run",
            side_effect=AssertionError("verification invoked a toolchain command"),
        ):
            binary = oracle.verify(
                self.bundle,
                self.root,
                self.role,
                self.producer,
                self.root,
            )
        self.assertEqual("oracle-ready\n", subprocess.check_output([binary], text=True))
        self.assertEqual(0o555, stat.S_IMODE(binary.stat().st_mode))

    def test_protected_verification_requires_external_trust_inputs(self) -> None:
        with self.assertRaisesRegex(oracle.OracleBundleError, "authenticated producer"):
            oracle.verify(self.bundle, self.root, self.role, protected=True)
        self.assertEqual(
            (self.bundle / oracle.BINARY_NAME).resolve(),
            oracle.verify(
                self.bundle,
                self.root,
                self.role,
                self.producer,
                self.root,
                protected=True,
            ),
        )

    def test_manifest_is_canonical_and_content_addressed(self) -> None:
        raw = (self.bundle / oracle.MANIFEST_NAME).read_bytes()
        manifest = self._manifest()
        self.assertEqual(oracle._canonical(manifest) + b"\n", raw)
        self.assertEqual(oracle._content_address(manifest), manifest["content_sha256"])
        self.assertEqual(
            {oracle.MANIFEST_NAME, oracle.BINARY_NAME},
            {path.name for path in self.bundle.iterdir()},
        )

    def test_rejects_binary_content_mode_and_symlink_mutations(self) -> None:
        binary = self.bundle / oracle.BINARY_NAME
        binary.chmod(0o755)
        binary.write_bytes(binary.read_bytes() + b"substitution")
        binary.chmod(0o555)
        with self.assertRaisesRegex(oracle.OracleBundleError, "binary content digest"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        self._reset()
        binary = self.bundle / oracle.BINARY_NAME
        binary.chmod(0o755)
        with self.assertRaisesRegex(oracle.OracleBundleError, "binary content digest"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        binary.unlink()
        binary.symlink_to(self.binary)
        with self.assertRaisesRegex(oracle.OracleBundleError, "binary path is unsafe"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

    def test_rejects_source_toolchain_platform_and_role_mutations(self) -> None:
        (self.root / "tools/stwo-interop-rs/src/main.rs").write_text(
            "fn main() { panic!(); }\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(oracle.OracleBundleError, "identity drifted"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        self._reset()
        self._rewrite(
            lambda value: value["rust_toolchain"]["rustc"].__setitem__(
                "commit", "4" * 40
            )
        )
        with self.assertRaisesRegex(oracle.OracleBundleError, "rustc identity drifted"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        self._reset()
        self._rewrite(lambda value: value["platform"].__setitem__("machine", "substitute"))
        with self.assertRaisesRegex(oracle.OracleBundleError, "identity drifted"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        other_role = "linux" if self.role == "macos" else "macos"
        with self.assertRaisesRegex(oracle.OracleBundleError, "requested role"):
            oracle.verify(self.bundle, self.root, other_role, authority_root=self.root)

    def test_rejects_content_address_and_noncanonical_json_mutations(self) -> None:
        self._rewrite(lambda value: value.__setitem__("content_sha256", "4" * 64), resign=False)
        with self.assertRaisesRegex(oracle.OracleBundleError, "content address mismatch"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        self._reset()
        manifest_path = self.bundle / oracle.MANIFEST_NAME
        manifest_path.write_bytes(b" " + manifest_path.read_bytes())
        with self.assertRaisesRegex(oracle.OracleBundleError, "encoding is not canonical"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        manifest_path.write_text(
            '{"schema":"first","schema":"second"}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(oracle.OracleBundleError, "duplicate JSON key"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

    def test_rejects_path_set_and_manifest_symlink_mutations(self) -> None:
        (self.bundle / "unexpected").write_text("substitute", encoding="utf-8")
        with self.assertRaisesRegex(oracle.OracleBundleError, "path set drifted"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        (self.bundle / "unexpected").unlink()
        manifest = self.bundle / oracle.MANIFEST_NAME
        copy = self.root / "manifest-copy.json"
        shutil.copyfile(manifest, copy)
        manifest.unlink()
        manifest.symlink_to(copy)
        with self.assertRaisesRegex(oracle.OracleBundleError, "not a regular file"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

    def test_rejects_producer_and_workflow_definition_mutations(self) -> None:
        expected = dict(self.producer)
        expected["run_id"] = 124
        with self.assertRaisesRegex(oracle.OracleBundleError, "trusted metadata"):
            oracle.verify(
                self.bundle,
                self.root,
                self.role,
                expected,
                self.root,
            )

        self._rewrite(lambda value: value["producer"].__setitem__("run_id", True))
        with self.assertRaisesRegex(oracle.OracleBundleError, "trust fields"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        self._reset()
        self._rewrite(lambda value: value["producer"].__setitem__("run_attempt", 1001))
        with self.assertRaisesRegex(oracle.OracleBundleError, "trust fields"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

        self._reset()
        self.workflow.write_text("name: substituted workflow\n", encoding="utf-8")
        with self.assertRaisesRegex(oracle.OracleBundleError, "trust fields"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)

    def test_build_publishes_atomically_and_refuses_replacement(self) -> None:
        with self.assertRaisesRegex(oracle.OracleBundleError, "refusing to replace"):
            oracle.build(
                self.binary,
                self.root,
                self.bundle,
                self.producer,
                self.root,
            )
        failed = self.root / "failed-bundle"
        with mock.patch.object(oracle.shutil, "copyfile", side_effect=OSError("stopped")):
            with self.assertRaisesRegex(OSError, "stopped"):
                oracle.build(
                    self.binary,
                    self.root,
                    failed,
                    self.producer,
                    self.root,
                )
        self.assertFalse(failed.exists())
        self.assertEqual([], list(self.root.glob(".failed-bundle.*")))

    def test_rejects_symlinked_input_binary_and_source(self) -> None:
        linked_binary = self.root / "linked-binary"
        linked_binary.symlink_to(self.binary)
        with self.assertRaisesRegex(oracle.OracleBundleError, "executable regular file"):
            oracle.build(
                linked_binary,
                self.root,
                self.root / "linked-output",
                self.producer,
                self.root,
            )
        source = self.root / "tools/stwo-interop-rs/src/main.rs"
        real_source = self.root / "real-main.rs"
        source.rename(real_source)
        source.symlink_to(real_source)
        with self.assertRaisesRegex(oracle.OracleBundleError, "source is unsafe"):
            oracle.verify(self.bundle, self.root, self.role, authority_root=self.root)


if __name__ == "__main__":
    unittest.main()
