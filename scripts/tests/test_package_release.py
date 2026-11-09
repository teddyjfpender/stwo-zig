from __future__ import annotations

import json
import hashlib
import io
from contextlib import redirect_stdout
from unittest.mock import patch
import subprocess
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

from scripts.repo import check_downstream_package as downstream
from scripts.release import package_release as subject
ROOT = Path(__file__).resolve().parents[2]


class PackageReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contracts = subject.load_contracts(ROOT)
        cls.policy = subject.load_policy(ROOT, cls.contracts)

    def test_policy_classifies_every_package_and_keeps_cuda_deferred(self) -> None:
        self.assertEqual(set(self.contracts), set(self.policy))
        self.assertEqual("deferred", self.policy["stwo_cuda_backend"]["status"])
        self.assertEqual(
            "deferred",
            self.policy["stwo_native_cuda_integration"]["status"],
        )
        self.assertEqual(
            "deferred",
            self.policy["stwo_cairo_cuda_integration"]["status"],
        )
        published = {
            name for name, entry in self.policy.items() if entry["status"] == "published"
        }
        self.assertEqual(17, len(published))
        self.assertEqual("internal", self.policy["stwo_circuit_metal_integration"]["status"])

    def test_every_published_dependency_closure_is_publishable(self) -> None:
        for package, entry in self.policy.items():
            if entry["status"] != "published":
                continue
            with self.subTest(package=package):
                closure = subject.dependency_closure(package, self.contracts)
                self.assertTrue(
                    all(self.policy[name]["status"] != "deferred" for name in closure)
                )

    def test_core_archive_is_deterministic_and_zig_only(self) -> None:
        with TemporaryDirectory() as directory:
            output = Path(directory)
            first = subject.build_release(
                ROOT,
                output,
                ["stwo_core"],
                allow_dirty=True,
            )
            first_bytes = (output / first["archives"][0]["archive"]).read_bytes()
            second = subject.build_release(
                ROOT,
                output,
                ["stwo_core"],
                allow_dirty=True,
            )
            second_bytes = (output / second["archives"][0]["archive"]).read_bytes()
            self.assertEqual(first_bytes, second_bytes)
            self.assertEqual(
                first["archives"][0]["sha256"],
                second["archives"][0]["sha256"],
            )
            archive = output / second["archives"][0]["archive"]
            with tarfile.open(archive, mode="r") as bundle:
                names = bundle.getnames()
            self.assertIn("stwo_core-1.0.0-rc.1/PACKAGE-RELEASE.json", names)
            self.assertIn("stwo_core-1.0.0-rc.1/src/waist/core/build.zig.zon", names)
            self.assertFalse(any(name.endswith(".rs") for name in names))
            self.assertFalse(any("/guests/" in name for name in names))
            self.assertFalse(any("/formal/" in name for name in names))
            self.assertFalse(any("/vectors/" in name for name in names))

    def test_deferred_package_cannot_be_built(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(subject.ReleaseError, "not publishable"):
                subject.build_release(
                    ROOT,
                    Path(directory),
                    ["stwo_cuda_backend"],
                    allow_dirty=True,
                )

    def test_downstream_receipt_owns_installed_binary_with_external_cache(self) -> None:
        with TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            fixture = root / "src/products/stwo/tests/public_modules.zig"
            fixture.parent.mkdir(parents=True)
            fixture.write_bytes(b"fixture")
            cache = Path(raw) / "external-cache"
            def build(argv, cwd):
                prefix = Path(argv[argv.index("--prefix") + 1])
                self.assertEqual(cwd / "zig-out", prefix)
                installed = prefix / "bin/consumer-smoke"
                installed.parent.mkdir(parents=True)
                if produce:
                    installed.write_bytes(b"owned executable")
                cached = cache / "o/stale/consumer-smoke"
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_bytes(b"unrelated cached executable")
            for produce in (True, False):
                with (
                    self.subTest(installed=produce),
                    patch.dict("os.environ", {"ZIG_LOCAL_CACHE_DIR": str(cache)}),
                    patch("sys.argv", ["check_downstream_package.py", "--repo", str(root)]),
                    patch.object(downstream, "run", side_effect=build),
                    redirect_stdout(io.StringIO()) as output,
                ):
                    if produce:
                        self.assertEqual(0, downstream.main())
                        receipt = json.loads(output.getvalue())
                        self.assertEqual(
                            hashlib.sha256(b"owned executable").hexdigest(),
                            receipt["external_consumer_binary_sha256"],
                        )
                    else:
                        with self.assertRaisesRegex(RuntimeError, "did not install"):
                            downstream.main()

    def test_untracked_files_mark_source_identity_dirty(self) -> None:
        with TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Package Test"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "package@test.invalid"],
                cwd=repository,
                check=True,
            )
            tracked = repository / "tracked.zig"
            tracked.write_text("pub const value = 1;\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "tracked.zig"],
                cwd=repository,
                check=True,
            )
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "base"],
                cwd=repository,
                check=True,
            )
            self.assertFalse(subject.source_identity(repository)["dirty"])
            (repository / "untracked.zig").write_text(
                "pub const value = 2;\n",
                encoding="utf-8",
            )
            self.assertTrue(subject.source_identity(repository)["dirty"])

    def test_transitive_deferred_dependency_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            repository = Path(directory)
            policy_path = repository / "conformance/package-release-v1.json"
            policy_path.parent.mkdir(parents=True)
            policy_path.write_text(
                json.dumps(
                    {
                        "schema": subject.POLICY_SCHEMA,
                        "archive_format": "tar",
                        "packages": {
                            "public": {"status": "published", "reason": "test"},
                            "internal": {"status": "internal", "reason": "test"},
                            "deferred": {"status": "deferred", "reason": "test"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            contracts = {
                "public": SimpleNamespace(dependencies={"internal": "ignored"}),
                "internal": SimpleNamespace(dependencies={"deferred": "ignored"}),
                "deferred": SimpleNamespace(dependencies={}),
            }
            with self.assertRaisesRegex(subject.ReleaseError, "unpublished packages"):
                subject.load_policy(repository, contracts)  # type: ignore[arg-type]

    def test_published_payload_rejects_tracked_symlinks(self) -> None:
        with TemporaryDirectory() as directory:
            repository = Path(directory)
            owner = repository / "src/example"
            owner.mkdir(parents=True)
            target = repository / "target.zig"
            target.write_text("pub const value = 1;\n", encoding="utf-8")
            (owner / "linked.zig").symlink_to(target)
            contracts = {
                "example": SimpleNamespace(directory=owner),
            }
            with self.assertRaisesRegex(subject.ReleaseError, "cannot be symlinks"):
                subject.package_files(
                    repository,
                    ["example"],
                    contracts,  # type: ignore[arg-type]
                    [Path("src/example/linked.zig")],
                )


if __name__ == "__main__":
    unittest.main()
