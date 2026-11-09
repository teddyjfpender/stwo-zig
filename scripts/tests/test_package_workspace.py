from __future__ import annotations

import json
import unittest
from dataclasses import replace
from tempfile import TemporaryDirectory
from pathlib import Path

from scripts.repo import check_package_workspace as subject
ROOT = Path(__file__).resolve().parents[2]


class PackageWorkspaceTests(unittest.TestCase):
    def test_semver_candidates_preserve_strict_version_encoding(self):
        payload = json.loads((ROOT / "src/waist/core/package.contract.json").read_text())
        with TemporaryDirectory() as raw:
            path = Path(raw) / "package.contract.json"
            for version in ("0.0.0", "1.0.0", "1.0.0-rc.1", "1.0.0-alpha.0", "1.0.0-1", "1.0.0-01a", "1.0.0-alpha-beta"):
                with self.subTest(valid=version):
                    path.write_text(json.dumps(payload | {"version": version}))
                    self.assertEqual(version, subject.load_contract(path).version)
            for version in (None, 1, True, "01.0.0", "1.01.0", "1.0.01", "1.0", "1.0.0-", "1.0.0-rc..1",
                            "1.0.0-rc.01", "1.0.0-01", "1.0.0-rc_1", "1.0.0-rc.1 ", "v1.0.0", "1.0.0-rc.1+"):
                with self.subTest(invalid=version):
                    path.write_text(json.dumps(payload | {"version": version}))
                    with self.assertRaisesRegex(ValueError, "invalid semantic version"):
                        subject.load_contract(path)

    def test_manifest_keeps_exact_release_candidate_identity(self):
        contract = subject.load_contract(ROOT / "src/waist/core/package.contract.json")
        with TemporaryDirectory() as raw:
            root = Path(raw)
            contract = replace(contract, directory=root, version="1.0.0-rc.1")
            (root / "build.zig").write_text('b.addModule("stwo_core", .{});')
            (root / "mod.zig").touch()
            for version in ("1.0.0", "1.0.0-rc.2"):
                (root / "build.zig.zon").write_text('.{ .name = .stwo_core, .version = "' + version + '", .dependencies = .{} }')
                failures = []
                subject._validate_manifest(contract, failures)
                self.assertTrue(any("manifest version differs" in error for error in failures))

    def test_repository_contracts_pass(self) -> None:
        self.assertEqual([], subject.check_repository(ROOT))

    def test_exact_owner_roles_reject_missing_unknown_or_overriding_routes(self):
        graph = subject.ci_package_graph
        expected = {"protocol-core": {"/src/waist/core/package.contract.json", "/src/waist/core/build.zig.zon"}}
        valid = "# owner-role: protocol-core\n/src/waist/core/package.contract.json @owner\n/src/waist/core/build.zig.zon @owner\n"
        with TemporaryDirectory() as raw:
            root = Path(raw)
            self.assertTrue(graph.check_owner_roles(root, expected))
            path = root / ".github/CODEOWNERS"
            path.parent.mkdir()
            path.write_text(valid)
            self.assertEqual([], graph.check_owner_roles(root, expected))
            for candidate in (valid.replace("protocol-core", "unassigned"),
                              valid.splitlines()[0] + "\n",
                              valid + "/src/waist/core/package.contract.json @other\n",
                              valid + "* @other\n",
                              valid.replace("@owner", "not-an-account"),
                              valid.replace("build.zig.zon @owner", "build.zig.zon @other"),
                              valid + "# owner-role: protocol-core\n"):
                with self.subTest(candidate=candidate):
                    path.write_text(candidate)
                    self.assertTrue(graph.check_owner_roles(root, expected))

    def test_shared_ownership_projection_retains_duplicate_and_exact_scope_rejection(self):
        graph = subject.ci_package_graph
        source = '.{ .prefix = "src/waist/core/", .package = .core, .dependency_name = "stwo_core" }'
        expected = {"src/waist/core/": "stwo_core"}
        self.assertEqual([], graph.check_ownership_projection(expected, source))
        self.assertTrue(graph.check_ownership_projection(expected, source + source))
        self.assertTrue(graph.check_ownership_projection(expected, ""))
        self.assertTrue(graph.check_ownership_projection({}, source))

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

    def test_multiline_imports_with_trailing_commas_are_dependencies(self) -> None:
        text = """
const owned = @import(
    "../owned/mod.zig",
);
"""
        self.assertEqual(["../owned/mod.zig"], subject.IMPORT_RE.findall(text))

    def test_backend_layer_cannot_depend_on_another_backend(self) -> None:
        root = Path("/tmp")
        dependency = subject.Contract(
            directory=root / "gpu",
            package="gpu_backend",
            version="0.1.0",
            layer="backend",
            owner="gpu-team",
            public_modules={"gpu_backend": "mod.zig"},
            dependencies={},
            injected_modules=frozenset(),
            api_surface=("Backend",),
            api_contract=subject.ApiContract(
                signature_tests=("mod.zig::signature",),
                invariant_tests=("mod.zig::invariant",),
            ),
            ci_lane="gpu_backend",
            ci_host="linux",
            ci_command=("zig", "build", "test"),
        )
        consumer = subject.Contract(
            directory=root / "metal",
            package="metal_backend",
            version="0.1.0",
            layer="backend",
            owner="metal-team",
            public_modules={"metal_backend": "mod.zig"},
            dependencies={"gpu_backend": "../gpu"},
            injected_modules=frozenset(),
            api_surface=("Backend",),
            api_contract=subject.ApiContract(
                signature_tests=("mod.zig::signature",),
                invariant_tests=("mod.zig::invariant",),
            ),
            ci_lane="metal_backend",
            ci_host="macos",
            ci_command=("zig", "build", "test"),
        )
        failures: list[str] = []
        subject._validate_layers(
            [dependency, consumer],
            {dependency.package: dependency, consumer.package: consumer},
            failures,
        )
        self.assertEqual(1, len(failures))
        self.assertIn("backend layer cannot depend on backend", failures[0])

    def test_api_contract_requires_reachable_named_tests(self) -> None:
        with TemporaryDirectory() as directory:
            owner = Path(directory).resolve()
            (owner / "mod.zig").write_text(
                'test "signature" {}\nconst law = @import("law.zig");\n',
                encoding="utf-8",
            )
            (owner / "law.zig").write_text(
                'test "invariant" {}\n',
                encoding="utf-8",
            )
            contract = subject.Contract(
                directory=owner,
                package="owned_package",
                version="0.1.0",
                layer="service",
                owner="owned-team",
                public_modules={"owned_package": "mod.zig"},
                dependencies={},
                injected_modules=frozenset(),
                api_surface=(),
                api_contract=subject.ApiContract(
                    signature_tests=("mod.zig::signature",),
                    invariant_tests=("law.zig::invariant",),
                ),
                ci_lane="owned_package",
                ci_host="linux",
                ci_command=("zig", "build", "test"),
            )
            failures: list[str] = []
            subject._validate_api_contract(contract, failures)
            self.assertEqual([], failures)

    def test_relative_import_cannot_enter_a_package_owner(self) -> None:
        with TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            owner = repository / "src/owned"
            consumer = repository / "src/consumer.zig"
            owner.mkdir(parents=True)
            (owner / "mod.zig").write_text("pub const ok = true;\n", encoding="utf-8")
            consumer.write_text(
                'const owned = @import("owned/mod.zig");\n',
                encoding="utf-8",
            )
            contract = subject.Contract(
                directory=owner,
                package="owned_package",
                version="0.1.0",
                layer="service",
                owner="owned-team",
                public_modules={"owned_package": "mod.zig"},
                dependencies={},
                injected_modules=frozenset(),
                api_surface=("ok",),
                api_contract=subject.ApiContract(
                    signature_tests=("mod.zig::signature",),
                    invariant_tests=("mod.zig::invariant",),
                ),
                ci_lane="owned_package",
                ci_host="linux",
                ci_command=("zig", "build", "test"),
            )
            failures: list[str] = []
            subject._validate_relative_ingress(repository, [contract], failures)
            self.assertEqual(1, len(failures))
            self.assertIn("use one of ['owned_package']", failures[0])

    def test_embed_file_cannot_escape_a_package_owner(self) -> None:
        with TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            owner = repository / "src/owned"
            owner.mkdir(parents=True)
            (repository / "private.txt").write_text("private\n", encoding="utf-8")
            (owner / "mod.zig").write_text(
                'pub const private = @embedFile("../../private.txt");\n',
                encoding="utf-8",
            )
            contract = subject.Contract(
                directory=owner,
                package="owned_package",
                version="0.1.0",
                layer="service",
                owner="owned-team",
                public_modules={"owned_package": "mod.zig"},
                dependencies={},
                injected_modules=frozenset(),
                api_surface=("private",),
                api_contract=subject.ApiContract(
                    signature_tests=("mod.zig::signature",),
                    invariant_tests=("mod.zig::invariant",),
                ),
                ci_lane="owned_package",
                ci_host="linux",
                ci_command=("zig", "build", "test"),
            )
            failures: list[str] = []
            subject._validate_imports(contract, {}, failures)
            self.assertEqual(1, len(failures))
            self.assertIn("embedded file escapes owner", failures[0])

    def test_generated_embeds_require_declaration_and_unambiguous_owned_asset(self):
        with TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            owner = root / "src/owned"
            owner.mkdir(parents=True)
            (root / "build_support").mkdir()
            (root / "vectors").mkdir()
            asset = root / "vectors/air.bin"
            asset.write_bytes(b"pinned AIR fixture")
            producer = root / "build_support/producer.zig"
            binding = '.{ .name = "generated_air", .path = "vectors/air.bin" },'
            producer.write_text("const embedded_assets = [_]struct { name: []const u8, path: []const u8 }{\n" + binding + "\n};\n")
            (owner / "mod.zig").write_text('pub const air = @embedFile("generated_air");\n')
            contract = replace(subject.load_contract(ROOT / "src/backends/cuda/package.contract.json"), directory=owner, injected_modules=frozenset({"generated_air"}))
            assets = subject.ci_package_graph.generated_embedded_assets(root)
            self.assertEqual({"generated_air": asset}, assets)
            failures = []
            subject._validate_imports(contract, {}, failures, assets)
            self.assertEqual([], failures)
            for candidate, sources in ((replace(contract, injected_modules=frozenset()), assets), (contract, {})):
                failures = []
                subject._validate_imports(candidate, {}, failures, sources)
                self.assertIn("embedded file is missing", failures[0])
            other = root / "vectors/other.bin"
            other.write_bytes(b"other")
            producer.write_text("const embedded_assets = [_]struct { name: []const u8, path: []const u8 }{\n" + binding + '\n.{ .name = "generated_air", .path = "vectors/other.bin" },\n};\n')
            self.assertEqual({}, subject.ci_package_graph.generated_embedded_assets(root))
            producer.write_text("const embedded_assets = [_]struct { name: []const u8, path: []const u8 }{\n" + binding + "\n};\n")
            asset.unlink()
            self.assertEqual({}, subject.ci_package_graph.generated_embedded_assets(root))

    def test_package_readme_is_required(self) -> None:
        with TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            owner = repository / "src/owned"
            owner.mkdir(parents=True)
            contract = subject.Contract(
                directory=owner,
                package="owned_package",
                version="0.1.0",
                layer="service",
                owner="owned-team",
                public_modules={"owned_package": "mod.zig"},
                dependencies={},
                injected_modules=frozenset(),
                api_surface=("Service",),
                api_contract=subject.ApiContract(
                    signature_tests=("mod.zig::signature",),
                    invariant_tests=("mod.zig::invariant",),
                ),
                ci_lane="owned_package",
                ci_host="linux",
                ci_command=("zig", "build", "test"),
            )
            failures: list[str] = []
            subject._validate_readme(repository, contract, failures)
            self.assertEqual(
                ["owned_package: package README.md is missing"],
                failures,
            )


if __name__ == "__main__":
    unittest.main()
