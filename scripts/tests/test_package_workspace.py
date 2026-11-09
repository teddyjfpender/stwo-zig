from __future__ import annotations

import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from scripts.repo import check_package_workspace as subject
ROOT = Path(__file__).resolve().parents[2]


class PackageWorkspaceTests(unittest.TestCase):
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
