from __future__ import annotations

import unittest
from dataclasses import replace
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


class ConsumerMetadataGrammarTests(unittest.TestCase):
    """Shape-only checkpoint; source ownership and execution are separate gates."""

    def payload(self, schema="stwo-zig-package-contract-v3"):
        import json
        value = json.loads((ROOT / "src/waist/backend/package.contract.json").read_text())
        value["schema"] = schema
        if schema.endswith("v3"):
            value["consumers"] = [{"id": "package:stwo_cpu_backend",
                                   "root": "src/backends/cpu_scalar/contract_tests/stwo_backend_contracts_test.zig",
                                   "route": "dependency:stwo_backend_contracts",
                                   "imports": ["stwo_backend_contracts", "stwo_core"],
                                   "tests": ["cdc: CPU column contract preserves field ownership"]}]
        return value

    def parse(self, payload):
        return subject.ci_package_graph.parse_contract_metadata(payload, "fixture")

    def test_closed_v2_is_retained_without_extension_metadata(self):
        actual = self.parse(self.payload("stwo-zig-package-contract-v2"))
        self.assertEqual((), actual.consumers)
        self.assertIsNone(actual.budget)
        for key, value in (("consumers", []), ("budget", {}), ("unknown", 0)):
            payload = self.payload("stwo-zig-package-contract-v2")
            payload[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.parse(payload)

    def test_v3_registration_preserves_exact_owned_metadata_without_claiming_execution(self):
        actual = self.parse(self.payload())
        self.assertEqual("package:stwo_cpu_backend", actual.consumers[0].id)
        self.assertEqual(("stwo_backend_contracts", "stwo_core"), actual.consumers[0].imports)
        self.assertEqual(("cdc: CPU column contract preserves field ownership",), actual.consumers[0].tests)
        self.assertIsNone(actual.budget)
        payload = self.payload()
        payload["consumers"] = []
        self.assertEqual((), self.parse(payload).consumers)  # shape only, not live-census coverage
        payload["consumers"] = [{**self.payload()["consumers"][0], "id": "product:stwo-native-cpu", "route": "product:stwo-native-cpu"}]
        self.assertEqual("product:stwo-native-cpu", self.parse(payload).consumers[0].id)

    def test_unknown_schema_extra_missing_fields_and_wrong_containers_fail(self):
        for key, value in (("schema", "stwo-zig-package-contract-v4"), ("schema", None),
                           ("unknown", []), ("consumers", {}), ("consumers", [None])):
            payload = self.payload()
            payload[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.parse(payload)
        for key in ("consumers", "api_contract", "owner"):
            payload = self.payload()
            del payload[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.parse(payload)
        for payload in (None, [], "v3"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.parse(payload)

    def test_consumer_records_are_closed_unique_sorted_and_nonempty(self):
        original = self.payload()["consumers"][0]
        for key, value in (("id", "unknown:cpu"), ("id", "package:../cpu"), ("id", ""),
                           ("route", "unknown:backend"), ("route", "product:stwo-native-cpu"),
                           ("imports", []), ("imports", ["std"]), ("imports", ["private.zig"]),
                           ("imports", ["stwo_core", "stwo_backend_contracts"]),
                           ("imports", ["stwo_core", "stwo_core"]), ("tests", []),
                           ("tests", [" "]), ("tests", ["b", "a"]), ("tests", ["a", "a"]),
                           ("tests", ["bad\nname"]), ("root", "/tmp/test.zig"),
                           ("root", "src/../outside/test.zig"), ("root", "src//test.zig"),
                           ("root", "src/owner/test.py"), ("root", "src\\owner\\test.zig"),
                           ("extra", True)):
            payload = self.payload()
            payload["consumers"] = [{**original, key: value}]
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.parse(payload)
        for key in original:
            payload = self.payload()
            del payload["consumers"][0][key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.parse(payload)
        for records in ([original, original], [{**original, "id": "package:zzz"}, original]):
            payload = self.payload()
            payload["consumers"] = records
            with self.subTest(records=records), self.assertRaises(ValueError):
                self.parse(payload)
        payload = self.payload()
        payload["consumers"][0].update(id="product:stwo-native-cpu", route="product:other")
        with self.assertRaises(ValueError):
            self.parse(payload)

    def test_nine_budget_dimensions_are_closed_integer_maxima_and_absence_is_distinct(self):
        keys = ("code_files", "code_lines", "generated_code_files", "generated_code_lines",
                "script_files", "api_entries", "dependencies", "rv64_registry_flags", "versioned_files")
        payload = self.payload()
        payload["budget"] = dict.fromkeys(keys, 0)
        self.assertEqual(dict.fromkeys(keys, 0), self.parse(payload).budget)
        for key in keys:
            for value in (-1, True, False, 0.5, "1", None):
                payload["budget"] = {**dict.fromkeys(keys, 0), key: value}
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.parse(payload)
            payload["budget"] = {k: 0 for k in keys if k != key}
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.parse(payload)
        for value in (None, [], {**dict.fromkeys(keys, 0), "unmeasured_metric": 1}):
            payload["budget"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.parse(payload)
        payload.pop("budget")
        self.assertIsNone(self.parse(payload).budget)

    def test_schema_checkpoint_does_not_activate_unvalidated_v3_workspace_reading(self):
        import json
        with TemporaryDirectory() as raw:
            path = Path(raw) / "package.contract.json"
            path.write_text(json.dumps(self.payload()))
            with self.assertRaises(ValueError):
                subject.load_contract(path)

if __name__ == "__main__":
    unittest.main()
