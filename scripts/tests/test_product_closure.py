from __future__ import annotations

import argparse
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from scripts.repo import check_product_closure as command
from scripts.native import check_native_cpu_product
from scripts.repo.product_closure.graph import ClosureError, inspect_sources
from scripts.repo.product_closure.linkage import (
    DynamicLinkage,
    check_dynamic,
    check_static_elf,
    inspect_elf,
)
from scripts.repo.product_closure.model import Manifest, NamedImport
from scripts.tests.product_closure_recursion_cases import RecursionOwnershipTest


class NativeCpuProductCheckTest(unittest.TestCase):
    def test_qualified_facades_keep_metadata_and_fail_closed_on_executable_code(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "src/tests").mkdir(parents=True)
            for name in ("good.zig", "bad.zig", "tests/root.zig"):
                (root / "src" / name).write_text("pub const Value = u32;\n")
            caller = root / "src/caller.zig"
            caller.write_text('const T = @import("api").primitives.fixed.Value;\n')
            facade = root / "src/api.zig"
            aliases = ('pub const primitives = struct { pub const fixed = @import("good.zig"); };\n'
                       'pub const unrelated = @import("bad.zig");\n'
                       'test { _ = @import("tests/root.zig"); }\n')
            facade.write_text(aliases)
            manifest = Manifest("facade", ("src/caller.zig",),
                                (NamedImport("api", "src/api.zig"),),
                                frozenset(), frozenset(), ("src",))
            graph = inspect_sources(root, manifest)
            self.assertEqual({"src/api.zig", "src/caller.zig", "src/good.zig"},
                             set(graph.relative_sources()))
            baseline_digest = graph.source_digest()
            facade.write_text(aliases + "\n// metadata is still hashed\n")
            self.assertNotEqual(baseline_digest, inspect_sources(root, manifest).source_digest())
            for extra in ('comptime { _ = @import("bad.zig"); }',
                          'pub const executed = @import("bad.zig").run();',
                          'pub const arbitrary = 1;',
                          'test { _ = @import("bad.zig"); }'):
                facade.write_text(aliases + extra)
                self.assertIn("src/bad.zig", inspect_sources(root, manifest).relative_sources())
            facade.write_text(aliases)
            caller.write_text(caller.read_text() + 'const whole = @import("api");\n')
            self.assertIn("src/bad.zig", inspect_sources(root, manifest).relative_sources())

    def test_aggregate_facade_binds_only_existing_support_and_generic_cpu_engine(self):
        import re
        root = Path(__file__).resolve().parents[2]
        descriptor = (root / "build_support/products/aggregate.zig").read_text()
        section = descriptor.split("const shared_named_imports", 1)[1].split("\n};", 1)[0]
        modules = dict(re.findall(r'\.name = "([^"\n]+)", \.source = "([^"\n]+)"', section))
        for name, source in (("atomic_file", "src/support/io/atomic_file.zig"),
                             ("stwo_native_artifact", "src/products/native/artifact/mod.zig"),
                             ("interop_riscv_artifact", "src/products/riscv/artifact/mod.zig")):
            self.assertEqual(source, modules[name])
            self.assertTrue((root / source).is_file())
        facade = (root / "src/products/cairo/aggregate/cpu.zig").read_text()
        self.assertIn("frontends.riscv.prover_mod.ProverEngineForBackend(backends.cpu.CpuBackend)", facade)
        self.assertNotIn('"stwo_riscv_cpu_integration"', facade)
        self.assertNotIn("addRiscVCpuImport", (root / "build_support/products/aggregate_cli.zig").read_text())

    def check(self, payload: bytes, *, rewind: bool = False, exit_code: int = 0) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "applications"
            binary.write_text(
                f"#!{sys.executable}\nimport os\n"
                + ("os.lseek(1, 0, os.SEEK_SET)\n" if rewind else "")
                + f"os.write(1, {payload!r})\nraise SystemExit({exit_code})\n"
            )
            binary.chmod(0o755)
            return check_native_cpu_product.check_binary(binary)

    def test_real_streaming_subprocess_preserves_prior_redirected_output(self) -> None:
        registry = {"product": {"name": "stwo-native-cpu"}, "applications": [{"air": "xor"}]}
        self.assertEqual([], self.check(json.dumps(registry).encode()))

    def test_rewinding_subprocess_reproduces_overwrite_failure(self) -> None:
        self.assertIn("overwrote prior", self.check(b"{}", rewind=True)[0])

    def test_malformed_or_wrong_registry_is_rejected(self) -> None:
        for raw in (b"invalid", b"[]", b"{}", b'{"product": {}, "applications": []}'):
            with self.subTest(raw=raw):
                self.assertTrue(self.check(raw))

    def test_failed_command_cannot_pass_with_registry_bytes(self) -> None:
        self.assertIn("exited 1", self.check(b"{}", exit_code=1)[0])


class SourceClosureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def manifest(self, **changes: object) -> Manifest:
        values: dict[str, object] = {
            "product": "test-cpu",
            "entry_roots": ("src/product/main.zig",),
            "named_imports": (NamedImport("core", "src/waist/core/mod.zig"),),
            "generated_imports": frozenset({"std"}),
            "allowed_files": frozenset(),
            "allowed_prefixes": ("src/product", "src/waist/core"),
        }
        values.update(changes)
        return Manifest(**values)  # type: ignore[arg-type]

    def test_typed_opcode_production_excludes_retired_evaluators(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="typed-opcode-authority",
            entry_roots=(
                "src/frontends/riscv/rv32/runner/trace.zig",
                "src/frontends/riscv/rv32/air/constraint_program.zig",
                "src/frontends/riscv/rv32/air/semantics/mod.zig",
            ),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/waist/core", "src/frontends/riscv"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        self.assertIn("src/frontends/riscv/rv32/air/x0_native_envelope.zig", sources)
        for source in sources:
            self.assertNotIn("legacy_test_oracle", source)
            if source.startswith("src/frontends/riscv/"):
                self.assertFalse(source.endswith("_test.zig"), source)
            if source.startswith("src/frontends/riscv/air/semantics/"):
                self.assertIn(Path(source).name, {
                    "mod.zig", "common.zig", "control_common.zig", "shift_common.zig",
                    "read_access.zig",
                })

    def test_typed_opcode_authority_rejects_a_prover_dependency(self) -> None:
        owner = Path(__file__).resolve().parents[2] / "src/frontends/riscv/rv32/air/x0_native_envelope.zig"
        read_text = Path.read_text

        def mutated_text(path: Path, *args: object, **kwargs: object) -> str:
            text = read_text(path, *args, **kwargs)
            return text + '\nconst forbidden = @import("stwo_prover_engine");\n' if path == owner else text

        with mock.patch.object(Path, "read_text", mutated_text):
            with self.assertRaisesRegex(ClosureError, "x0_native_envelope.zig: undeclared named import 'stwo_prover_engine'"):
                self.test_typed_opcode_production_excludes_retired_evaluators()

    def test_resolves_relative_and_named_imports(self) -> None:
        self.write(
            "src/product/main.zig",
            'const std = @import("std");\nconst core = @import("core");\n'
            'const child = @import(\n    "child.zig",\n);\n',
        )
        self.write("src/product/child.zig", "pub const value = 1;\n")
        self.write("src/waist/core/mod.zig", "pub const value = 2;\n")
        graph = inspect_sources(self.root, self.manifest())
        self.assertEqual(3, len(graph.sources))
        self.assertEqual(64, len(graph.source_digest()))

    def test_manifest_digest_binds_policy(self) -> None:
        original = self.manifest()
        changed = self.manifest(
            allowed_prefixes=("src/product", "src/waist/core", "src/hidden")
        )
        self.assertNotEqual(original.digest(), changed.digest())
        self.assertEqual(original.digest(), self.manifest().digest())

    def test_rejects_undeclared_named_import(self) -> None:
        self.write("src/product/main.zig", 'const hidden = @import("hidden");\n')
        self.write("src/waist/core/mod.zig", "")
        with self.assertRaisesRegex(ClosureError, "undeclared named import"):
            inspect_sources(self.root, self.manifest())

    def test_rejects_relative_import_escape(self) -> None:
        outside = self.root.parent / "outside.zig"
        outside.write_text("", encoding="utf-8")
        self.addCleanup(outside.unlink)
        self.write("src/product/main.zig", 'const hidden = @import("../../../outside.zig");\n')
        self.write("src/waist/core/mod.zig", "")
        with self.assertRaisesRegex(ClosureError, "escapes repository"):
            inspect_sources(self.root, self.manifest())

    def test_rejects_source_outside_manifest(self) -> None:
        self.write("src/product/main.zig", 'const hidden = @import("../hidden.zig");\n')
        self.write("src/hidden.zig", "")
        self.write("src/waist/core/mod.zig", "")
        with self.assertRaisesRegex(ClosureError, "outside product manifest"):
            inspect_sources(self.root, self.manifest())

    def test_aggregate_manifest_rejects_unrelated_product_owner(self) -> None:
        self.write(
            "src/products/stwo/tools/prove/main.zig",
            'const unrelated = @import("../../../unrelated/main.zig");\n',
        )
        self.write("src/products/unrelated/main.zig", "pub const value = 1;\n")
        self.write("src/waist/core/mod.zig", "")
        self.write("src/engine/prover/mod.zig", "")
        manifest = self.manifest(
            product="stwo-zig",
            entry_roots=("src/products/stwo/tools/prove/main.zig",),
            named_imports=(),
            allowed_prefixes=("src/products/stwo/tools/prove", "src/waist/core", "src/engine/prover"),
        )
        with self.assertRaisesRegex(ClosureError, "outside product manifest"):
            inspect_sources(self.root, manifest)

    def test_rejects_named_module_cycle(self) -> None:
        self.write("src/product/main.zig", 'const core = @import("core");\n')
        self.write("src/waist/core/mod.zig", 'const product = @import("product");\n')
        manifest = self.manifest(
            named_imports=(
                NamedImport("core", "src/waist/core/mod.zig"),
                NamedImport("product", "src/product/main.zig"),
            )
        )
        with self.assertRaisesRegex(ClosureError, "source import cycle"):
            inspect_sources(self.root, manifest)

    def test_allows_internal_test_self_import_cycle(self) -> None:
        self.write("src/product/main.zig", 'const child = @import("child.zig");\n')
        self.write("src/product/child.zig", 'const main = @import("main.zig");\n')
        self.write("src/waist/core/mod.zig", "")
        graph = inspect_sources(self.root, self.manifest())
        self.assertEqual(2, len(graph.sources))

    def test_comment_and_multiline_text_do_not_create_imports(self) -> None:
        self.write(
            "src/product/main.zig",
            '// @import("hidden.zig")\nconst text = \\\\@import("hidden.zig");\n'
            'const ordinary = "@import(\\\"hidden.zig\\\")";\n',
        )
        self.write("src/waist/core/mod.zig", "")
        graph = inspect_sources(self.root, self.manifest())
        self.assertEqual(("src/product/main.zig",), graph.relative_sources())

    def test_rejects_non_literal_import(self) -> None:
        self.write("src/product/main.zig", "const hidden = @import(path);\n")
        self.write("src/waist/core/mod.zig", "")
        with self.assertRaisesRegex(
            ClosureError,
            r"src/product/main\.zig: unsupported non-literal",
        ):
            inspect_sources(self.root, self.manifest())


class ElfClosureTest(unittest.TestCase):
    def fake_elf(self, path: Path, *, interpreter: bool = False) -> None:
        data = bytearray(128)
        data[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", data, 18, 62)
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<H", data, 54, 56)
        struct.pack_into("<H", data, 56, 1)
        struct.pack_into("<I", data, 64, 3 if interpreter else 1)
        path.write_bytes(data)

    def test_static_elf_identity_is_host_independent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "candidate"
            self.fake_elf(path)
            identity = inspect_elf(path)
            self.assertEqual([], check_static_elf(identity, "x86_64", 64))

    def test_static_elf_rejects_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "candidate"
            self.fake_elf(path, interpreter=True)
            errors = check_static_elf(inspect_elf(path), "x86_64", 64)
            self.assertIn("static ELF contains a PT_INTERP program header", errors)

    def test_dynamic_policy_requires_and_forbids_exact_runtime_tokens(self) -> None:
        linkage = DynamicLinkage(
            inspector="otool",
            output="/System/Library/Frameworks/Metal.framework/Metal\nlibobjc.A.dylib\n",
        )
        self.assertEqual(
            [],
            check_dynamic(linkage, ("metal.framework", "libobjc"), ("cuda",)),
        )
        self.assertEqual(
            ["binary links forbidden dynamic dependency 'metal'"],
            check_dynamic(linkage, (), ("metal",)),
        )


class CommandTest(unittest.TestCase):
    def test_invalid_named_import_is_reported_without_traceback(self) -> None:
        args = argparse.Namespace(
            repo=command.ROOT,
            product="test",
            entry_root=["src/products/stwo/root.zig"],
            named_import=["invalid"],
            generated_import=[],
            allow_file=[],
            allow_prefix=["src"],
            binary=None,
            require_link=[],
            forbid_link=[],
            static_binary=None,
            static_machine="x86_64",
            static_bits=64,
            receipt=None,
        )
        errors, receipt = command.run(args)
        self.assertEqual({}, receipt)
        self.assertIn("named import must be NAME=PATH", errors[0])

    def test_link_policy_without_binary_fails_closed(self) -> None:
        args = argparse.Namespace(
            repo=command.ROOT,
            product="test",
            entry_root=["src/products/stwo/root.zig"],
            named_import=[],
            generated_import=[],
            allow_file=[],
            allow_prefix=["src"],
            binary=None,
            require_link=[],
            forbid_link=["metal"],
            static_binary=None,
            static_machine="x86_64",
            static_bits=64,
            receipt=None,
        )
        errors, receipt = command.run(args)
        self.assertEqual({}, receipt)
        self.assertEqual(["dynamic linkage policy requires --binary"], errors)


if __name__ == "__main__":
    unittest.main()
