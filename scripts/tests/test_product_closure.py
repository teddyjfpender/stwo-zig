from __future__ import annotations

import argparse
import struct
import tempfile
import unittest
from pathlib import Path

from scripts import check_product_closure as command
from scripts.product_closure.graph import ClosureError, inspect_sources
from scripts.product_closure.linkage import (
    DynamicLinkage,
    check_dynamic,
    check_static_elf,
    inspect_elf,
)
from scripts.product_closure.model import Manifest, NamedImport


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
            "named_imports": (NamedImport("core", "src/core/mod.zig"),),
            "generated_imports": frozenset({"std"}),
            "allowed_files": frozenset(),
            "allowed_prefixes": ("src/product", "src/core"),
        }
        values.update(changes)
        return Manifest(**values)  # type: ignore[arg-type]

    def test_resolves_relative_and_named_imports(self) -> None:
        self.write(
            "src/product/main.zig",
            'const std = @import("std");\nconst core = @import("core");\n'
            'const child = @import(\n    "child.zig",\n);\n',
        )
        self.write("src/product/child.zig", "pub const value = 1;\n")
        self.write("src/core/mod.zig", "pub const value = 2;\n")
        graph = inspect_sources(self.root, self.manifest())
        self.assertEqual(3, len(graph.sources))
        self.assertEqual(64, len(graph.source_digest()))

    def test_manifest_digest_binds_policy(self) -> None:
        original = self.manifest()
        changed = self.manifest(
            allowed_prefixes=("src/product", "src/core", "src/hidden")
        )
        self.assertNotEqual(original.digest(), changed.digest())
        self.assertEqual(original.digest(), self.manifest().digest())

    def test_rejects_undeclared_named_import(self) -> None:
        self.write("src/product/main.zig", 'const hidden = @import("hidden");\n')
        self.write("src/core/mod.zig", "")
        with self.assertRaisesRegex(ClosureError, "undeclared named import"):
            inspect_sources(self.root, self.manifest())

    def test_rejects_relative_import_escape(self) -> None:
        outside = self.root.parent / "outside.zig"
        outside.write_text("", encoding="utf-8")
        self.addCleanup(outside.unlink)
        self.write("src/product/main.zig", 'const hidden = @import("../../../outside.zig");\n')
        self.write("src/core/mod.zig", "")
        with self.assertRaisesRegex(ClosureError, "escapes repository"):
            inspect_sources(self.root, self.manifest())

    def test_rejects_source_outside_manifest(self) -> None:
        self.write("src/product/main.zig", 'const hidden = @import("../hidden.zig");\n')
        self.write("src/hidden.zig", "")
        self.write("src/core/mod.zig", "")
        with self.assertRaisesRegex(ClosureError, "outside product manifest"):
            inspect_sources(self.root, self.manifest())

    def test_aggregate_manifest_rejects_unrelated_product_owner(self) -> None:
        self.write(
            "src/tools/prove/main.zig",
            'const unrelated = @import("../../products/unrelated/main.zig");\n',
        )
        self.write("src/products/unrelated/main.zig", "pub const value = 1;\n")
        self.write("src/core/mod.zig", "")
        self.write("src/prover/mod.zig", "")
        manifest = self.manifest(
            product="stwo-zig",
            entry_roots=("src/tools/prove/main.zig",),
            named_imports=(),
            allowed_prefixes=("src/tools/prove", "src/core", "src/prover"),
        )
        with self.assertRaisesRegex(ClosureError, "outside product manifest"):
            inspect_sources(self.root, manifest)

    def test_rejects_named_module_cycle(self) -> None:
        self.write("src/product/main.zig", 'const core = @import("core");\n')
        self.write("src/core/mod.zig", 'const product = @import("product");\n')
        manifest = self.manifest(
            named_imports=(
                NamedImport("core", "src/core/mod.zig"),
                NamedImport("product", "src/product/main.zig"),
            )
        )
        with self.assertRaisesRegex(ClosureError, "source import cycle"):
            inspect_sources(self.root, manifest)

    def test_allows_internal_test_self_import_cycle(self) -> None:
        self.write("src/product/main.zig", 'const child = @import("child.zig");\n')
        self.write("src/product/child.zig", 'const main = @import("main.zig");\n')
        self.write("src/core/mod.zig", "")
        graph = inspect_sources(self.root, self.manifest())
        self.assertEqual(2, len(graph.sources))

    def test_comment_and_multiline_text_do_not_create_imports(self) -> None:
        self.write(
            "src/product/main.zig",
            '// @import("hidden.zig")\nconst text = \\\\@import("hidden.zig");\n'
            'const ordinary = "@import(\\\"hidden.zig\\\")";\n',
        )
        self.write("src/core/mod.zig", "")
        graph = inspect_sources(self.root, self.manifest())
        self.assertEqual(("src/product/main.zig",), graph.relative_sources())

    def test_rejects_non_literal_import(self) -> None:
        self.write("src/product/main.zig", "const hidden = @import(path);\n")
        self.write("src/core/mod.zig", "")
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
            entry_root=["src/stwo.zig"],
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
            entry_root=["src/stwo.zig"],
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
