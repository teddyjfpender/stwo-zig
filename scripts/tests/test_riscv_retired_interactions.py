"""The retired opcode generator is an oracle, never a production AIR route."""
from pathlib import Path
import unittest
from scripts.repo.product_closure.graph import inspect_sources, literal_imports
from scripts.repo.product_closure.model import Manifest, NamedImport

ROOT = Path(__file__).resolve().parents[2]


class RetiredInteractionTests(unittest.TestCase):
    def test_only_test_surfaces_import_the_oracle(self) -> None:
        allowed = {
            "src/frontends/riscv/rv32/mod.zig",
            "src/frontends/riscv/rv32/tests/root.zig",
            "src/frontends/riscv/rv32/focused_test_air_semantics_0.zig",
        }
        consumers = set()
        for source in (ROOT / "src").rglob("*.zig"):
            for imported in literal_imports(source.read_text()):
                if imported.endswith("interaction_legacy_test_oracle.zig"):
                    consumers.add(str(source.relative_to(ROOT)))
        self.assertEqual(allowed, consumers)

    def test_retired_public_route_is_absent(self) -> None:
        air = ROOT / "src/frontends/riscv/compat/air"
        self.assertFalse((air / "interaction_gen.zig").exists())
        self.assertNotIn("pub const interaction_gen", (air / "mod.zig").read_text())

    def test_memory_owner_excludes_retired_writers_and_constraints(self) -> None:
        source = (ROOT / "src/frontends/riscv/rv32/air/opcode_memory.zig").read_text()
        for declaration in ("pub fn generate(", "pub fn constraints(", "pub const Generated", "fn accessFromTrace("):
            self.assertNotIn(declaration, source)

    def test_retired_executor_file_and_export_are_absent(self) -> None:
        runner = ROOT / "src/frontends/riscv/runner"
        self.assertFalse((runner / "execute.zig").exists())
        self.assertNotIn("execute_mod", (runner / "mod.zig").read_text())

    def test_session_and_host_runtime_exclude_proving_and_oracles(self) -> None:
        manifest = Manifest(
            product="typed-session-host-contract",
            entry_roots=(
                "src/frontends/riscv/runner/segment_session.zig",
                "src/frontends/riscv/rv32/host/runtime.zig",
            ),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),
                *(NamedImport("stwo_riscv_" + name, "src/frontends/riscv/" + name + "/mod.zig")
                  for name in ("isa", "air_lang", "memory", "recursion_air", "precompiles", "rv32"))),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/waist/core", "src/frontends/riscv"),
        )
        sources = inspect_sources(ROOT, manifest).relative_sources()
        self.assertIn("src/frontends/riscv/rv32/runner/generated_retirement.zig", sources)
        self.assertIn("src/frontends/riscv/isa/host/interface.zig", sources)
        for source in sources:
            if source.startswith("src/frontends/riscv/"):
                self.assertNotIn("/prover", source)
                self.assertNotIn("/recursion/", source)
                self.assertNotIn("legacy_test_oracle", source)
                self.assertNotIn("sail_oracle", source)
                self.assertFalse(source.endswith("_test.zig"), source)
