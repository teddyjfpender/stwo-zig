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

    def test_typed_opcode_production_excludes_retired_evaluators(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="typed-opcode-authority",
            entry_roots=(
                "src/frontends/riscv/runner/trace.zig",
                "src/frontends/riscv/air/constraint_program.zig",
                "src/frontends/riscv/air/semantics/mod.zig",
            ),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/core", "src/frontends/riscv"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertNotIn("legacy_test_oracle", source)
            if source.startswith("src/frontends/riscv/"):
                self.assertFalse(source.endswith("_test.zig"), source)
            if source.startswith("src/frontends/riscv/air/semantics/"):
                self.assertIn(Path(source).name, {
                    "mod.zig", "common.zig", "control_common.zig", "shift_common.zig",
                    "read_access.zig",
                })

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


class RecursionOwnershipTest(unittest.TestCase):
    def test_wide_poseidon_typed_plan_is_independent_and_verifier_safe(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="typed-wide-poseidon-definition",
            entry_roots=("src/frontends/riscv/air/lang/typed_poseidon2_wide.zig",),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({"src/frontends/riscv/access_clock.zig"}),
            allowed_prefixes=("src/core", "src/frontends/riscv/air"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for path in sources:
            self.assertNotIn("/prover/", path)
            self.assertNotIn("/runner/", path)
            self.assertNotIn("witness", Path(path).name)
            self.assertNotIn("wide_equation", Path(path).name)
            self.assertNotIn("typed_admission", Path(path).name)
        self.assertNotIn("src/frontends/riscv/air/memory_commitment/poseidon2_air.zig", sources)
        self.assertNotIn("src/frontends/riscv/air/logup.zig", sources)
        self.assertIn("src/frontends/riscv/air/lang/degree3_materializer.zig", sources)
        self.assertIn("src/frontends/riscv/air/lang/typed_poseidon2_bound_program.zig", sources)
        self.assertIn("src/frontends/riscv/air/lang/typed_poseidon2_relation_contract.zig", sources)
        profile = (root / "src/frontends/riscv/recursion/vm_air_profile_v2.zig").read_text()
        shared = profile[profile.index("fn deriveFromSource("):]
        self.assertIn('native_infrastructure_typed_admission.zig").validateKind(descriptor.kind, allocator)', shared)
        owner = (root / "src/frontends/riscv/air/native_infrastructure_typed_admission.zig").read_text()
        self.assertIn('.poseidon2 => try @import("memory_commitment/poseidon2_wide_typed_admission.zig").validate(allocator)', owner)
        for consumer in ("prover/verifier.zig", "prover/proof_finalize.zig"):
            self.assertIn('native_infrastructure_typed_admission.zig").validateStatement(', (root / "src/frontends/riscv" / consumer).read_text())

    def test_native_boundary_definitions_are_independent_and_profile_admitted(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="typed-native-boundary-definition",
            entry_roots=("src/frontends/riscv/air/lang/typed_native_boundary.zig",),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/core", "src/frontends/riscv"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for path in (
            "air/program/interaction.zig", "air/memory_commitment/interaction.zig",
            "air/clock_update_component.zig", "air/lookups/tables/equations.zig",
            "air/native_boundary_typed_admission.zig",
        ):
            self.assertNotIn("src/frontends/riscv/" + path, sources)
        profile = (root / "src/frontends/riscv/recursion/vm_air_profile_v2.zig").read_text()
        shared = profile[profile.index("fn deriveFromSource("):]
        for kind in ("program", "memory", "clock_update", "bitwise", "range_check_20",
                     "range_check_8_11", "range_check_8_8_4", "range_check_8_8", "range_check_m31"):
            self.assertIn(f".{kind} => try boundary_admission.", (root / "src/frontends/riscv/air/native_infrastructure_typed_admission.zig").read_text())
        self.assertIn('native_infrastructure_typed_admission.zig").validateKind(descriptor.kind, allocator)', shared)

    def test_native_merkle_definition_is_independent_and_admitted_by_profiles(self) -> None:
        root = Path(__file__).resolve().parents[2]
        definition = (root / "src/frontends/riscv/air/lang/typed_merkle_node.zig").read_text()
        self.assertNotIn('merkle_node.zig"', definition)
        self.assertNotIn("merkle_typed_admission", definition)
        self.assertIn("a.assertZero", definition)
        profile = (root / "src/frontends/riscv/recursion/vm_air_profile_v2.zig").read_text()
        shared_derivation = profile[profile.index("fn deriveFromSource("):]
        owner = (root / "src/frontends/riscv/air/native_infrastructure_typed_admission.zig").read_text()
        self.assertIn(".merkle =>", owner)
        self.assertIn('merkle_typed_admission.zig").validate(allocator)', owner)
        self.assertIn('native_infrastructure_typed_admission.zig").validateKind(descriptor.kind, allocator)', shared_derivation)

    def test_shared_publication_validation_excludes_prover_and_witness_sources(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="shared-publication-validation",
            entry_roots=tuple("src/frontends/riscv/recursion/" + name + ".zig" for name in (
                "segment_verified_publication_v2", "segment_verified_artifact_v2",
                "canonical_proof_identity_v1", "engine_protocol", "segment_outer_wire_geometry_v2",
            )),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/core", "src/frontends/riscv"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertNotIn("/prover/", source)
            self.assertNotIn("/integrations/", source)
            self.assertNotIn("/backends/", source)
            self.assertNotIn("witness", Path(source).name)
        self.assertNotIn("src/frontends/riscv/recursion/engine.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/segment_outer_cohort_v2.zig", sources)

    def test_detached_leaf_command_excludes_legacy_harness_entrypoints(self) -> None:
        root = Path(__file__).resolve().parents[2]
        for name in (
            "detached_leaf_runner", "detached_leaf_producer", "native_ingress",
            "detached_leaf_options", "workload", "memory_workload", "leaf_key_setup_runner",
        ):
            source = (root / f"src/integrations/riscv_cpu/recursive_segment_v2_{name}.zig").read_text()
            self.assertNotIn('recursive_segment_v2_leaf_outer_proof_test.zig', source)
            self.assertNotIn('recursive_segment_v2_concrete_outer_proof_test.zig', source)
            self.assertNotIn('recursive_segment_v2_outer_engine.zig', source)
            self.assertNotIn('stwo_riscv_cpu_integration', source)
        command = (root / "src/integrations/riscv_cpu/recursive_segment_v2_detached_leaf_runner.zig").read_text()
        self.assertNotIn("runGate", command)
        self.assertNotIn("runSizedProof", command)
        self.assertNotIn("runMemoryProof", command)
        self.assertIn("options_mod.parse(args[1..])", command)

    def test_cpu_public_recursion_surface_excludes_retired_routes(self) -> None:
        root = Path(__file__).resolve().parents[2]
        integration = root / "src/integrations/riscv_cpu"
        public = (integration / "mod.zig").read_text()
        for prefix in ("recursive_temporal_", "recursive_binary_", "recursive_parent_statement_"):
            self.assertNotIn("pub const " + prefix, public)
        for line in public.splitlines():
            if line.startswith("pub const recursive_segment_v2_"):
                self.assertTrue(line.startswith("pub const recursive_segment_v2_detached_"), line)
        build = (integration / "build_segment_steps.zig").read_text()
        for name in ("recursive_temporal_parent_real_proof_runner", "recursive_segment_v2_poseidon_ingress_runner"):
            self.assertFalse((integration / (name + ".zig")).exists())
            self.assertNotIn(name, build)
        self.assertNotIn('"run-recursive-temporal-parent-real-proof"', build)
        self.assertNotIn('"run-recursive-segment-v2-poseidon-ingress"', build)

    def test_canonical_producer_modules_exclude_broad_integration_and_harnesses(self) -> None:
        root = Path(__file__).resolve().parents[2]
        cpu = "src/integrations/riscv_cpu/"
        metal = "src/integrations/riscv_metal/"
        # This guard covers the producer integration layer. Frontend/backend
        # authority and verifier closures have their own transitive guards.
        manifest = Manifest(
            product="canonical-recursive-producer-integration",
            entry_roots=(
                cpu + "recursive_segment_v2_detached_leaf_runner.zig",
                cpu + "recursive_segment_v2_detached_parent_producer_runner.zig",
                cpu + "recursive_segment_v2_leaf_key_setup_runner.zig",
                metal + "recursive_segment_v2_detached_leaf_runner.zig",
                metal + "recursive_segment_v2_detached_parent_producer_runner.zig",
            ),
            named_imports=(
                NamedImport("stwo_riscv_detached_parent_producer", cpu + "recursive_segment_v2_detached_parent_producer.zig"),
                NamedImport("stwo_riscv_detached_leaf_runner", cpu + "recursive_segment_v2_detached_leaf_runner.zig"),
            ),
            generated_imports=frozenset({
                "std", "builtin", "stwo_core", "stwo_cpu_backend", "stwo_metal_backend",
                "stwo_riscv_frontend", "stwo_prover_api", "stwo_prover_engine", "interop_postcard",
            }),
            allowed_files=frozenset(),
            allowed_prefixes=(cpu.rstrip("/"), metal.rstrip("/")),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertFalse(source.endswith("_test.zig"), source)
            self.assertNotIn("test_support", source)
            self.assertNotIn("recursive_temporal_", source)
            self.assertNotEqual(cpu + "mod.zig", source)

    def test_producer_allocator_has_no_integration_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = "src/prover/tracked_smp_allocator.zig"
        manifest = Manifest(
            product="producer-allocation-accounting",
            entry_roots=(source,),
            named_imports=(),
            generated_imports=frozenset({"std"}),
            allowed_files=frozenset({source}),
            allowed_prefixes=(),
        )
        self.assertEqual({source}, set(inspect_sources(root, manifest).relative_sources()))
        for consumer in (
            "src/frontends/riscv/recursion/segment_outer_transaction_v2.zig",
            "src/integrations/riscv_cpu/recursive_segment_v2_detached_leaf_producer.zig",
        ):
            text = (root / consumer).read_text()
            self.assertNotIn('recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig', text)
            self.assertIn("tracked_smp_allocator.TrackedSmpAllocator", text)

    DEFINITION_FILES = (
        "access_schedule", "bounded_arithmetic", "capabilities",
        "conditional_access_evidence", "conditional_access_plan", "definition",
        "digest", "effects", "expr", "functions", "hint_recipe", "hints", "ir",
        "ir_type_rules", "machine_derived_validation", "memory_access_validation",
        "program", "range_refinement", "range_refinement_runtime", "relation",
        "source", "types", "validate", "validate_support", "window_ir_v2",
    )

    def test_typed_verifier_component_excludes_prover_and_witness_sources(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="typed-verifier-component",
            entry_roots=(
                "src/frontends/riscv/recursion/air/universal_typed_verifier_component.zig",
                "src/frontends/riscv/recursion/detached_parent_definitions_v1.zig",
                "src/frontends/riscv/recursion/air/query_bits_profile.zig",
                "src/frontends/riscv/recursion/detached_segment_admission_v1.zig",
                "src/frontends/riscv/recursion/segment_leaf_statement_contract_v2.zig",
                "src/frontends/riscv/air/statement_geometry.zig",
                "src/frontends/riscv/air/memory_commitment/poseidon2_call.zig",
                "src/frontends/riscv/air/statement_v2_authority_preimage.zig",
                "src/frontends/riscv/recursion/detached_segment_public_inputs_v1.zig",
                "src/frontends/riscv/recursion/detached_segment_authority_boundary_v1.zig",
                "src/frontends/riscv/recursion/detached_segment_protocol_v1.zig",
                "src/frontends/riscv/recursion/air/verifier_wire_claims.zig",
                "src/frontends/riscv/recursion/detached_segment_verifier_components_v1.zig",
                "src/frontends/riscv/recursion/segment_leaf_parameters_v2.zig",
                "src/frontends/riscv/recursion/air/segment_leaf_catalog_v2.zig",
                "src/frontends/riscv/recursion/air/verifier_component_parameters.zig",
                "src/frontends/riscv/recursion/air/universal_manifest.zig",
                "src/frontends/riscv/recursion/segment_statement_outer_geometry_v2.zig",
                "src/frontends/riscv/recursion/segment_leaf_outer_geometry_v2.zig",
                "src/frontends/riscv/recursion/segment_publication_input_provider_contract_v2.zig",
                "src/frontends/riscv/recursion/air/segment_outer_typed_catalog_v2.zig",
                "src/frontends/riscv/recursion/air/segment_outer_manifest_contract_v2.zig",
                "src/frontends/riscv/recursion/detached_parent_verifier_components_v1.zig",
            ),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/core", "src/frontends/riscv"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertNotIn("/runner/", source)
            self.assertNotIn("/prover/", source)
            self.assertNotIn("witness", Path(source).name)
            self.assertFalse(Path(source).name.startswith("universal_typed_component"), source)
        self.assertNotIn("src/frontends/riscv/air/logup.zig", sources)

    def test_parent_verification_excludes_prover_runner_and_witness_sources(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="detached-parent-verification",
            entry_roots=("src/integrations/riscv_cpu/recursive_segment_v2_detached_parent_verifier_runner.zig",),
            named_imports=(
                NamedImport("stwo_core", "src/core/mod.zig"),
                NamedImport("stwo_parent_verifier", "src/frontends/riscv/parent_verifier.zig"),
                NamedImport("interop_postcard", "src/interop/postcard.zig"),
                NamedImport("stwo_proof_wire", "src/interop/proof_wire/mod.zig"),
            ),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({"src/integrations/riscv_cpu/recursive_segment_v2_detached_parent_verifier_runner.zig"}),
            allowed_prefixes=("src/core", "src/frontends/riscv", "src/interop"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertNotIn("/runner/", source)
            self.assertNotIn("/prover/", source)
            self.assertNotIn("witness", Path(source).name)
        self.assertNotIn("src/frontends/riscv/recursion/recording_poseidon_channel_v4.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/engine.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/air/qm31_mul_full.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/air/universal_catalog.zig", sources)
        self.assertIn("src/frontends/riscv/air/lang/typed_poseidon2_compact.zig", sources)
        self.assertIn("src/frontends/riscv/air/lang/typed_poseidon2.zig", sources)

    def test_leaf_verification_excludes_prover_runner_and_witness_sources(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="detached-leaf-verification",
            entry_roots=("src/integrations/riscv_cpu/recursive_segment_v2_detached_verifier_runner.zig",),
            named_imports=(
                NamedImport("stwo_core", "src/core/mod.zig"),
                NamedImport("stwo_leaf_verifier", "src/frontends/riscv/leaf_verifier.zig"),
                NamedImport("interop_postcard", "src/interop/postcard.zig"),
                NamedImport("stwo_proof_wire", "src/interop/proof_wire/mod.zig"),
            ),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({"src/integrations/riscv_cpu/recursive_segment_v2_detached_verifier_runner.zig"}),
            allowed_prefixes=("src/core", "src/frontends/riscv", "src/interop"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertNotIn("/runner/", source)
            self.assertNotIn("/prover/", source)
            self.assertNotIn("witness", Path(source).name)
        self.assertNotIn("src/frontends/riscv/recursion/recording_poseidon_channel_v4.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/engine.zig", sources)

    def test_native_table_and_poseidon_verifiers_import_only_core_and_equations(self) -> None:
        root = Path(__file__).resolve().parents[2]
        files = (
            "access_clock.zig", "air/component_point_support.zig",
            "air/logup_equations.zig", "air/lookups/entry.zig",
            "air/lookups/tables/equations.zig", "air/lookups/tables/layout.zig",
            "air/lookups/tables/schema_definition.zig", "air/lookups/tables/verifier.zig",
            "air/relation_challenges.zig", "air/semantics/common.zig",
            "air/semantics/control_common.zig",
            "air/memory_commitment/hash_component_sampling.zig",
            "air/memory_commitment/poseidon2_degree3_verifier.zig",
            "air/memory_commitment/poseidon2_wide_equations.zig",
            "air/memory_commitment/poseidon2_wide_equation_kernel.zig",
            "air/memory_commitment/poseidon2_layout.zig",
            "air/memory_commitment/poseidon2_universal_equations_v1.zig",
            "air/memory_commitment/poseidon2_universal_layout_v1.zig",
            "air/memory_commitment/poseidon2_degree3_schedule.zig",
            "air/memory_commitment/poseidon2_constants.zig",
            "air/memory_commitment/poseidon2_matrix.zig",
        )
        manifest = Manifest(
            product="native-verifier-components",
            entry_roots=tuple("src/frontends/riscv/" + name for name in (
                "air/lookups/tables/verifier.zig",
                "air/memory_commitment/poseidon2_degree3_verifier.zig",
                "air/memory_commitment/poseidon2_universal_equations_v1.zig",
            "air/memory_commitment/poseidon2_universal_layout_v1.zig",
                "air/memory_commitment/poseidon2_wide_equations.zig",
            )),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset("src/frontends/riscv/" + name for name in files),
            allowed_prefixes=("src/core",),
        )
        inspect_sources(root, manifest)

    def test_typed_geometry_has_no_runtime_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        owner = "src/frontends/riscv/recursion/air/universal_typed_geometry.zig"
        manifest = Manifest(
            product="typed-air-geometry",
            entry_roots=(owner,),
            named_imports=(),
            generated_imports=frozenset(),
            allowed_files=frozenset({owner}),
            allowed_prefixes=(),
        )
        self.assertEqual((owner,), inspect_sources(root, manifest).relative_sources())

    def test_shared_provider_admission_has_only_equations_and_metadata(self) -> None:
        root = Path(__file__).resolve().parents[2]
        files = (
            "air/lang/static_collections.zig", "air/lang/typed_poseidon2.zig",
            "air/lang/typed_poseidon2_compact.zig", "air/lang/polynomial_replay.zig",
            "air/extract/symbolic_relations.zig", "air/extract/provider_equivalence.zig",
            "access_clock.zig", "air/extract/canonical_digest.zig", "air/extract/symbolic.zig",
            "air/logup_equations.zig", "air/lookups/entry.zig",
            "air/lookups/tables/layout.zig", "air/lookups/tables/schema_definition.zig",
            "air/relation_challenges.zig", "air/semantics/common.zig",
            "air/semantics/control_common.zig", "air/memory_commitment/poseidon2_constants.zig",
            "air/memory_commitment/poseidon2_degree3_schedule.zig",
            "air/memory_commitment/poseidon2_layout.zig", "air/memory_commitment/poseidon2_matrix.zig",
            "air/memory_commitment/poseidon2_universal_equations_v1.zig",
            "air/memory_commitment/poseidon2_universal_layout_v1.zig",
            "air/memory_commitment/poseidon2_universal_identity_v2.zig",
            "recursion/air/range_check_8_8_contract.zig", "recursion/air/relation_effect.zig",
            "recursion/air/universal_roster.zig", "recursion/air/universal_shared_geometry.zig",
            "air/lang/typed_poseidon2_identity_codec.zig",
            "air/lang/typed_poseidon2_identity_golden.zig",
            "recursion/air/universal_challenges.zig",
            "recursion/air/universal_provider_authority.zig",
            "recursion/air/universal_provider_admission.zig",
            "recursion/air/universal_provider_relations.zig",
        )
        manifest = Manifest(
            product="shared-provider-geometry",
            entry_roots=tuple("src/frontends/riscv/recursion/air/" + name for name in (
                "universal_shared_geometry.zig", "universal_provider_authority.zig",
                "universal_provider_admission.zig",
                "universal_provider_relations.zig",
            )),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=(
                frozenset("src/frontends/riscv/" + name for name in files) |
                frozenset(f"src/frontends/riscv/air/lang/{name}.zig" for name in self.DEFINITION_FILES)
            ),
            allowed_prefixes=("src/core",),
        )
        inspect_sources(root, manifest)

    def test_range_table_contract_has_only_schema_and_definition_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        files = (
            "access_clock.zig", "air/logup_equations.zig",
            "air/lookups/entry.zig", "air/lookups/tables/layout.zig",
            "air/lookups/tables/schema_definition.zig", "air/relation_challenges.zig",
            "air/semantics/common.zig", "air/semantics/control_common.zig",
            "recursion/air/range_check_8_8_contract.zig", "recursion/air/relation_effect.zig",
        )
        manifest = Manifest(
            product="range-table-contract",
            entry_roots=("src/frontends/riscv/recursion/air/range_check_8_8_contract.zig",),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=(
                frozenset("src/frontends/riscv/" + name for name in files) |
                frozenset(f"src/frontends/riscv/air/lang/{name}.zig" for name in self.DEFINITION_FILES)
            ),
            allowed_prefixes=("src/core",),
        )
        inspect_sources(root, manifest)

    def test_vm_profile_identity_has_no_derivation_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = "src/frontends/riscv/recursion/vm_air_profile_v2_identity.zig"
        manifest = Manifest(
            product="vm-profile-identity",
            entry_roots=(source,),
            named_imports=(),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({source}),
            allowed_prefixes=(),
        )
        inspect_sources(root, manifest)

    def test_canonical_poseidon_identity_has_only_typed_equation_and_core_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        files = (
            "air/lang/static_collections.zig", "air/lang/typed_poseidon2.zig",
            "air/lang/typed_poseidon2_compact.zig", "air/lang/polynomial_replay.zig",
            "air/extract/symbolic_relations.zig", "air/extract/provider_equivalence.zig",
            "access_clock.zig", "air/extract/canonical_digest.zig",
            "air/extract/symbolic.zig", "air/logup_equations.zig",
            "air/lookups/entry.zig", "air/relation_challenges.zig",
            "air/semantics/common.zig", "air/semantics/control_common.zig",
            "air/memory_commitment/poseidon2_constants.zig",
            "air/memory_commitment/poseidon2_degree3_schedule.zig",
            "air/memory_commitment/poseidon2_matrix.zig",
            "air/memory_commitment/poseidon2_universal_equations_v1.zig",
            "air/memory_commitment/poseidon2_universal_layout_v1.zig",
            "air/memory_commitment/poseidon2_universal_identity_v2.zig",
        )
        manifest = Manifest(
            product="canonical-poseidon-identity",
            entry_roots=("src/frontends/riscv/air/memory_commitment/poseidon2_universal_identity_v2.zig",),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=(
                frozenset("src/frontends/riscv/" + name for name in files) |
                frozenset(f"src/frontends/riscv/air/lang/{name}.zig" for name in self.DEFINITION_FILES)
            ),
            allowed_prefixes=("src/core",),
        )
        inspect_sources(root, manifest)

    def test_public_claim_has_only_statement_and_core_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="vm-public-claim",
            entry_roots=("src/frontends/riscv/recursion/vm_public_claim.zig",),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(
                "src/frontends/riscv/" + path for path in (
                    "access_clock.zig", "isa/profile.zig", "air/public_data.zig",
                    "air/memory_commitment/poseidon2.zig",
                    "air/memory_commitment/poseidon2_constants.zig",
                    "recursion/poseidon2_channel.zig",
                    "recursion/poseidon2_canonical_word_sponge.zig",
                    "recursion/vm_public_claim.zig",
                    "recursion/vm_public_claim_layout.zig",
                )
            ),
            allowed_prefixes=("src/core",),
        )
        inspect_sources(root, manifest)

    def test_air_definition_and_fixed_wire_import_only_core_and_reviewed_ir(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="air-definition",
            entry_roots=(
                "src/frontends/riscv/air/lang/definition.zig",
                "src/frontends/riscv/recursion/air/fixed_wire_v3.zig",
            ),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({
                "src/frontends/riscv/recursion/air/fixed_wire_v3.zig",
                "src/frontends/riscv/recursion/air/relation_effect.zig",
                "src/frontends/riscv/recursion/air/verifier_wire_protocol.zig",
            }) | frozenset(
                f"src/frontends/riscv/air/lang/{name}.zig" for name in self.DEFINITION_FILES
            ),
            allowed_prefixes=("src/core",),
        )
        inspect_sources(root, manifest)

    def test_parent_protocol_has_no_prover_or_witness_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="detached-parent-protocol",
            entry_roots=("src/frontends/riscv/recursion/detached_parent_protocol_v1.zig",),
            named_imports=(
                NamedImport("stwo_core", "src/core/mod.zig"),
            ),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=(
                "src/core", "src/frontends/riscv",
            ),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        self.assertNotIn("src/frontends/riscv/recursion/detached_parent_prepared_v1.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/compact_tuple_ledger_v1.zig", sources)
        for forbidden in (
            "detached_parent_components_v1.zig", "air/universal_shared_provider.zig",
            "air/universal_typed_component.zig", "air/universal_adapter_manifest.zig",
            "air/manifest_proof_protocol.zig",
        ):
            self.assertNotIn("src/frontends/riscv/recursion/" + forbidden, sources)
        for source in sources:
            self.assertNotIn("/runner/", source)
            self.assertNotIn("/prover/", source)
            self.assertNotIn("witness", Path(source).name)
        # This is the key/claim protocol boundary; standalone verifier component
        # construction is qualified separately and still needs its own guard.

    def test_detached_pcs_preparation_excludes_integrations_and_concrete_backends(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="detached-pcs-preparation",
            entry_roots=("src/frontends/riscv/recursion/detached_pcs_preparation_v1.zig",
                         "src/frontends/riscv/recursion/pcs_transcript_program_v1.zig",
                         "src/frontends/riscv/recursion/transcript_frame_rows_v1.zig",
                         "src/frontends/riscv/recursion/detached_prefix_preparation_v1.zig",
                         "src/frontends/riscv/recursion/detached_pcs_rows_v1.zig",
                         "src/frontends/riscv/recursion/detached_child_views_v1.zig",
                         "src/frontends/riscv/recursion/detached_parent_preparation_v1.zig",
                         "src/frontends/riscv/recursion/air/prepared_interaction_generation.zig",
                         "src/frontends/riscv/recursion/detached_native_leaf_preparation_v2.zig",
                         "src/frontends/riscv/recursion/detached_leaf_noncore_owner_v2.zig",
                         "src/frontends/riscv/recursion/detached_fri_core_v2.zig",
                         "src/frontends/riscv/recursion/detached_leaf_cohort_v2.zig",
                         "src/frontends/riscv/recursion/transaction_storage_v2.zig",
                         "src/frontends/riscv/recursion/leaf_interaction_generator_v2.zig",
                         "src/frontends/riscv/recursion/segment_outer_transaction_v2.zig",
                         "src/frontends/riscv/recursion/binary_verified_publication.zig"),
            named_imports=tuple(NamedImport(name, path) for name, path in (
                ("stwo_core", "src/core/mod.zig"),
                ("stwo_prover_engine", "src/prover/mod.zig"),
                ("stwo_prover_api", "src/prover_api/mod.zig"),
                ("stwo_backend_contracts", "src/backend/mod.zig"),
                ("interop_postcard", "src/interop/postcard.zig"),
                ("stwo_proof_wire", "src/interop/proof_wire/mod.zig"),
                ("typed_air_artifacts", "design/typed-air/artifacts/embedded.zig"),
                ("typed_air_h009_artifacts", "design/typed-air/artifacts/h009_embedded.zig"),
                ("typed_air_h010_artifacts", "design/typed-air/artifacts/h010_embedded.zig"),
            )),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            # Preparation owns witnesses and may use generic proving contracts.
            # Concrete backend and integration directories are deliberately absent.
            allowed_prefixes=("src/core", "src/frontends/riscv", "src/prover",
                              "src/prover_api", "src/backend", "src/interop",
                              "design/typed-air/artifacts"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        self.assertIn("src/frontends/riscv/runner/segment_session.zig", sources)
        self.assertNotIn("src/frontends/riscv/runner/execute.zig", sources)
        self.assertNotIn("execute_mod", (root / "src/frontends/riscv/runner/mod.zig").read_text())
        self.assertIn(manifest.entry_roots[0], sources)
        for source in sources:
            self.assertNotIn("src/integrations/", source)
            self.assertNotIn("src/backends/", source)

    def test_compact_tuple_preparation_excludes_integrations_and_concrete_backends(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="recursion-compact-tuple-preparation",
            entry_roots=("src/frontends/riscv/recursion/compact_tuple_ledger_v1.zig",),
            named_imports=(
                NamedImport("stwo_core", "src/core/mod.zig"),
                NamedImport("stwo_prover_engine", "src/prover/mod.zig"),
                NamedImport("stwo_prover_api", "src/prover_api/mod.zig"),
                NamedImport("stwo_backend_contracts", "src/backend/mod.zig"),
            ),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=(
                "src/core", "src/frontends/riscv", "src/prover",
                "src/prover_api", "src/backend",
            ),
        )
        graph = inspect_sources(root, manifest)
        self.assertIn(manifest.entry_roots[0], graph.relative_sources())

    def test_manifest_tree_registration_has_only_protocol_and_core_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="recursion-verifier-tree",
            entry_roots=("src/frontends/riscv/recursion/verifier_tree.zig",),
            named_imports=(NamedImport("stwo_core", "src/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({
                "src/frontends/riscv/recursion/verifier_tree.zig",
                "src/frontends/riscv/recursion/poseidon2_channel.zig",
                "src/frontends/riscv/recursion/poseidon2_canonical_word_sponge.zig",
                "src/frontends/riscv/air/memory_commitment/poseidon2.zig",
                "src/frontends/riscv/air/memory_commitment/poseidon2_constants.zig",
            }),
            allowed_prefixes=("src/core",),
        )
        # Follow real relative and named imports. A witness, backend, prover or
        # integration dependency must fail the closure, even when Zig would
        # otherwise leave the declaration uninstantiated in a verifier build.
        graph = inspect_sources(root, manifest)
        self.assertIn(manifest.entry_roots[0], graph.relative_sources())


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
