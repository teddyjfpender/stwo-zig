from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock
from scripts.repo.product_closure.graph import ClosureError, inspect_sources
from scripts.repo.product_closure.model import Manifest, NamedImport


class RecursionOwnershipTest(unittest.TestCase):
    def native_profile_authority(self, root: Path) -> str:
        base = root / "src/frontends/riscv/recursion"
        facade = (base / "vm_air_profile_v2.zig").read_text()
        self.assertIn('const shared = @import("vm_air_profile_v2_authority.zig");', facade)
        self.assertIn("const Native = shared.ForOwner(NativeOwner);", facade)
        self.assertNotIn("fn deriveFromSource(", facade)
        for name in ("ProfileV2", "derive", "deriveAuthority"):
            self.assertIn(f"pub const {name} = Native.{name};", facade)
        return (base / "vm_air_profile_v2_authority.zig").read_text()

    def test_wide_poseidon_typed_plan_is_independent_and_verifier_safe(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="typed-wide-poseidon-definition",
            entry_roots=("src/frontends/riscv/air/lang/typed_poseidon2_wide.zig",),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({"src/frontends/riscv/access_clock.zig"}),
            allowed_prefixes=("src/waist/core", "src/frontends/riscv/air"),
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
        profile = self.native_profile_authority(root)
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
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/waist/core", "src/frontends/riscv"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for path in (
            "air/program/interaction.zig", "air/memory_commitment/interaction.zig",
            "air/clock_update_component.zig", "air/lookups/tables/equations.zig",
            "air/native_boundary_typed_admission.zig",
        ):
            self.assertNotIn("src/frontends/riscv/" + path, sources)
        profile = self.native_profile_authority(root)
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
        profile = self.native_profile_authority(root)
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
                "segment_verified_publication", "segment_verified_artifact",
                "canonical_proof_identity", "engine_protocol", "segment_outer_wire_geometry",
            )),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/waist/core", "src/frontends/riscv"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertNotIn("/prover/", source)
            self.assertNotIn("/integrations/", source)
            self.assertNotIn("/backends/", source)
            self.assertNotIn("witness", Path(source).name)
        self.assertNotIn("src/frontends/riscv/recursion/engine.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/segment_outer_cohort.zig", sources)

    def test_detached_leaf_command_excludes_legacy_harness_entrypoints(self) -> None:
        root = Path(__file__).resolve().parents[2]
        for name in (
            "detached_leaf_runner", "detached_leaf_producer", "native_ingress",
            "detached_leaf_options", "workload", "memory_workload", "leaf_key_setup_runner",
        ):
            source = (root / f"src/integrations/riscv_cpu/recursive_segment_{name}.zig").read_text()
            self.assertNotIn('recursive_segment_v2_leaf_outer_proof_test.zig', source)
            self.assertNotIn('recursive_segment_v2_concrete_outer_proof_test.zig', source)
            self.assertNotIn('recursive_segment_v2_outer_engine.zig', source)
            self.assertNotIn('stwo_riscv_cpu_integration', source)
        command = (root / "src/integrations/riscv_cpu/recursive_segment_detached_leaf_runner.zig").read_text()
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
        build = (integration / "build.zig").read_text()
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
                cpu + "recursive_segment_detached_leaf_runner.zig",
                cpu + "recursive_segment_detached_parent_producer_runner.zig",
                cpu + "recursive_segment_leaf_key_setup_runner.zig",
                metal + "recursive_segment_detached_leaf_runner.zig",
                metal + "recursive_segment_detached_parent_producer_runner.zig",
            ),
            named_imports=(
                NamedImport("stwo_riscv_detached_parent_producer", cpu + "recursive_segment_detached_parent_producer.zig"),
                NamedImport("stwo_riscv_detached_leaf_runner", cpu + "recursive_segment_detached_leaf_runner.zig"),
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
        source = "src/engine/prover/tracked_smp_allocator.zig"
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
            "src/frontends/riscv/recursion/segment_outer_transaction.zig",
            "src/integrations/riscv_cpu/recursive_segment_detached_leaf_producer.zig",
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
        "source", "types", "validate", "validate_support", "window_ir",
    )

    def test_typed_verifier_component_excludes_prover_and_witness_sources(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="typed-verifier-component",
            entry_roots=(
                "src/frontends/riscv/recursion/air/universal_typed_verifier_component.zig",
                "src/frontends/riscv/recursion/detached_parent_definitions.zig",
                "src/frontends/riscv/recursion/air/query_bits_profile.zig",
                "src/frontends/riscv/recursion/detached_segment_admission.zig",
                "src/frontends/riscv/recursion/segment_leaf_statement_contract.zig",
                "src/frontends/riscv/air/statement_geometry.zig",
                "src/frontends/riscv/air/memory_commitment/poseidon2_call.zig",
                "src/frontends/riscv/air/statement_authority_preimage.zig",
                "src/frontends/riscv/recursion/detached_segment_public_inputs.zig",
                "src/frontends/riscv/recursion/detached_segment_authority_boundary.zig",
                "src/frontends/riscv/recursion/detached_segment_protocol.zig",
                "src/frontends/riscv/recursion/air/verifier_wire_claims.zig",
                "src/frontends/riscv/recursion/detached_segment_verifier_components.zig",
                "src/frontends/riscv/recursion/segment_leaf_parameters.zig",
                "src/frontends/riscv/recursion/air/segment_leaf_catalog.zig",
                "src/frontends/riscv/recursion/air/verifier_component_parameters.zig",
                "src/frontends/riscv/recursion/air/universal_manifest.zig",
                "src/frontends/riscv/recursion/segment_statement_outer_geometry.zig",
                "src/frontends/riscv/recursion/segment_leaf_outer_geometry.zig",
                "src/frontends/riscv/recursion/segment_publication_input_provider_contract.zig",
                "src/frontends/riscv/recursion/air/segment_outer_typed_catalog.zig",
                "src/frontends/riscv/recursion/air/segment_outer_manifest_contract.zig",
                "src/frontends/riscv/recursion/detached_parent_verifier_components.zig",
            ),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=("src/waist/core", "src/frontends/riscv"),
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
            entry_roots=("src/integrations/riscv_cpu/recursive_segment_detached_parent_verifier_runner.zig",),
            named_imports=(
                NamedImport("stwo_core", "src/waist/core/mod.zig"),
                NamedImport("stwo_parent_verifier", "src/frontends/riscv/parent_verifier.zig"),
                NamedImport("interop_postcard", "src/waist/recursion_wire/postcard/mod.zig"),
                NamedImport("stwo_proof_wire", "src/waist/proof_wire/mod.zig"),
            ),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({"src/integrations/riscv_cpu/recursive_segment_detached_parent_verifier_runner.zig"}),
            allowed_prefixes=("src/waist/core", "src/frontends/riscv", "src/waist/recursion_wire", "src/waist/proof_wire"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertNotIn("/runner/", source)
            self.assertNotIn("/prover/", source)
            self.assertNotIn("witness", Path(source).name)
        self.assertNotIn("src/frontends/riscv/recursion/recording_poseidon_channel.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/engine.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/air/qm31_mul_full.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/air/universal_catalog.zig", sources)
        self.assertIn("src/frontends/riscv/air/lang/typed_poseidon2_compact.zig", sources)
        self.assertIn("src/frontends/riscv/air/lang/typed_poseidon2.zig", sources)

    def test_leaf_verification_excludes_prover_runner_and_witness_sources(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="detached-leaf-verification",
            entry_roots=("src/integrations/riscv_cpu/recursive_segment_detached_verifier_runner.zig",),
            named_imports=(
                NamedImport("stwo_core", "src/waist/core/mod.zig"),
                NamedImport("stwo_leaf_verifier", "src/frontends/riscv/leaf_verifier.zig"),
                NamedImport("interop_postcard", "src/waist/recursion_wire/postcard/mod.zig"),
                NamedImport("stwo_proof_wire", "src/waist/proof_wire/mod.zig"),
            ),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({"src/integrations/riscv_cpu/recursive_segment_detached_verifier_runner.zig"}),
            allowed_prefixes=("src/waist/core", "src/frontends/riscv", "src/waist/recursion_wire", "src/waist/proof_wire"),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        for source in sources:
            self.assertNotIn("/runner/", source)
            self.assertNotIn("/prover/", source)
            self.assertNotIn("witness", Path(source).name)
        self.assertNotIn("src/frontends/riscv/recursion/recording_poseidon_channel.zig", sources)
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
            "air/memory_commitment/poseidon2_universal_equations.zig",
            "air/memory_commitment/poseidon2_universal_layout.zig",
            "air/memory_commitment/poseidon2_degree3_schedule.zig",
            "air/memory_commitment/poseidon2_constants.zig",
            "air/memory_commitment/poseidon2_matrix.zig",
        )
        manifest = Manifest(
            product="native-verifier-components",
            entry_roots=tuple("src/frontends/riscv/" + name for name in (
                "air/lookups/tables/verifier.zig",
                "air/memory_commitment/poseidon2_degree3_verifier.zig",
                "air/memory_commitment/poseidon2_universal_equations.zig",
            "air/memory_commitment/poseidon2_universal_layout.zig",
                "air/memory_commitment/poseidon2_wide_equations.zig",
            )),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset("src/frontends/riscv/" + name for name in files),
            allowed_prefixes=("src/waist/core",),
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
            "air/memory_commitment/poseidon2_universal_equations.zig",
            "air/memory_commitment/poseidon2_universal_layout.zig",
            "air/memory_commitment/poseidon2_universal_identity.zig",
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
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=(
                frozenset("src/frontends/riscv/" + name for name in files) |
                frozenset(f"src/frontends/riscv/air/lang/{name}.zig" for name in self.DEFINITION_FILES)
            ),
            allowed_prefixes=("src/waist/core",),
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
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=(
                frozenset("src/frontends/riscv/" + name for name in files) |
                frozenset(f"src/frontends/riscv/air/lang/{name}.zig" for name in self.DEFINITION_FILES)
            ),
            allowed_prefixes=("src/waist/core",),
        )
        inspect_sources(root, manifest)

    def test_vm_profile_identity_has_no_derivation_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = "src/frontends/riscv/recursion/vm_air_profile_identity.zig"
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
            "air/memory_commitment/poseidon2_universal_equations.zig",
            "air/memory_commitment/poseidon2_universal_layout.zig",
            "air/memory_commitment/poseidon2_universal_identity.zig",
        )
        manifest = Manifest(
            product="canonical-poseidon-identity",
            entry_roots=("src/frontends/riscv/air/memory_commitment/poseidon2_universal_identity.zig",),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=(
                frozenset("src/frontends/riscv/" + name for name in files) |
                frozenset(f"src/frontends/riscv/air/lang/{name}.zig" for name in self.DEFINITION_FILES)
            ),
            allowed_prefixes=("src/waist/core",),
        )
        inspect_sources(root, manifest)

    def test_public_claim_has_only_statement_and_core_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="vm-public-claim",
            entry_roots=("src/frontends/riscv/recursion/vm_public_claim.zig",),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
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
                    "recursion/blake3_identity_digest.zig",
                )
            ),
            allowed_prefixes=("src/waist/core",),
        )
        inspect_sources(root, manifest)

    def test_public_claim_digest_rejects_a_backend_dependency(self) -> None:
        owner = Path(__file__).resolve().parents[2] / "src/frontends/riscv/recursion/blake3_identity_digest.zig"
        read_text = Path.read_text

        def mutated_text(path: Path, *args: object, **kwargs: object) -> str:
            text = read_text(path, *args, **kwargs)
            return text + f'\nconst forbidden = @import("{forbidden}");\n' if path == owner else text

        for forbidden in ("stwo_cpu_backend", "stwo_prover_engine"):
            with self.subTest(imported=forbidden), mock.patch.object(Path, "read_text", mutated_text):
                with self.assertRaisesRegex(ClosureError, f"blake3_identity_digest.zig: undeclared named import {forbidden!r}"):
                    self.test_public_claim_has_only_statement_and_core_dependencies()

    def test_air_definition_and_fixed_wire_import_only_core_and_reviewed_ir(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="air-definition",
            entry_roots=(
                "src/frontends/riscv/air/lang/definition.zig",
                "src/frontends/riscv/recursion/air/fixed_wire.zig",
            ),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({
                "src/frontends/riscv/recursion/air/fixed_wire.zig",
                "src/frontends/riscv/recursion/air/relation_effect.zig",
                "src/frontends/riscv/recursion/air/verifier_wire_protocol.zig",
            }) | frozenset(
                f"src/frontends/riscv/air/lang/{name}.zig" for name in self.DEFINITION_FILES
            ),
            allowed_prefixes=("src/waist/core",),
        )
        inspect_sources(root, manifest)

    def test_parent_protocol_has_no_prover_or_witness_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="detached-parent-protocol",
            entry_roots=("src/frontends/riscv/recursion/detached_parent_protocol.zig",),
            named_imports=(
                NamedImport("stwo_core", "src/waist/core/mod.zig"),
            ),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=(
                "src/waist/core", "src/frontends/riscv",
            ),
        )
        sources = inspect_sources(root, manifest).relative_sources()
        self.assertNotIn("src/frontends/riscv/recursion/detached_parent_prepared.zig", sources)
        self.assertNotIn("src/frontends/riscv/recursion/compact_tuple_ledger.zig", sources)
        for forbidden in (
            "detached_parent_components.zig", "air/universal_shared_provider.zig",
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
            entry_roots=("src/frontends/riscv/recursion/detached_pcs_preparation.zig",
                         "src/frontends/riscv/recursion/pcs_transcript_program.zig",
                         "src/frontends/riscv/recursion/transcript_frame_rows.zig",
                         "src/frontends/riscv/recursion/detached_prefix_preparation.zig",
                         "src/frontends/riscv/recursion/detached_pcs_rows.zig",
                         "src/frontends/riscv/recursion/detached_child_views.zig",
                         "src/frontends/riscv/recursion/detached_parent_preparation.zig",
                         "src/frontends/riscv/recursion/air/prepared_interaction_generation.zig",
                         "src/frontends/riscv/recursion/detached_native_leaf_preparation.zig",
                         "src/frontends/riscv/recursion/detached_leaf_noncore_owner.zig",
                         "src/frontends/riscv/recursion/detached_fri_core.zig",
                         "src/frontends/riscv/recursion/detached_leaf_cohort.zig",
                         "src/frontends/riscv/recursion/transaction_storage.zig",
                         "src/frontends/riscv/recursion/leaf_interaction_generator.zig",
                         "src/frontends/riscv/recursion/segment_outer_transaction.zig",
                         "src/frontends/riscv/recursion/binary_verified_publication.zig"),
            named_imports=tuple(NamedImport(name, path) for name, path in (
                ("stwo_core", "src/waist/core/mod.zig"),
                ("stwo_prover_engine", "src/engine/prover/mod.zig"),
                ("stwo_prover_api", "src/waist/prover_api/mod.zig"),
                ("stwo_backend_contracts", "src/waist/backend/mod.zig"),
                ("interop_postcard", "src/waist/recursion_wire/postcard/mod.zig"),
                ("stwo_proof_wire", "src/waist/proof_wire/mod.zig"),
                ("typed_air_artifacts", "src/frontends/riscv/air/lang/artifacts/embedded.zig"),
                ("typed_air_h009_artifacts", "src/frontends/riscv/air/lang/artifacts/h009_embedded.zig"),
                ("typed_air_h010_artifacts", "src/frontends/riscv/air/lang/artifacts/h010_embedded.zig"),
            )),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({
                "src/waist/proof_wire/family.zig",
                "src/waist/proof_wire/bounded_count_test.zig",
                "src/waist/proof_wire/hash_family_test.zig",
                "src/waist/proof_wire/wide_test.zig",
            }),
            # Preparation owns witnesses and may use generic proving contracts.
            # Concrete backend and integration directories are deliberately absent.
            allowed_prefixes=("src/waist/core", "src/frontends/riscv", "src/engine/prover",
                              "src/waist/prover_api", "src/waist/backend", "src/waist/recursion_wire",
                              "src/frontends/riscv/air/lang/artifacts"),
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
            entry_roots=("src/frontends/riscv/recursion/compact_tuple_ledger.zig",),
            named_imports=(
                NamedImport("stwo_core", "src/waist/core/mod.zig"),
                NamedImport("stwo_prover_engine", "src/engine/prover/mod.zig"),
                NamedImport("stwo_prover_api", "src/waist/prover_api/mod.zig"),
                NamedImport("stwo_backend_contracts", "src/waist/backend/mod.zig"),
            ),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset(),
            allowed_prefixes=(
                "src/waist/core", "src/frontends/riscv", "src/engine/prover",
                "src/waist/prover_api", "src/waist/backend",
            ),
        )
        graph = inspect_sources(root, manifest)
        self.assertIn(manifest.entry_roots[0], graph.relative_sources())

    def test_manifest_tree_registration_has_only_protocol_and_core_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[2]
        manifest = Manifest(
            product="recursion-verifier-tree",
            entry_roots=("src/frontends/riscv/recursion/verifier_tree.zig",),
            named_imports=(NamedImport("stwo_core", "src/waist/core/mod.zig"),),
            generated_imports=frozenset({"std", "builtin"}),
            allowed_files=frozenset({
                "src/frontends/riscv/recursion/verifier_tree.zig",
                "src/frontends/riscv/recursion/poseidon2_channel.zig",
                "src/frontends/riscv/recursion/poseidon2_canonical_word_sponge.zig",
                "src/frontends/riscv/air/memory_commitment/poseidon2.zig",
                "src/frontends/riscv/air/memory_commitment/poseidon2_constants.zig",
            }),
            allowed_prefixes=("src/waist/core",),
        )
        # Follow real relative and named imports. A witness, backend, prover or
        # integration dependency must fail the closure, even when Zig would
        # otherwise leave the declaration uninstantiated in a verifier build.
        graph = inspect_sources(root, manifest)
        self.assertIn(manifest.entry_roots[0], graph.relative_sources())
