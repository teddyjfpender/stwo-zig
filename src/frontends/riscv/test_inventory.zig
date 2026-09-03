//! Every test-bearing file in this package, named once so the test binary
//! contains all of them.
//!
//! ## Why this file exists
//!
//! Zig collects a `test` declaration only from a file the compiler was made to
//! analyse. A `pub const x = @import("x.zig")` at the top of a `mod.zig` does
//! not do that, and neither does `std.testing.refAllDecls` or
//! `refAllDeclsRecursive` -- both reference decls from *inside* a test body,
//! which is after the runner's test list is fixed. The only thing that works is
//! a literal `_ = @import("...")` in a `test` block reachable from the module
//! root, which is why `air/mod.zig` already carries two of them with that
//! comment attached.
//!
//! Relying on that per directory left 142 named tests in this package compiled
//! by nothing at all -- not by this package's own `test` step, and not by any
//! product gate. Measured before this file existed: 458 named `test` blocks in
//! the tree, 316 of them in the binary. Among the missing were every pin in
//! `air/diagnostic_hints.zig` (now `air/diagnostic_hints_test.zig`),
//! `air/interaction.zig` and `prover/statement_validation.zig`.
//!
//! ## The rule
//!
//! A new test-bearing file in this package must be named below. A file already
//! reachable some other way may be listed anyway -- a duplicate import is free,
//! and a complete list is what makes "is my test compiled?" answerable by
//! reading one file.
//!
//! `test_inventory_test.zig` walks this directory tree and fails if a file
//! holding a `test` block is missing from the list, so the list cannot silently
//! fall behind the tree. The test-count floors in
//! `src/frontends/riscv/build.zig` and `build_support/products/riscv_cpu.zig`
//! fail if a rewiring drops the tests back out of a binary.
//!
//! Deliberately excluded: `refinement_ir_export_test.zig`, whose single test
//! demands `RISCV_AIR_IR_DIR` and is driven by the `riscv-refinement-ir` step
//! with that variable set; and `mod.zig`, the module root, whose tests are
//! always collected.

test {
    // Package root.
    _ = @import("access_clock.zig");
    _ = @import("air_semantics_test_root.zig");
    _ = @import("execution_profile_identity_test.zig");
    _ = @import("ethereum_runner_test_root.zig");
    _ = @import("guest_precompile_test_root.zig");
    _ = @import("infra_trace.zig");
    _ = @import("isa_test_root.zig");
    _ = @import("lookup_batch_test_root.zig");
    _ = @import("opcode_coverage_test.zig");
    _ = @import("opcode_manifest.zig");
    _ = @import("outer_parent_statement_source_test_root.zig");
    _ = @import("outer_parent_range_authority_test_root.zig");
    _ = @import("outer_parent_statement_air_source_test_root.zig");
    _ = @import("outer_parent_transcript_source_test_root.zig");
    _ = @import("owned_statement.zig");
    _ = @import("proof_transcript.zig");
    _ = @import("prover/memory_provider_shards/authority_test.zig");
    _ = @import("recursion_air_test_root.zig");
    _ = @import("recursion_outer_sources_test_root.zig");
    _ = @import("row_window_test_root.zig");
    _ = @import("runner_test_root.zig");
    _ = @import("segment_public_outer_source_test_root.zig");
    _ = @import("segment_leaf_outer_bundle_test_root.zig");
    _ = @import("segment_outer_noncore_audits_v2_test_root.zig");
    _ = @import("segment_statement_outer_source_test_root.zig");
    _ = @import("segment_transcript_outer_source_test_root.zig");
    _ = @import("temporal_pair_node_test_root.zig");
    _ = @import("testing.zig");
    _ = @import("witness_layout.zig");

    // Isolated native/non-recursive aggregation reference.
    _ = @import("aggregation/manifest_test.zig");
    _ = @import("aggregation/reference_test.zig");
    _ = @import("aggregation/summary_test.zig");

    // Shadow recursion boundary; native codec only until the recursive
    // verifier admits independently verified child-proof authority.
    _ = @import("recursion/relation_summary_test.zig");
    _ = @import("recursion/arithmetic_circuit_test.zig");
    _ = @import("recursion/binary_pair_authority_test.zig");
    _ = @import("recursion/poseidon2_channel.zig");
    _ = @import("recursion/protocol.zig");
    _ = @import("recursion/fixed_profile.zig");
    _ = @import("recursion/fri_profile_frontier_test.zig");
    _ = @import("recursion/leaf_profile.zig");
    _ = @import("recursion/outer_parent_child_admission_test.zig");
    _ = @import("recursion/outer_parent_range_authority_test.zig");
    _ = @import("recursion/outer_parent_statement_air_source_test.zig");
    _ = @import("recursion/outer_parent_statement_source_test.zig");
    _ = @import("recursion/outer_parent_transcript_source_test.zig");
    _ = @import("recursion/transcript_program_test.zig");
    _ = @import("recursion/scheduled_channel.zig");
    _ = @import("recursion/segment_transcript_witness_test.zig");
    _ = @import("recursion/segment_leaf_authority_test.zig");
    _ = @import("recursion/segment_leaf_outer_bundle_test.zig");
    _ = @import("recursion/segment_profile.zig");
    _ = @import("recursion/segment_public_outer_source_test.zig");
    _ = @import("recursion/segment_range_authority_test.zig");
    _ = @import("recursion/segment_statement_outer_source_test.zig");
    _ = @import("recursion/span_statement_test.zig");
    _ = @import("recursion/statement_semantics_circuit_test.zig");
    _ = @import("recursion/temporal_pair_node_test.zig");
    _ = @import("recursion/transcript_shape.zig");
    _ = @import("recursion/vm_public_claim_test.zig");
    _ = @import("recursion/vm_public_semantics_circuit_test.zig");
    _ = @import("recursion/engine.zig");
    _ = @import("recursion/pair_node_test.zig");
    _ = @import("recursion/vm_air_profile_test.zig");
    _ = @import("recursion/air/composition_circuit_test.zig");
    _ = @import("recursion/air/universal_shared_provider_composition.zig");
    _ = @import("recursion/air/control_component.zig");
    _ = @import("recursion/air/control_slice_test.zig");
    _ = @import("recursion/air/control_slice_heterogeneous_v2_test.zig");
    _ = @import("recursion/air/control_test.zig");
    _ = @import("recursion/air/control_witness.zig");
    _ = @import("recursion/air/direct_constraint_program.zig");
    _ = @import("recursion/air/framework_interaction.zig");
    _ = @import("recursion/air/fri_merkle_anchor_test.zig");
    _ = @import("recursion/air/fri_merkle_leaf_test.zig");
    _ = @import("recursion/air/fri_merkle_node_test.zig");
    _ = @import("recursion/air/fri_verifier_circuit_test.zig");
    _ = @import("recursion/air/fri_verifier_control_test.zig");
    _ = @import("recursion/air/inventory_test.zig");
    _ = @import("recursion/air/linear_ops_adversarial_test.zig");
    _ = @import("recursion/air/linear_ops_test.zig");
    _ = @import("recursion/air/qm31_inv_adversarial_test.zig");
    _ = @import("recursion/air/qm31_inv_test.zig");
    _ = @import("recursion/air/qm31_mul_adversarial_test.zig");
    _ = @import("recursion/air/qm31_mul_full_adversarial_test.zig");
    _ = @import("recursion/air/qm31_mul_full_test.zig");
    _ = @import("recursion/air/qm31_mul_test.zig");
    _ = @import("recursion/air/fri_verifier_input_test.zig");
    _ = @import("recursion/air/fri_verifier_lowering_test.zig");
    _ = @import("recursion/air/merkle_path_test.zig");
    _ = @import("recursion/air/merkle_path_poseidon_bridge_test.zig");
    _ = @import("recursion/air/merkle_root_test.zig");
    _ = @import("recursion/air/pcs_deep_circuit_test.zig");
    _ = @import("recursion/air/pcs_deep_input_test.zig");
    _ = @import("recursion/air/pow_check_test.zig");
    _ = @import("recursion/air/pow_frame_test.zig");
    _ = @import("recursion/air/range_check_8_8_bridge_test.zig");
    _ = @import("recursion/air/relation_challenge_test.zig");
    _ = @import("recursion/air/query_bits_test.zig");
    _ = @import("recursion/air/query_mapping_test.zig");
    _ = @import("recursion/air/relation_effect.zig");
    _ = @import("recursion/air/statement_input_test.zig");
    _ = @import("recursion/air/statement_semantics_input_test.zig");
    _ = @import("recursion/air/trace_merkle_test.zig");
    _ = @import("recursion/air/transcript_air_test.zig");
    _ = @import("recursion/air/transcript_binding_test.zig");
    _ = @import("recursion/air/transcript_payload_test.zig");
    _ = @import("recursion/air/transcript_state_test.zig");
    _ = @import("recursion/air/transcript_word_test.zig");
    _ = @import("recursion/air/universal_challenges.zig");
    _ = @import("recursion/air/universal_manifest_test.zig");
    _ = @import("recursion/air/universal_roster.zig");
    _ = @import("recursion/air/universal_roster_inventory_test.zig");
    _ = @import("recursion/air/universal_shared_provider_test.zig");
    _ = @import("recursion/air/universal_typed_component_test.zig");
    _ = @import("recursion/air/verifier_arithmetic_lowering_test.zig");
    _ = @import("recursion/air/verifier_randomness_test.zig");
    _ = @import("recursion/air/verifier_schedule.zig");
    _ = @import("recursion/air/vm_air_composition_input_test.zig");
    _ = @import("recursion/air/vm_public_claim_hash_test.zig");
    _ = @import("recursion/air/vm_public_claim_input_test.zig");
    _ = @import("recursion/air/vm_public_claim_semantics_input_test.zig");
    _ = @import("recursion/air/vm_public_io_hash_test.zig");
    _ = @import("recursion/air/vm_public_logup_input_test.zig");
    _ = @import("recursion/vm_air_profile_test.zig");
    _ = @import("recursion/vm_leaf_context_test.zig");

    // Typed Poseidon2 authority carries protocol-seal tests beside its source.
    _ = @import("air/lang/typed_poseidon2_authority.zig");

    // Host interface.
    _ = @import("host/hint_oracle.zig");
    _ = @import("host/mod.zig");
    _ = @import("host/runtime.zig");

    // Instruction decode and profile authority.
    _ = @import("isa/authority.zig");
    _ = @import("isa/custom0.zig");
    _ = @import("isa/decode.zig");
    _ = @import("isa/execution_profile.zig");
    _ = @import("isa/mod.zig");
    _ = @import("isa/profile.zig");

    // Sail-authoritative execution and trace capture.
    _ = @import("runner/access_witness.zig");
    _ = @import("runner/cpu.zig");
    _ = @import("runner/decode.zig");
    _ = @import("runner/decode_cache.zig");
    _ = @import("runner/elf_loader.zig");
    _ = @import("runner/execute.zig");
    _ = @import("runner/auipc_retirement_test.zig");
    _ = @import("runner/base_alu_imm_retirement_test.zig");
    _ = @import("runner/base_alu_reg_retirement_test.zig");
    _ = @import("runner/guest_precompile/c011_semantic_equivalence_test.zig");
    _ = @import("runner/guest_precompile/call_buffer.zig");
    _ = @import("runner/guest_precompile/mod.zig");
    _ = @import("runner/guest_precompile/poseidon2_v1.zig");
    _ = @import("runner/guest_precompile/runner_test.zig");
    _ = @import("runner/host_integration_test.zig");
    _ = @import("runner/fence_retirement_test.zig");
    _ = @import("runner/generated_retirement.zig");
    _ = @import("runner/jal_retirement.zig");
    _ = @import("runner/jal_retirement_test.zig");
    _ = @import("runner/jalr_retirement_test.zig");
    _ = @import("runner/branch_eq_retirement.zig");
    _ = @import("runner/branch_eq_retirement_test.zig");
    _ = @import("runner/branch_lt_retirement.zig");
    _ = @import("runner/branch_lt_retirement_test.zig");
    _ = @import("runner/lt_imm_retirement.zig");
    _ = @import("runner/lt_imm_retirement_test.zig");
    _ = @import("runner/lt_reg_retirement_test.zig");
    _ = @import("runner/lui_retirement_test.zig");
    _ = @import("runner/shifts_imm_retirement_test.zig");
    _ = @import("runner/shifts_imm_retirement.zig");
    _ = @import("runner/shifts_reg_retirement_test.zig");
    _ = @import("runner/load_store_retirement_test.zig");
    _ = @import("runner/mul_retirement_test.zig");
    _ = @import("runner/mul_retirement.zig");
    _ = @import("runner/mulh_retirement_test.zig");
    _ = @import("runner/mulh_retirement.zig");
    _ = @import("runner/div_retirement_test.zig");
    _ = @import("runner/div_retirement.zig");
    _ = @import("runner/memory.zig");
    _ = @import("runner/memory_state.zig");
    _ = @import("runner/minimal_trace/mod.zig");
    _ = @import("runner/minimal_trace/test.zig");
    _ = @import("runner/mod.zig");
    _ = @import("runner/sail_oracle.zig");
    _ = @import("runner/state_chain.zig");
    _ = @import("runner/trace.zig");
    _ = @import("runner/trace_dump.zig");

    // Per-family witness derivation.
    _ = @import("runner/witness/load_store_legacy_test_oracle.zig");

    // AIR: claims, components, relations and diagnostics.
    _ = @import("air/claims.zig");
    _ = @import("air/clock_update_component_prepared_test.zig");
    _ = @import("air/clock_update_component_test.zig");
    _ = @import("air/component_prepared_test.zig");
    _ = @import("air/component_order.zig");
    _ = @import("air/composition_work_support.zig");
    _ = @import("air/diagnostic_hints_test.zig");
    _ = @import("air/guest_precompile/caller_component_prepared_test.zig");
    _ = @import("air/guest_precompile/caller_component_test.zig");
    _ = @import("air/guest_precompile/direct_constraints_test.zig");
    _ = @import("air/guest_precompile/identity_test.zig");
    _ = @import("air/guest_precompile/interaction_chunk_test.zig");
    _ = @import("air/guest_precompile/interaction_test.zig");
    _ = @import("air/guest_precompile/lookup_registration_test.zig");
    _ = @import("air/guest_precompile/main_trace_test.zig");
    _ = @import("air/guest_precompile/proof_admission_test.zig");
    _ = @import("air/guest_precompile/proof_transcript_test.zig");
    _ = @import("air/guest_precompile/proof_transcript_security_test.zig");
    _ = @import("air/guest_precompile/program_commitment_test.zig");
    _ = @import("air/guest_precompile/provider_component_test.zig");
    _ = @import("air/guest_precompile/relation_test.zig");
    _ = @import("air/interaction.zig");
    _ = @import("air/interaction_gen.zig");
    _ = @import("air/logup.zig");
    _ = @import("air/memory_logup.zig");
    _ = @import("air/mod.zig");
    _ = @import("air/opcode_memory.zig");
    _ = @import("air/public_data.zig");
    _ = @import("air/public_logup.zig");
    _ = @import("air/relation_challenges.zig");
    _ = @import("air/relation_evidence.zig");
    _ = @import("air/relation_export_components_test.zig");
    _ = @import("air/relation_export_test.zig");
    _ = @import("air/relations.zig");
    _ = @import("air/semantic_component_test.zig");
    _ = @import("air/semantic_eval.zig");
    _ = @import("air/trace_columns.zig");

    // AIR: isolated typed authoring kernel.
    _ = @import("air/lang/access_schedule_memory_test.zig");
    _ = @import("air/lang/access_transaction_test.zig");
    _ = @import("air/lang/access_schedule_test.zig");
    _ = @import("air/lang/authoring_test.zig");
    _ = @import("air/lang/compat_layout_test.zig");
    _ = @import("air/lang/compat_manifest_diff_test.zig");
    _ = @import("air/lang/compat_manifest_test.zig");
    _ = @import("air/lang/cost_aware_materializer_adversarial_test.zig");
    _ = @import("air/lang/cost_aware_materializer_test.zig");
    _ = @import("air/lang/degree3_materializer_test.zig");
    _ = @import("air/lang/degree_test.zig");
    _ = @import("air/lang/diagnostic_test.zig");
    _ = @import("air/lang/digest_test.zig");
    _ = @import("air/lang/direct_witness_executor_test.zig");
    _ = @import("air/lang/effects_test.zig");
    _ = @import("air/lang/finalization_test.zig");
    _ = @import("air/lang/function_frames_test.zig");
    _ = @import("air/lang/function_body_lowering_test.zig");
    _ = @import("air/lang/function_activation_logup_test.zig");
    _ = @import("air/lang/function_body_ownership_test.zig");
    _ = @import("air/lang/hint_recipe_test.zig");
    _ = @import("air/lang/range_refinement_test.zig");
    _ = @import("air/lang/row_window_test.zig");
    _ = @import("air/lang/hints_test.zig");
    _ = @import("air/lang/kernel_test.zig");
    _ = @import("air/lang/lower_air_ir_test.zig");
    _ = @import("air/lang/lower_constraint_test.zig");
    _ = @import("air/lang/lower_lookup_test.zig");
    _ = @import("air/lang/lower_runtime_test.zig");
    _ = @import("air/lang/lookup_batch_execution_test.zig");
    _ = @import("air/lang/lookup_batch_performance_test.zig");
    _ = @import("air/lang/lookup_batch_planner_test.zig");
    _ = @import("air/lang/manifest_test.zig");
    _ = @import("air/lang/materialization_cost_test.zig");
    _ = @import("air/lang/materialization_direct_program_test.zig");
    _ = @import("air/lang/materialization_cost_direct_test.zig");
    _ = @import("air/lang/materialization_cut_set_test.zig");
    _ = @import("air/lang/materialization_direct_benchmark_test.zig");
    _ = @import("air/lang/materialization_diagnostics_test.zig");
    _ = @import("air/lang/materialization_fixed_direct_test.zig");
    _ = @import("air/lang/materialization_fixed_cost_test.zig");
    _ = @import("air/lang/materialization_frontier_cost_model_test.zig");
    _ = @import("air/lang/materialization_frontier_manifest_test.zig");
    _ = @import("air/lang/materialization_frontier_projection_test.zig");
    _ = @import("air/lang/materialization_neighbourhood_test.zig");
    _ = @import("air/lang/poseidon_layout_benchmark_artifact.zig");
    _ = @import("air/lang/poseidon_layout_benchmark_artifact_test.zig");
    _ = @import("air/lang/poseidon_layout_benchmark_protocol.zig");
    _ = @import("air/lang/poseidon_layout_benchmark_protocol_test.zig");
    _ = @import("air/lang/poseidon_layout_benchmark_rss.zig");
    _ = @import("air/lang/mod.zig");
    _ = @import("air/lang/program_test.zig");
    _ = @import("air/lang/protocol_degree_test.zig");
    _ = @import("air/lang/protocol_report_test.zig");
    _ = @import("air/lang/relation_test.zig");
    _ = @import("air/lang/runtime_profile_test.zig");
    _ = @import("air/lang/shadow_import_test.zig");
    _ = @import("air/lang/shadow_program_test.zig");
    _ = @import("air/lang/static_collections_test.zig");
    _ = @import("air/lang/static_profile_registry_artifact_test.zig");
    _ = @import("air/lang/static_profile_test.zig");
    _ = @import("air/lang/static_profile_registry_test.zig");
    _ = @import("air/lang/typed_addi_adversarial_test.zig");
    _ = @import("air/lang/typed_addi_test.zig");
    _ = @import("air/lang/typed_addi_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_addi_witness_test.zig");
    _ = @import("air/lang/typed_base_alu_imm_witness_test.zig");
    _ = @import("air/lang/typed_base_alu_imm_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_base_alu_imm_witness_performance_test.zig");
    _ = @import("air/lang/typed_base_alu_imm_authority_test.zig");
    _ = @import("air/lang/typed_base_alu_reg_test.zig");
    _ = @import("air/lang/typed_base_alu_reg_authority_test.zig");
    _ = @import("air/lang/typed_base_alu_reg_witness_test.zig");
    _ = @import("air/lang/typed_base_alu_reg_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_base_alu_reg_witness_performance_test.zig");
    _ = @import("air/lang/typed_auipc_test.zig");
    _ = @import("air/lang/typed_auipc_authority_test.zig");
    _ = @import("air/lang/typed_auipc_witness_test.zig");
    _ = @import("air/lang/typed_auipc_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_branch_eq_test.zig");
    _ = @import("air/lang/typed_branch_eq_witness_test.zig");
    _ = @import("air/lang/typed_branch_eq_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_branch_eq_witness_performance_test.zig");
    _ = @import("air/lang/typed_branch_eq_authority_test.zig");
    _ = @import("air/lang/typed_branch_lt_test.zig");
    _ = @import("air/lang/typed_branch_lt_witness_test.zig");
    _ = @import("air/lang/typed_branch_lt_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_branch_lt_witness_performance_test.zig");
    _ = @import("air/lang/typed_branch_lt_authority_test.zig");
    _ = @import("air/lang/typed_div_adversarial_test.zig");
    _ = @import("air/lang/typed_div_authority_test.zig");
    _ = @import("air/lang/typed_div_test.zig");
    _ = @import("air/lang/typed_div_witness_test.zig");
    _ = @import("air/lang/typed_fence_test.zig");
    _ = @import("air/lang/typed_fence_authority_test.zig");
    _ = @import("air/lang/typed_fence_witness_test.zig");
    _ = @import("air/lang/typed_fence_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_jalr_adversarial_test.zig");
    _ = @import("air/lang/typed_jalr_test.zig");
    _ = @import("air/lang/typed_jalr_authority_test.zig");
    _ = @import("air/lang/typed_jalr_witness_test.zig");
    _ = @import("air/lang/typed_jal_test.zig");
    _ = @import("air/lang/typed_jal_authority_test.zig");
    _ = @import("air/lang/typed_jal_witness_test.zig");
    _ = @import("air/lang/typed_jal_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_load_store_adversarial_test.zig");
    _ = @import("air/lang/typed_load_store_authority_test.zig");
    _ = @import("air/lang/typed_load_store_test.zig");
    _ = @import("air/lang/typed_load_store_witness_test.zig");
    _ = @import("air/lang/typed_lt_imm_test.zig");
    _ = @import("air/lang/typed_lt_imm_witness_test.zig");
    _ = @import("air/lang/typed_lt_imm_authority_test.zig");
    _ = @import("air/lang/typed_lt_reg_test.zig");
    _ = @import("air/lang/typed_lt_reg_authority_test.zig");
    _ = @import("air/lang/typed_lt_reg_witness_test.zig");
    _ = @import("air/lang/typed_lt_reg_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_lt_reg_witness_performance_test.zig");
    _ = @import("air/lang/typed_mul_test.zig");
    _ = @import("air/lang/typed_mul_authority_test.zig");
    _ = @import("air/lang/typed_mul_adversarial_test.zig");
    _ = @import("air/lang/typed_mul_witness_test.zig");
    _ = @import("air/lang/typed_mulh_test.zig");
    _ = @import("air/lang/typed_mulh_authority_test.zig");
    _ = @import("air/lang/typed_mulh_witness_test.zig");
    _ = @import("air/lang/typed_mulh_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_mulh_witness_performance_test.zig");
    _ = @import("air/lang/typed_opcode_production_authority_test.zig");
    _ = @import("air/lang/typed_shifts_imm_test.zig");
    _ = @import("air/lang/typed_shifts_imm_authority_test.zig");
    _ = @import("air/lang/typed_shifts_imm_witness_test.zig");
    _ = @import("air/lang/typed_shifts_imm_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_shifts_imm_witness_performance_test.zig");
    _ = @import("air/lang/typed_shifts_reg_test.zig");
    _ = @import("air/lang/typed_shifts_reg_authority_test.zig");
    _ = @import("air/lang/typed_shifts_reg_witness_test.zig");
    _ = @import("air/lang/typed_shifts_reg_witness_adversarial_test.zig");
    _ = @import("air/lang/typed_shifts_reg_witness_performance_test.zig");
    _ = @import("air/lang/typed_poseidon2_test.zig");
    _ = @import("air/lang/typed_poseidon2_compat_schedule_test.zig");
    _ = @import("air/lang/typed_poseidon2_compat_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_candidate_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_component_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_backend_test.zig");
    _ = @import("air/lang/typed_poseidon2_degree_bounded_trace_test.zig");
    _ = @import("air/lang/typed_poseidon2_identity_test.zig");
    _ = @import("air/lang/typed_poseidon2_frontier_artifact_test.zig");
    _ = @import("air/lang/typed_poseidon2_layout_executor_test.zig");
    _ = @import("air/lang/typed_poseidon2_relations_test.zig");
    _ = @import("air/lang/typed_poseidon2_witness_test.zig");
    _ = @import("air/lang/typed_lui_adversarial_test.zig");
    _ = @import("air/lang/typed_lui_test.zig");
    _ = @import("air/lang/typed_lui_authority_test.zig");
    _ = @import("air/lang/typed_lui_witness_test.zig");
    _ = @import("air/lang/validate_test.zig");

    // AIR: relation wiring.
    _ = @import("air/lookups/entry.zig");
    _ = @import("air/lookups/mod.zig");
    _ = @import("air/lookups/opcode_component_prepared_parallel_test.zig");
    _ = @import("air/lookups/opcode_component_prepared_test.zig");
    _ = @import("air/lookups/opcode_entries.zig");
    _ = @import("air/lookups/opcode_interaction_test.zig");

    // AIR: preprocessed lookup tables.
    _ = @import("air/lookups/tables/component.zig");
    _ = @import("air/lookups/tables/component_prepared_test.zig");
    _ = @import("air/prepared_parallel.zig");
    _ = @import("air/lookups/tables/counter.zig");
    _ = @import("air/lookups/tables/interaction.zig");
    _ = @import("air/lookups/tables/mod.zig");
    _ = @import("air/lookups/tables/schema.zig");
    _ = @import("air/lookups/tables/source_ingest.zig");

    // AIR: memory commitment.
    _ = @import("air/memory_commitment/boundary.zig");
    _ = @import("air/memory_commitment/hash_component_prepared_test.zig");
    _ = @import("air/memory_commitment/hash_runtime_program.zig");
    _ = @import("air/memory_commitment/interaction.zig");
    _ = @import("air/memory_commitment/merkle_node.zig");
    _ = @import("air/memory_commitment/mod.zig");
    _ = @import("air/memory_commitment/poseidon2.zig");
    _ = @import("air/memory_commitment/poseidon2_air.zig");
    _ = @import("air/memory_commitment/sparse_merkle.zig");
    _ = @import("air/memory_commitment/trace.zig");

    // AIR: transcript protocol.
    _ = @import("air/transcript/claims.zig");
    _ = @import("air/transcript/mod.zig");
    _ = @import("air/transcript/protocol.zig");

    // AIR: preprocessed range and bitwise tables.
    _ = @import("air/preprocessed/bitwise.zig");
    _ = @import("air/preprocessed/mod.zig");
    _ = @import("air/preprocessed/range_check.zig");

    // AIR: per-family opcode semantics.
    _ = @import("air/semantics/auipc_legacy_test_oracle.zig");
    _ = @import("air/semantics/base_alu_imm.zig");
    _ = @import("air/semantics/base_alu_reg.zig");
    _ = @import("air/semantics/branch_eq_legacy_test_oracle.zig");
    _ = @import("air/semantics/branch_lt_legacy_test_oracle.zig");
    _ = @import("air/semantics/common.zig");
    _ = @import("air/semantics/control_common.zig");
    _ = @import("air/semantics/div_legacy_test_oracle.zig");
    _ = @import("air/semantics/fence_legacy_test_oracle.zig");
    _ = @import("air/semantics/jal_legacy_test_oracle.zig");
    _ = @import("air/semantics/jalr_legacy_test_oracle.zig");
    _ = @import("air/semantics/load_store_legacy_test_oracle.zig");
    _ = @import("air/semantics/lt_imm_legacy_test_oracle.zig");
    _ = @import("air/semantics/lt_reg_legacy_test_oracle.zig");
    _ = @import("air/semantics/lui_legacy_test_oracle.zig");
    _ = @import("air/semantics/mod.zig");
    _ = @import("air/semantics/mul_legacy_test_oracle.zig");
    _ = @import("air/semantics/mulh_legacy_test_oracle.zig");
    _ = @import("air/semantics/shift_common.zig");
    _ = @import("air/semantics/shifts_imm_legacy_test_oracle.zig");
    _ = @import("air/semantics/shifts_reg_legacy_test_oracle.zig");

    // AIR: committed column layout.
    _ = @import("air/trace_columns/m_extension.zig");

    // AIR: program commitment.
    _ = @import("air/program/commitment.zig");
    _ = @import("air/program/decode.zig");
    _ = @import("air/program/interaction.zig");
    _ = @import("air/program/mod.zig");
    _ = @import("air/program/opcode.zig");
    _ = @import("air/program/table.zig");

    // AIR: symbolic extraction for the uniqueness model.
    _ = @import("air/extract/mod.zig");
    _ = @import("air/extract/runtime_program.zig");
    _ = @import("air/extract/symbolic.zig");

    // Shared primitives.
    _ = @import("common/poseidon2.zig");

    // Diagnostic dumps.
    _ = @import("diagnostics/mod.zig");
    _ = @import("diagnostics/public_values.zig");
    _ = @import("diagnostics/segment_manifest.zig");

    // Proof orchestration.
    _ = @import("prover/lookup_sources.zig");
    _ = @import("prover/main_trace_lifecycle_test.zig");
    _ = @import("prover/main_trace_plan_execution_test.zig");
    _ = @import("prover/main_trace_plan_execution_production_arena_test.zig");
    _ = @import("prover/main_trace_plan_execution_production_test.zig");
    _ = @import("prover/main_witness_work.zig");
    _ = @import("prover/interaction_trace_plan_test.zig");
    _ = @import("prover/tree2_main_source.zig");
    _ = @import("prover/main_trace_plan_test.zig");
    _ = @import("prover/proof_finalize_test.zig");
    _ = @import("prover/statement_validation_ownership_test.zig");
    _ = @import("prover/guest_precompile/component_assembly_test.zig");
    _ = @import("prover/guest_precompile/split_component_assembly_test.zig");
    _ = @import("prover/guest_precompile/split_joint_pow_test.zig");
    _ = @import("prover/guest_precompile/split_leaf_prepare_test.zig");
    _ = @import("prover/guest_precompile/split_leaf_statement_test.zig");
    _ = @import("prover/guest_precompile/split_main_trace_test.zig");
    _ = @import("prover/guest_precompile/split_pcs_prepare_test.zig");
    _ = @import("prover/guest_precompile/proof_artifact_test.zig");
    _ = @import("prover/guest_precompile/proof_finalize_test.zig");
    _ = @import("prover/guest_precompile/trace_geometry_test.zig");
    _ = @import("prover/guest_precompile/types_test.zig");
    _ = @import("prover/opcode_trace.zig");
    _ = @import("prover/preprocessed.zig");
    _ = @import("prover/proof_phase_meter_test.zig");
    _ = @import("prover/proof_workspace.zig");
    _ = @import("prover/statement_validation.zig");
    _ = @import("prover/test_witness_hook.zig");
    _ = @import("prover/trace_arena.zig");
    _ = @import("prover/verifier_test.zig");

    // Split and focused sources that carry their own tests. Some are also
    // reached through a cohort root; naming them here keeps that ownership
    // explicit and lets the inventory checker detect future rewiring.
    _ = @import("air/lang/lookup_physical_manifest_v2_assembly_test.zig");
    _ = @import("air/lang/lookup_physical_manifest_v2_test.zig");
    _ = @import("air/lang/lookup_polynomial_program_v2_test.zig");
    _ = @import("air/lang/opcode_composition_manifest_extended_test.zig");
    _ = @import("air/lang/opcode_composition_manifest_test.zig");
    _ = @import("air/lang/row_window_expression_v2_test.zig");
    _ = @import("air/lookups/opcode_component_prepared_domain.zig");
    _ = @import("air/lookups/tables/source_ingest_test.zig");
    _ = @import("air/memory_commitment/poseidon2_air_test.zig");
    _ = @import("air/public_data_v2_test.zig");
    _ = @import("air/public_logup_v2_test.zig");
    _ = @import("binary_fri_outer_bundle_v2_test_root.zig");
    _ = @import("binary_fri_outer_source_test_root.zig");
    _ = @import("binary_global_closure_outer_source_test_root.zig");
    _ = @import("binary_inactive_outer_source_test_root.zig");
    _ = @import("binary_pair_nonfri_outer_bundle_test_root.zig");
    _ = @import("binary_pair_outer_fixture_test_root.zig");
    _ = @import("binary_transcript_outer_source_test_root.zig");
    _ = @import("framework_interaction_test_root.zig");
    _ = @import("fri_profile_frontier_measurement_test_root.zig");
    _ = @import("lookup_batch_edit_test_root.zig");
    _ = @import("lookup_polynomial_v2_edit_test_root.zig");
    _ = @import("opcode_composition_manifest_test_root.zig");
    _ = @import("opcode_composition_performance_test_root.zig");
    _ = @import("proof_phase_meter_test_root.zig");
    _ = @import("prover/guest_precompile/orchestration.zig");
    _ = @import("prover/guest_precompile/split_leaf_prepare_core_test.zig");
    _ = @import("prover/guest_precompile/split_leaf_prepare_golden_test.zig");
    _ = @import("prover/interaction_trace_execution_policy_test.zig");
    _ = @import("prover/interaction_trace_plan_core_test.zig");
    _ = @import("prover/interaction_trace_plan_performance_test.zig");
    _ = @import("prover/interaction_witness_work.zig");
    _ = @import("prover/poseidon_witness_work_test.zig");
    _ = @import("prover/test_witness_hook_test.zig");
    _ = @import("recursion/air/composition_graph_recorder_record_component.zig");
    _ = @import("recursion/air/composition_graph_recorder_support.zig");
    _ = @import("recursion/air/relation_interaction_fixture.zig");
    _ = @import("recursion/air/segment_boundary_components_v2_test.zig");
    _ = @import("recursion/air/segment_outer_adapter_manifest_v2_test.zig");
    _ = @import("recursion/air/segment_publication_input_provider_component_v2.zig");
    _ = @import("recursion/air/temporal_packed_relation_challenge_v2.zig");
    _ = @import("recursion/air/vm_public_logup_control_v2_test.zig");
    _ = @import("recursion/binary_fri_outer_bundle_v2_test.zig");
    _ = @import("recursion/binary_fri_outer_source_test_expect_arithmetic_plan_parity.zig");
    _ = @import("recursion/binary_fri_outer_source_test_fixture.zig");
    _ = @import("recursion/binary_fri_outer_source_test_suite_5.zig");
    _ = @import("recursion/binary_fri_outer_source_test_validate_composition_input_base_rows.zig");
    _ = @import("recursion/binary_global_closure_outer_source_test.zig");
    _ = @import("recursion/binary_inactive_outer_source_test.zig");
    _ = @import("recursion/binary_pair_nonfri_outer_bundle_test.zig");
    _ = @import("recursion/binary_transcript_outer_source_test.zig");
    _ = @import("recursion/canonical_empty_cohort_v3_test.zig");
    _ = @import("recursion/fixed_wire_fixed_stark_proof_wire.zig");
    _ = @import("recursion/fri_profile_frontier_measurement_test.zig");
    _ = @import("recursion/pair_node_test_continuation_1.zig");
    _ = @import("recursion/recursion_air_composition_circuit_test.zig");
    _ = @import("recursion/recursion_air_composition_circuit_v3_authority_validation.zig");
    _ = @import("recursion/recursion_air_composition_circuit_v3_test.zig");
    _ = @import("recursion/recursion_air_composition_circuit_v3_test_continuation_1.zig");
    _ = @import("recursion/segment_leaf_authority_v2_test.zig");
    _ = @import("recursion/segment_leaf_local_authority_v3_test.zig");
    _ = @import("recursion/segment_leaf_local_projection_v3_test.zig");
    _ = @import("recursion/segment_leaf_outer_authority_v2_test.zig");
    _ = @import("recursion/segment_outer_cohort_v2_test.zig");
    _ = @import("recursion/segment_outer_noncore_audits_v2_test_fixture.zig");
    _ = @import("recursion/segment_outer_noncore_audits_v2_test_suite_3.zig");
    _ = @import("recursion/segment_public_native_sum_authority_v2_test.zig");
    _ = @import("recursion/segment_public_outer_source_v2_test.zig");
    _ = @import("recursion/segment_publication_input_provider_authority_v2_test.zig");
    _ = @import("recursion/segment_publication_input_provider_plan_v2_test.zig");
    _ = @import("recursion/segment_statement_outer_source_test_continuation_1.zig");
    _ = @import("recursion/segment_statement_outer_source_v2_test.zig");
    _ = @import("recursion/segment_statement_outer_source_v2_test_root.zig");
    _ = @import("recursion/segment_statement_v2_runner_e2e_test.zig");
    _ = @import("recursion/segment_statement_v2_test.zig");
    _ = @import("recursion/segment_transcript_outer_components_v2_test.zig");
    _ = @import("recursion/segment_transcript_outer_source_v2_test.zig");
    _ = @import("recursion/transcript_program_v2_test.zig");
    _ = @import("recursion_air_composition_v3_test_root.zig");
    _ = @import("row_window_edit_test_root.zig");
    _ = @import("row_window_expression_v2_edit_test_root.zig");
    _ = @import("runner/guest_precompile/poseidon2_clock_authority_test.zig");
    _ = @import("runner/segment_continuation_test.zig");
    _ = @import("runner/trace_clock_authority_test.zig");
    _ = @import("segment_boundary_components_v2_test_root.zig");
    _ = @import("segment_leaf_outer_authority_v2_test_root.zig");
    _ = @import("segment_outer_adapter_manifest_v2_test_root.zig");
    _ = @import("segment_outer_cohort_v2_test_root.zig");
    _ = @import("segment_public_native_sum_authority_v2_test_root.zig");
    _ = @import("segment_public_outer_components_v2_test_root.zig");
    _ = @import("segment_public_outer_source_v2_test_root.zig");
    _ = @import("segment_publication_input_provider_authority_v2_test_root.zig");
    _ = @import("segment_statement_outer_source_v2_test_root.zig");
    _ = @import("segment_transcript_outer_source_v2_test_root.zig");
    _ = @import("transcript_v2_test_root.zig");
    _ = @import("vm_public_claim_hash_authority_v2_test_root.zig");
    _ = @import("vm_public_logup_control_v2_test_root.zig");
    _ = @import("air/constraint_program.zig");
    _ = @import("air/extract/program.zig");
    _ = @import("air/extract/program_json.zig");
    _ = @import("sail_oracle_test_root.zig");
}
