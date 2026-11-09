# `stwo_riscv_rv32`

| Fact | Value |
| --- | --- |
| Version | `0.1.0` |
| Layer | `frontend` |
| Owner | `riscv-frontend` |
| Focused CI host | Linux |

## Purpose and architecture

Canonical rv32 source ownership under RFC #344; public module aliases point to one implementation each.

```mermaid
graph LR
  Consumer --> rv32
  rv32 --> DeclaredProviders
```

## Public API

`@import("stwo_riscv_rv32")` exposes these consumed canonical source interfaces:

- `aggregation_manifest`
- `aggregation_test_fixture`
- `air_claims`
- `air_clock_update_component`
- `air_clock_update_interaction`
- `air_component`
- `air_component_order`
- `air_constraint_program`
- `air_diagnostic_hints`
- `air_extract_mod`
- `air_extract_model`
- `air_extract_program`
- `air_extract_program_json`
- `air_extract_runtime_program`
- `air_guest_precompile_artifact_identity`
- `air_guest_precompile_caller_component`
- `air_guest_precompile_component_registry`
- `air_guest_precompile_direct_constraints`
- `air_guest_precompile_interaction`
- `air_guest_precompile_interaction_plan`
- `air_guest_precompile_keccakf_caller`
- `air_guest_precompile_keccakf_caller_local_zero`
- `air_guest_precompile_keccakf_component`
- `air_guest_precompile_keccakf_direct`
- `air_guest_precompile_keccakf_interaction`
- `air_guest_precompile_keccakf_interaction_plan`
- `air_guest_precompile_keccakf_row`
- `air_guest_precompile_keccakf_trace`
- `air_guest_precompile_lookup_registration`
- `air_guest_precompile_main_trace`
- `air_guest_precompile_manifest`
- `air_guest_precompile_program_commitment`
- `air_guest_precompile_proof_admission`
- `air_guest_precompile_proof_transcript`
- `air_guest_precompile_provider_component`
- `air_guest_precompile_secp256k1_component_bundle`
- `air_guest_precompile_secp256k1_component_config`
- `air_guest_precompile_secp256k1_recovery_caller`
- `air_guest_precompile_sha256_caller_local_zero`
- `air_guest_precompile_sha256_coefficient_bounds`
- `air_guest_precompile_sha256_component_profile`
- `air_guest_precompile_sha256_lookup_registration`
- `air_guest_precompile_sha256_memory_caller`
- `air_guest_precompile_sha256_memory_rows`
- `air_guest_precompile_sha256_preprocessed`
- `air_guest_precompile_statement`
- `air_guest_precompile_x0_caller_envelope`
- `air_incremental_public_logup_v4`
- `air_interaction`
- `air_interaction_legacy_test_oracle`
- `air_lang_access_transaction`
- `air_lang_compat_layout`
- `air_lang_compat_manifest`
- `air_lang_fixed_load_store`
- `air_lang_function_activation_logup`
- `air_lang_lookup_batch_execution`
- `air_lang_lookup_batch_planner`
- `air_lang_lookup_physical_manifest`
- `air_lang_lookup_polynomial_program`
- `air_lang_lower_air_ir`
- `air_lang_lower_constraint`
- `air_lang_lower_lookup`
- `air_lang_lower_runtime`
- `air_lang_opcode_composition_manifest`
- `air_lang_protocol_degree`
- `air_lang_protocol_report`
- `air_lang_row_window`
- `air_lang_runtime_profile`
- `air_lang_shadow_program`
- `air_lang_static_profile`
- `air_lang_static_profile_registry`
- `air_lang_static_profile_registry_artifact`
- `air_lang_typed_addi_witness`
- `air_lang_typed_auipc_authority`
- `air_lang_typed_auipc_witness`
- `air_lang_typed_base_alu_imm_authority`
- `air_lang_typed_base_alu_imm_witness`
- `air_lang_typed_base_alu_reg_authority`
- `air_lang_typed_base_alu_reg_witness`
- `air_lang_typed_branch_eq_authority`
- `air_lang_typed_branch_eq_witness`
- `air_lang_typed_branch_lt_authority`
- `air_lang_typed_branch_lt_witness`
- `air_lang_typed_div_authority`
- `air_lang_typed_div_corpus`
- `air_lang_typed_div_witness`
- `air_lang_typed_fence_authority`
- `air_lang_typed_fence_witness`
- `air_lang_typed_jal_authority`
- `air_lang_typed_jal_witness`
- `air_lang_typed_jalr_authority`
- `air_lang_typed_jalr_witness`
- `air_lang_typed_load_store_authority`
- `air_lang_typed_load_store_witness`
- `air_lang_typed_lt_imm_authority`
- `air_lang_typed_lt_imm_witness`
- `air_lang_typed_lt_reg_authority`
- `air_lang_typed_lt_reg_witness`
- `air_lang_typed_lui_authority`
- `air_lang_typed_lui_witness`
- `air_lang_typed_mul_authority`
- `air_lang_typed_mul_corpus`
- `air_lang_typed_mul_witness`
- `air_lang_typed_mulh_authority`
- `air_lang_typed_mulh_witness`
- `air_lang_typed_poseidon2_degree5_backend`
- `air_lang_typed_poseidon2_proof_harness`
- `air_lang_typed_shifts_imm_authority`
- `air_lang_typed_shifts_imm_witness`
- `air_lang_typed_shifts_reg_authority`
- `air_lang_typed_shifts_reg_witness`
- `air_lookups_mod`
- `air_lookups_opcode_component`
- `air_lookups_opcode_entries`
- `air_lookups_opcode_interaction`
- `air_lookups_tables_component`
- `air_lookups_tables_interaction`
- `air_lookups_tables_verifier`
- `air_memory_commitment_hash_component`
- `air_memory_commitment_hash_runtime_program`
- `air_memory_commitment_poseidon2_narrow_backend`
- `air_memory_commitment_poseidon2_narrow_component`
- `air_memory_commitment_poseidon2_narrow_degree3`
- `air_memory_commitment_poseidon2_universal_component`
- `air_memory_commitment_poseidon2_universal_degree3`
- `air_memory_logup`
- `air_native_boundary_typed_admission`
- `air_native_infrastructure_typed_admission`
- `air_native_polynomial_inventory`
- `air_opcode_memory`
- `air_preprocessed_mod`
- `air_profiling`
- `air_program_commitment`
- `air_program_decode`
- `air_program_fixed_table`
- `air_program_interaction`
- `air_program_mod`
- `air_program_table`
- `air_public_data`
- `air_public_data_test_support`
- `air_public_data_v2`
- `air_public_logup`
- `air_public_logup_v2`
- `air_relation_evidence`
- `air_relation_export`
- `air_relation_export_components`
- `air_relations`
- `air_semantic_component`
- `air_semantic_eval`
- `air_semantics_auipc_legacy_test_oracle`
- `air_semantics_base_alu_imm_legacy_test_oracle`
- `air_semantics_base_alu_reg_legacy_test_oracle`
- `air_semantics_branch_eq_legacy_test_oracle`
- `air_semantics_branch_lt_legacy_test_oracle`
- `air_semantics_div_legacy_test_oracle`
- `air_semantics_fence_legacy_test_oracle`
- `air_semantics_jal_legacy_test_oracle`
- `air_semantics_jalr_legacy_test_oracle`
- `air_semantics_load_store_legacy_test_oracle`
- `air_semantics_lt_imm_legacy_test_oracle`
- `air_semantics_lt_reg_legacy_test_oracle`
- `air_semantics_lui_legacy_test_oracle`
- `air_semantics_mod`
- `air_semantics_mul_legacy_test_oracle`
- `air_semantics_mulh_legacy_test_oracle`
- `air_semantics_shifts_imm_legacy_test_oracle`
- `air_semantics_shifts_reg_legacy_test_oracle`
- `air_statement`
- `air_statement_authority_preimage`
- `air_statement_geometry`
- `air_statement_public_projection`
- `air_statement_v2`
- `air_tests_clock_update_component_test`
- `air_tests_relation_export_components_test`
- `air_tests_relation_export_test`
- `air_tests_semantic_component_test`
- `air_trace_columns`
- `air_transcript_claims`
- `air_transcript_mod`
- `air_x0_native_envelope`
- `assets`
- `diagnostics_mod`
- `diagnostics_segment_manifest`
- `host_block_input`
- `host_hint_oracle`
- `host_prove_block`
- `host_runtime`
- `infra_trace`
- `owned_statement`
- `prover_base_component_assembly`
- `prover_blake3_coefficient_retention`
- `prover_blake3_commitment_columns`
- `prover_blake3_commitment_components`
- `prover_blake3_commitment_plan`
- `prover_blake3_commitment_plan_codec`
- `prover_blake3_commitment_sharing`
- `prover_blake3_commitment_witness`
- `prover_blake3_execution_artifact`
- `prover_blake3_execution_proof`
- `prover_blake3_execution_protocol`
- `prover_blake3_execution_trace`
- `prover_blake3_extension_bounds`
- `prover_blake3_extension_manifest`
- `prover_blake3_extension_proof`
- `prover_blake3_poseidon_proof`
- `prover_blake3_poseidon_witness`
- `prover_blake3_profile_artifact`
- `prover_blake3_segment_execution`
- `prover_blake3_segment_public`
- `prover_blake3_shared_path_topology`
- `prover_commitment_program_witness`
- `prover_commitment_witness`
- `prover_compact_extension_contract`
- `prover_elf`
- `prover_guest_precompile_cancellation`
- `prover_guest_precompile_component_assembly`
- `prover_guest_precompile_ecdsa_csp`
- `prover_guest_precompile_external_profile_tree`
- `prover_guest_precompile_orchestration`
- `prover_guest_precompile_proof_artifact`
- `prover_guest_precompile_proof_artifact_header`
- `prover_guest_precompile_proof_artifact_wire`
- `prover_guest_precompile_proof_finalize`
- `prover_guest_precompile_sha256_interaction`
- `prover_guest_precompile_split_caller_finish`
- `prover_guest_precompile_split_component_assembly`
- `prover_guest_precompile_split_leaf_prepare`
- `prover_guest_precompile_split_leaf_statement`
- `prover_guest_precompile_split_main_trace`
- `prover_guest_precompile_split_pcs_prepare`
- `prover_guest_precompile_split_provider_finish`
- `prover_guest_precompile_trace_geometry`
- `prover_guest_precompile_types`
- `prover_guest_precompile_verifier`
- `prover_incremental_bridge_external`
- `prover_lookup_sources`
- `prover_main_trace_plan`
- `prover_main_trace_plan_execution_production`
- `prover_main_trace_plan_execution_production_generators`
- `prover_memory_provider_shards_joint_proof_authority`
- `prover_memory_provider_shards_joint_protocol`
- `prover_memory_provider_shards_joint_provider_proof`
- `prover_memory_provider_shards_native_provider_omit`
- `prover_memory_provider_shards_proof_harness`
- `prover_opcode_trace`
- `prover_orchestration`
- `prover_preprocessed`
- `prover_proof_capture_sha256`
- `prover_proof_finalize`
- `prover_proof_phase_meter`
- `prover_proof_workspace`
- `prover_statement_geometry`
- `prover_statement_shape_inspection`
- `prover_statement_validation`
- `prover_test_witness_hook`
- `prover_types`
- `prover_verifier`
- `prover_verifier_lookup_compatibility`
- `recursion_air_arithmetic_fusion_census`
- `recursion_air_arithmetic_fusion_rows`
- `recursion_air_blake3_memory_custody`
- `recursion_air_blake3_memory_leaf`
- `recursion_air_blake3_memory_path`
- `recursion_air_blake3_memory_snapshot`
- `recursion_air_blake3_memory_update`
- `recursion_air_blake3_memory_update_chain`
- `recursion_air_blake3_memory_word`
- `recursion_air_blake3_native_root_nonce`
- `recursion_air_blake3_native_transcript`
- `recursion_air_blake3_parent_input_inventory`
- `recursion_air_blake3_program_word`
- `recursion_air_blake3_proof_fixture`
- `recursion_air_blake3_public_subtree_path`
- `recursion_air_composition_circuit`
- `recursion_air_composition_graph_recorder`
- `recursion_air_detached_arithmetic_fusion_plan`
- `recursion_air_detached_opening_accumulation_plan`
- `recursion_air_fri_hash_wire_plan`
- `recursion_air_fri_verifier_circuit`
- `recursion_air_fri_verifier_input_witness`
- `recursion_air_inventory`
- `recursion_air_pcs_deep_input_witness`
- `recursion_air_pcs_deep_input_witness_preprocessed`
- `recursion_air_pcs_deep_input_witness_reference`
- `recursion_air_range_check_8_8_bridge`
- `recursion_air_range_check_8_8_contract`
- `recursion_air_statement_input_roots`
- `recursion_air_statement_input_witness`
- `recursion_air_statement_semantics_bytes`
- `recursion_air_statement_semantics_input_witness`
- `recursion_air_statement_semantics_input_witness_blake3`
- `recursion_air_universal_manifest`
- `recursion_air_universal_provider_admission`
- `recursion_air_universal_shared_geometry`
- `recursion_air_universal_shared_provider`
- `recursion_air_universal_shared_provider_composition`
- `recursion_air_verifier_arithmetic_lowering`
- `recursion_air_verifier_arithmetic_lowering_plan`
- `recursion_air_verifier_arithmetic_lowering_reference`
- `recursion_air_vm_air_composition_input_witness`
- `recursion_air_vm_public_claim_hash_witness`
- `recursion_air_vm_public_claim_hash_witness_contract`
- `recursion_air_vm_public_claim_input_witness`
- `recursion_air_vm_public_io_hash_witness`
- `recursion_air_vm_statement_roots`
- `recursion_artifact_limits`
- `recursion_detached_proof_preflight`
- `recursion_segment_profile`
- `recursion_segment_statement`
- `recursion_segment_statement_authenticate_canonical_wire`
- `recursion_segment_statement_canonical_wire_view`
- `recursion_segment_statement_contract`
- `recursion_segment_statement_parallel_root`
- `recursion_segment_statement_source`
- `recursion_segment_statement_transcript_layout`
- `recursion_segment_statement_wire`
- `recursion_span_statement`
- `recursion_span_statement_blake3`
- `recursion_span_statement_blake3_test_fixture`
- `recursion_transcript_shape`
- `recursion_vm_air_profile`
- `recursion_vm_air_profile_v2`
- `recursion_vm_composition_base_geometry`
- `recursion_vm_leaf_context`
- `recursion_vm_leaf_context_v2`
- `recursion_vm_public_claim`
- `runner_access_witness`
- `runner_auipc_retirement`
- `runner_base_alu_imm_retirement`
- `runner_base_alu_reg_retirement`
- `runner_base_result`
- `runner_decode_cache`
- `runner_default_profile_owner`
- `runner_elf_admission`
- `runner_elf_loader`
- `runner_fence_retirement`
- `runner_generated_retirement`
- `runner_guest_precompile_bulk_memcpy`
- `runner_guest_precompile_bulk_memcpy_candidate_dispatch`
- `runner_guest_precompile_generic_session_state`
- `runner_guest_precompile_keccakf`
- `runner_guest_precompile_poseidon2`
- `runner_guest_precompile_secp256k1_recover`
- `runner_guest_precompile_sha256_compression`
- `runner_guest_precompile_stack_swap`
- `runner_guest_precompile_stack_swap_candidate_dispatch`
- `runner_guest_precompile_test_elf`
- `runner_load_store_retirement`
- `runner_lt_reg_retirement`
- `runner_lui_retirement`
- `runner_minimal_trace_mod`
- `runner_minimal_trace_replay`
- `runner_minimal_trace_types`
- `runner_sail_oracle`
- `runner_segment_capacity`
- `runner_segment_session_contract`
- `runner_segment_session_retirement`
- `runner_segment_session_support`
- `runner_session_owner`
- `runner_shifts_reg_retirement`
- `runner_trace`
- `runner_trace_dump`
- `runner_witness_auipc_legacy_test_oracle`
- `runner_witness_base_alu_imm_legacy_test_oracle`
- `runner_witness_base_alu_reg_legacy_test_oracle`
- `runner_witness_branch_eq_legacy_test_oracle`
- `runner_witness_branch_lt_legacy_test_oracle`
- `runner_witness_div_legacy_test_oracle`
- `runner_witness_fence_legacy_test_oracle`
- `runner_witness_jal_legacy_test_oracle`
- `runner_witness_jalr_legacy_test_oracle`
- `runner_witness_load_store_legacy_test_oracle`
- `runner_witness_lt_imm_legacy_test_oracle`
- `runner_witness_lt_reg_legacy_test_oracle`
- `runner_witness_lui_legacy_test_oracle`
- `runner_witness_mul_legacy_test_oracle`
- `runner_witness_mulh_legacy_test_oracle`
- `runner_witness_shifts_imm_legacy_test_oracle`
- `runner_witness_shifts_reg_legacy_test_oracle`
- `witness_layout`

## Dependencies

- `stwo_core`
- `stwo_prover_api`
- `stwo_prover_engine`
- `stwo_riscv_air_lang`
- `stwo_riscv_isa`
- `stwo_riscv_memory`
- `stwo_riscv_precompiles`
- `stwo_riscv_recursion_air`

## Build, test, and run

`zig build test --build-file src/frontends/riscv/rv32/build.zig -Doptimize=Debug -j2`

## Contract and invariants

Preserve field/proof bytes, canonical nominal types, errors, allocation, cancellation and teardown ownership. Existing behavior tests move with their owner; CPU proof byte identity and complete discovery remain required.

## Change checklist

Use the owned package contracts and existing developer entrypoints; do not relax pins, floors, proof checks or layer rejection.

## Related documentation

[Restructure plan](../../../../design/repository/restructure-plan.md) and [RFC #344](https://github.com/teddyjfpender/stwo-zig/issues/344).

The public aliases in this package are the concrete source interfaces already consumed by other owners. Each alias resolves to one owned implementation module, so shared records and callbacks retain one canonical nominal identity. Internal declarations in those modules retain their existing Zig visibility. New consumers should depend on the named package instead of a relative filesystem path; changes to these aliases or dependencies require the invariant owner's contract decision.

Request owners retain the original allocation and failure rules. Validate untrusted shapes before publication, complete fallible preparation before a commit boundary, and unwind every acquired resource on cancellation or error. A moved deinit method still owns exactly the same buffers. This split adds no runtime registry, environment policy, protocol revision or new proof format. The same behavior and rejection tests move with each implementation.

The compatibility umbrella continues to assemble the old module names for one minor version. Product-selecting orchestration stays above generic children. Complete Debug and ReleaseFast owner suites, preserved focused-test counts and frozen CPU proof bytes are the acceptance evidence. Syntax checks, a source-tree audit or a successful package build alone do not certify the complete proving pipeline or any GPU path.
