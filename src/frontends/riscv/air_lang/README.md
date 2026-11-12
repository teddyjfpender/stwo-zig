# `stwo_riscv_air_lang`

| Fact | Value |
| --- | --- |
| Version | `0.1.0` |
| Layer | `frontend` |
| Owner | `riscv-frontend` |
| Focused CI host | Linux |

## Purpose and architecture

Canonical air lang source ownership under RFC #344; public module aliases point to one implementation each.

```mermaid
graph LR
  Consumer --> air_lang
  air_lang --> DeclaredProviders
```

## Public API

`@import("stwo_riscv_air_lang")` exposes these consumed canonical source interfaces:

- `access_transaction_support`
- `assets`
- `capabilities`
- `compat_manifest_diff`
- `cost_aware_materializer`
- `definition`
- `degree`
- `degree3_materializer`
- `degree3_materializer_identity`
- `diagnostic`
- `digest`
- `direct_polynomial_graph`
- `direct_polynomial_program`
- `direct_witness_executor`
- `effects`
- `expr`
- `fixed_polynomial_program`
- `fixed_shift_common`
- `framework_blake3_boundary`
- `framework_blake3_byte_route`
- `framework_blake3_challenge_block`
- `framework_blake3_component_roster`
- `framework_blake3_compression_plan`
- `framework_blake3_counter_step`
- `framework_blake3_field_bytes`
- `framework_blake3_frame_route`
- `framework_blake3_frame_witness`
- `framework_blake3_g_call`
- `framework_blake3_hash_metadata`
- `framework_blake3_hash_plan`
- `framework_blake3_hash_witness`
- `framework_blake3_input_bridge`
- `framework_blake3_memory_boundary`
- `framework_blake3_parallel_lookup_counts`
- `framework_blake3_parent_row_storage`
- `framework_blake3_path_select`
- `framework_blake3_private_word`
- `framework_blake3_program_boundary`
- `framework_blake3_public_program`
- `framework_blake3_query_mask`
- `framework_blake3_retry_control`
- `framework_blake3_row_columns`
- `framework_blake3_xor_call`
- `framework_closed_machine_expression`
- `framework_compact_range_geometry`
- `framework_compact_range_interaction`
- `framework_compact_range_provider`
- `framework_compact_range_roster`
- `framework_compact_range_witness`
- `framework_control`
- `framework_control_relation`
- `framework_detached_opening_accumulate4`
- `framework_direct_constraint_program`
- `framework_framework_device_interaction`
- `framework_framework_interaction`
- `framework_framework_parallel_interaction`
- `framework_framework_polynomial_export`
- `framework_linear_ops`
- `framework_manifest_proof_protocol`
- `framework_native_pcs_opening4`
- `framework_proof_kind`
- `framework_qm31_inv`
- `framework_qm31_mul`
- `framework_qm31_mul_add`
- `framework_qm31_pack_wire`
- `framework_readonly_consistency`
- `framework_readonly_input`
- `framework_relation_effect`
- `framework_relation_interaction`
- `framework_scalar_wire_source`
- `framework_universal_adapter_manifest`
- `framework_universal_challenges`
- `framework_universal_component_roster`
- `framework_universal_manifest_contract`
- `framework_universal_provider_relations`
- `framework_universal_relation_binding`
- `framework_universal_roster`
- `framework_universal_typed_component`
- `framework_universal_typed_component_contract`
- `framework_universal_typed_geometry`
- `framework_universal_typed_verifier_component`
- `framework_wire_relation`
- `function_activation_alias`
- `function_activation_authority`
- `function_activation_logup_test_support`
- `function_activation_preflight`
- `function_frames`
- `functions`
- `hint_recipe`
- `hints`
- `instruction_effects`
- `ir`
- `lower_effects`
- `lower_test_oracle`
- `manifest`
- `materialization_cost`
- `materialization_cut_set`
- `materialization_direct_benchmark`
- `materialization_frontier_digest`
- `materialization_frontier_manifest_lengths`
- `materialization_frontier_manifest_test_support`
- `materialization_frontier_manifest_validate`
- `materialization_frontier_manifest_wire`
- `materialization_neighbourhood`
- `opcode_composition_manifest_test_support`
- `polynomial_replay`
- `program`
- `relation`
- `row_window_runtime`
- `runtime_profile_json`
- `runtime_profile_support`
- `shadow_import`
- `shared_air_component_point_support`
- `shared_air_composition_work_support`
- `shared_air_extract_canonical_digest`
- `shared_air_extract_provider_equivalence`
- `shared_air_extract_symbolic`
- `shared_air_extract_symbolic_relations`
- `shared_air_logup`
- `shared_air_logup_equations`
- `shared_air_lookups_entry`
- `shared_air_lookups_tables_counter`
- `shared_air_lookups_tables_schema`
- `shared_air_lookups_tables_schema_definition`
- `shared_air_packed_fields16`
- `shared_air_prepared_evaluation_owner`
- `shared_air_prepared_parallel`
- `shared_air_relation_challenges`
- `shared_air_semantics_common`
- `shared_air_semantics_control_common`
- `shared_infra_trace_permutation`
- `source`
- `static_collections`
- `typed_addi`
- `typed_addi_witness_test_support`
- `typed_air_compatibility_test_support`
- `typed_auipc`
- `typed_auipc_witness_test_support`
- `typed_base_alu_imm_witness_test_support`
- `typed_base_alu_reg`
- `typed_base_alu_reg_witness_test_support`
- `typed_branch_eq`
- `typed_branch_eq_test_support`
- `typed_branch_eq_witness_test_support`
- `typed_branch_lt`
- `typed_branch_lt_test_support`
- `typed_branch_lt_witness_test_support`
- `typed_div`
- `typed_div_evaluator`
- `typed_div_test_support`
- `typed_fence`
- `typed_fence_witness_test_support`
- `typed_jal`
- `typed_jal_witness_test_support`
- `typed_jalr`
- `typed_jalr_test_support`
- `typed_load_store`
- `typed_load_store_polynomial_test_support`
- `typed_load_store_test_support`
- `typed_lt_imm`
- `typed_lt_imm_test_support`
- `typed_lt_reg`
- `typed_lt_reg_test_support`
- `typed_lt_reg_witness_test_support`
- `typed_lui`
- `typed_mul`
- `typed_mulh`
- `typed_mulh_witness_test_support`
- `typed_native_boundary`
- `typed_shifts_imm`
- `typed_shifts_imm_witness_test_support`
- `typed_shifts_reg`
- `typed_shifts_reg_witness_test_support`
- `types`
- `validate`
- `window_ir`

## Dependencies

- `stwo_core`
- `stwo_prover_api`
- `stwo_prover_engine`
- `stwo_riscv_isa`

## Build, test, and run

`zig build test --build-file src/frontends/riscv/air_lang/build.zig -Doptimize=Debug -j2`

## Contract and invariants

Preserve field/proof bytes, canonical nominal types, errors, allocation, cancellation and teardown ownership. Existing behavior tests move with their owner; CPU proof byte identity and complete discovery remain required.

## Change checklist

Use the owned package contracts and existing developer entrypoints; do not relax pins, floors, proof checks or layer rejection.

## Related documentation

[Restructure plan](../../../../design/repository/restructure-plan.md) and [RFC #344](https://github.com/teddyjfpender/stwo-zig/issues/344).

The public aliases in this package are the concrete source interfaces already consumed by other owners. Each alias resolves to one owned implementation module, so shared records and callbacks retain one canonical nominal identity. Internal declarations in those modules retain their existing Zig visibility. New consumers should depend on the named package instead of a relative filesystem path; changes to these aliases or dependencies require the invariant owner's contract decision.

Request owners retain the original allocation and failure rules. Validate untrusted shapes before publication, complete fallible preparation before a commit boundary, and unwind every acquired resource on cancellation or error. A moved deinit method still owns exactly the same buffers. This split adds no runtime registry, environment policy, protocol revision or new proof format. The same behavior and rejection tests move with each implementation.

The compatibility umbrella continues to assemble the old module names for one minor version. Product-selecting orchestration stays above generic children. Complete Debug and ReleaseFast owner suites, preserved focused-test counts and frozen CPU proof bytes are the acceptance evidence. Syntax checks, a source-tree audit or a successful package build alone do not certify the complete proving pipeline or any GPU path.

## Typed domain interfaces

`access_transaction_support`, `capabilities`, `circuit_layout`, `compat_manifest_diff`, `cost_aware_materializer`, `definition`, `degree`, `degree3_materializer`, `degree3_materializer_identity`, `diagnostic`, `digest`, `direct_polynomial_graph`, `direct_polynomial_program`, `direct_witness_executor`, `effects`, `evaluation`, `expr`, `fixed_polynomial_program`, `fixed_shift_common`, `framework`, `function_activation_alias`, `function_activation_authority`, `function_activation_preflight`, `function_frames`, `functions`, `hint_recipe`, `hints`, `instruction_effects`, `ir`, `lower_effects`, `manifest`, `materialization_cost`, `materialization_cut_set`, `materialization_direct_benchmark`, `materialization_frontier_digest`, `materialization_frontier_manifest_lengths`, `materialization_frontier_manifest_validate`, `materialization_frontier_manifest_wire`, `materialization_neighbourhood`, `physical_profile`, `polynomial_encoding`, `polynomial_replay`, `program`, `relation`, `row_window_runtime`, `runtime_profile_json`, `runtime_profile_support`, `shadow_import`, `source`, `static_collections`, `testing`, `trace_layout`, `typed_addi`, `typed_auipc`, `typed_base_alu_reg`, `typed_branch_eq`, `typed_branch_lt`, `typed_div`, `typed_div_evaluator`, `typed_fence`, `typed_jal`, `typed_jalr`, `typed_load_store`, `typed_lt_imm`, `typed_lt_reg`, `typed_lui`, `typed_mul`, `typed_mulh`, `typed_native_boundary`, `typed_shifts_imm`, `typed_shifts_reg`, `types`, `validate`, `window_ir`.

These names expose canonical domain owners. The `testing` namespace, when present, is an unstable qualification interface. Production request admission and product orchestration remain in the umbrella.
