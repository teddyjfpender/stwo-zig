# `stwo_riscv_recursion_air`

| Fact | Value |
| --- | --- |
| Version | `0.1.0` |
| Layer | `frontend` |
| Owner | `riscv-frontend` |
| Focused CI host | Linux |

## Purpose and architecture

Canonical recursion air source ownership under RFC #344; public module aliases point to one implementation each.

```mermaid
graph LR
  Consumer --> recursion_air
  recursion_air --> DeclaredProviders
```

## Public API

`@import("stwo_riscv_recursion_air")` exposes these consumed canonical source interfaces:

- `arithmetic_fusion_fixed_columns`
- `assets`
- `blake3_direct_cohort_columns`
- `blake3_direct_source_columns`
- `blake3_draw_hash_layout`
- `blake3_draw_witness`
- `blake3_fixture_roster`
- `blake3_frontier_capture`
- `blake3_hash_test_support`
- `blake3_lifted_leaf_plan`
- `blake3_main_column_test_support`
- `blake3_merkle_group_witness`
- `blake3_merkle_path_witness`
- `blake3_native_recorder`
- `blake3_node_route`
- `blake3_nonhash_emission`
- `blake3_path_sharing_census`
- `blake3_pcs_transcript`
- `blake3_proof_gate_test_support`
- `blake3_query_witness`
- `blake3_recursive_column_rows`
- `blake3_root_sources`
- `blake3_scalar_payload_rows`
- `blake3_shared_root_plan`
- `blake3_transcript_plan`
- `blake3_transcript_witness`
- `blake3_two_level_frontier`
- `blake3_upstream_source_columns`
- `control_slice_witness`
- `control_witness`
- `detached_graph_input`
- `detached_parent_catalog`
- `detached_pcs_opening4`
- `detached_poseidon_graph`
- `field_public_word`
- `field_statement_word`
- `fixed_wire`
- `fri_merkle_anchor`
- `fri_merkle_anchor_relation`
- `fri_merkle_anchor_witness`
- `fri_merkle_leaf`
- `fri_merkle_leaf_relation`
- `fri_merkle_leaf_witness`
- `fri_merkle_node`
- `fri_merkle_node_relation`
- `fri_merkle_node_witness`
- `fri_verifier_control`
- `fri_verifier_control_relation`
- `fri_verifier_control_witness`
- `fri_verifier_input`
- `fri_verifier_input_relation`
- `implementation`
- `interaction_generator`
- `linear_ops_witness`
- `merkle_path`
- `merkle_path_poseidon_bridge`
- `merkle_path_relation`
- `merkle_path_witness`
- `merkle_root`
- `merkle_root_relation`
- `merkle_root_witness`
- `pcs_deep_input`
- `pcs_deep_input_relation`
- `pow_check`
- `pow_check_witness`
- `pow_frame`
- `pow_frame_witness`
- `prepared_interaction_generation`
- `protocol_aggregation_types`
- `protocol_recursion_blake3_engine_protocol`
- `protocol_recursion_engine_protocol`
- `protocol_recursion_fixed_profile`
- `protocol_recursion_fixed_wire`
- `protocol_recursion_protocol`
- `protocol_recursion_protocol_statement_constants`
- `qm31_inv_witness`
- `qm31_mul_full`
- `qm31_mul_full_witness`
- `query_bits`
- `query_bits_profile`
- `query_bits_relation`
- `query_bits_witness`
- `query_mapping`
- `query_mapping_relation`
- `query_mapping_witness`
- `relation_challenge`
- `relation_challenge_witness`
- `roster_composition_geometry`
- `segment_public_outer_air`
- `statement_input`
- `statement_input_relation`
- `statement_semantics_input`
- `statement_semantics_input_relation`
- `structural_sha256`
- `test_support`
- `tests_blake3_rejection_fixture_test_support`
- `tests_qm31_mul_full_relation_test_support`
- `tests_vm_public_logup_control_test`
- `trace_merkle`
- `trace_merkle_relation`
- `trace_merkle_witness`
- `transcript_air`
- `transcript_air_witness`
- `transcript_binding`
- `transcript_binding_witness`
- `transcript_payload`
- `transcript_payload_clocks`
- `transcript_payload_relation`
- `transcript_payload_witness`
- `transcript_state`
- `transcript_state_witness`
- `transcript_word`
- `transcript_word_witness`
- `universal_catalog`
- `universal_catalog_entry`
- `universal_component_owner`
- `verifier_component_parameters`
- `verifier_parameter_tags`
- `verifier_randomness`
- `verifier_randomness_relation`
- `verifier_randomness_witness`
- `verifier_schedule`
- `verifier_wire_claims`
- `verifier_wire_protocol`
- `vm_air_composition_control`
- `vm_air_composition_input`
- `vm_air_composition_input_relation`
- `vm_public_claim_hash`
- `vm_public_claim_hash_authority`
- `vm_public_claim_input`
- `vm_public_claim_semantics_input`
- `vm_public_claim_semantics_input_witness`
- `vm_public_io_hash`
- `vm_public_logup_control`
- `vm_public_logup_control_relation`
- `vm_public_logup_control_v2`
- `vm_public_logup_control_witness`
- `vm_public_logup_input`
- `vm_public_logup_input_witness`

## Dependencies

- `stwo_core`
- `stwo_prover_engine`
- `stwo_riscv_air_lang`
- `stwo_riscv_memory`

## Build, test, and run

`zig build test --build-file src/frontends/riscv/recursion_air/build.zig -Doptimize=Debug -j2`

## Contract and invariants

Preserve field/proof bytes, canonical nominal types, errors, allocation, cancellation and teardown ownership. Existing behavior tests move with their owner; CPU proof byte identity and complete discovery remain required.

## Change checklist

Use the owned package contracts and existing developer entrypoints; do not relax pins, floors, proof checks or layer rejection.

## Related documentation

[Restructure plan](../../../../design/repository/restructure-plan.md) and [RFC #344](https://github.com/teddyjfpender/stwo-zig/issues/344).

The public aliases in this package are the concrete source interfaces already consumed by other owners. Each alias resolves to one owned implementation module, so shared records and callbacks retain one canonical nominal identity. Internal declarations in those modules retain their existing Zig visibility. New consumers should depend on the named package instead of a relative filesystem path; changes to these aliases or dependencies require the invariant owner's contract decision.

Request owners retain the original allocation and failure rules. Validate untrusted shapes before publication, complete fallible preparation before a commit boundary, and unwind every acquired resource on cancellation or error. A moved deinit method still owns exactly the same buffers. This split adds no runtime registry, environment policy, protocol revision or new proof format. The same behavior and rejection tests move with each implementation.

The compatibility umbrella continues to assemble the old module names for one minor version. Product-selecting orchestration stays above generic children. Complete Debug and ReleaseFast owner suites, preserved focused-test counts and frozen CPU proof bytes are the acceptance evidence. Syntax checks, a source-tree audit or a successful package build alone do not certify the complete proving pipeline or any GPU path.
