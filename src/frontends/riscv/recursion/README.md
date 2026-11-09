# `stwo_riscv_recursion`

| Fact | Value |
| --- | --- |
| Version | `0.1.0` |
| Layer | `frontend` |
| Owner | `riscv-frontend` |
| Focused CI host | Linux |

## Purpose and architecture

Canonical recursion source ownership under RFC #344; public module aliases point to one implementation each.

```mermaid
graph LR
  Consumer --> recursion
  recursion --> DeclaredProviders
```

## Public API

`@import("stwo_riscv_recursion")` exposes these consumed canonical source interfaces:

- `air_blake3_native_challenge_links`
- `air_blake3_native_openings`
- `air_blake3_native_parent_roster`
- `air_blake3_native_parent_rows`
- `air_blake3_native_payload_links`
- `air_blake3_native_pcs_challenges`
- `air_blake3_native_public_links`
- `air_blake3_native_public_sources`
- `air_blake3_native_queries`
- `air_blake3_native_sample_links`
- `air_blake3_native_terminal_encoding`
- `air_blake3_projection_links`
- `air_blake3_query_links`
- `air_blake3_stark_paths`
- `air_detached_pcs_opening_plan`
- `air_pcs_deep_circuit`
- `air_segment_boundary_components`
- `air_segment_leaf_catalog`
- `air_segment_outer_adapter_manifest`
- `air_segment_outer_adapter_manifest_proof_gate`
- `air_segment_outer_manifest_contract`
- `air_segment_outer_typed_catalog`
- `air_segment_publication_input_provider`
- `air_segment_publication_input_provider_component`
- `air_segment_publication_input_provider_relation`
- `air_segment_publication_input_provider_witness`
- `arithmetic_circuit`
- `blake3_native_parent_artifact`
- `blake3_native_parent_codec`
- `blake3_native_parent_pipeline`
- `blake3_native_parent_producer`
- `blake3_native_parent_protocol`
- `blake3_native_parent_verifier`
- `blake3_native_parent_worker`
- `detached_parent_components`
- `detached_parent_contract`
- `detached_parent_definitions`
- `detached_parent_prepared`
- `detached_parent_verifier_components`
- `detached_segment_admission`
- `implementation`
- `sample_point_layout`
- `segment_leaf_authority_v2`
- `segment_leaf_local_authority`
- `segment_leaf_local_projection`
- `segment_leaf_local_verified_link`
- `segment_leaf_outer_air`
- `segment_leaf_outer_authority`
- `segment_leaf_outer_bundle`
- `segment_leaf_statement_contract`
- `segment_public_native_sum_authority`
- `segment_public_outer_components`
- `segment_public_outer_source`
- `segment_public_outer_source_v2`
- `segment_public_outer_test_support`
- `segment_publication_input_provider_authority`
- `segment_publication_input_provider_test_support`
- `segment_statement_outer_components`
- `segment_statement_outer_source`
- `segment_statement_outer_source_v2`
- `segment_transcript_outer_source_v2`
- `statement_semantics_circuit`
- `temporal_pair_node`
- `tests_segment_leaf_outer_authority_test`
- `tests_segment_statement_outer_source_v2_test`
- `vm_air_composition_circuit`
- `vm_air_composition_circuit_circuit`
- `vm_composition_preparation`
- `vm_public_semantics_circuit`
- `vm_selected_lookup_compiler`

## Dependencies

- `stwo_core`
- `stwo_prover_api`
- `stwo_prover_engine`
- `stwo_riscv_air_lang`
- `stwo_riscv_isa`
- `stwo_riscv_memory`
- `stwo_riscv_precompiles`
- `stwo_riscv_recursion_air`
- `stwo_riscv_rv32`

## Build, test, and run

`zig build test --build-file src/frontends/riscv/recursion/build.zig -Doptimize=Debug -j2`

## Contract and invariants

Preserve field/proof bytes, canonical nominal types, errors, allocation, cancellation and teardown ownership. Existing behavior tests move with their owner; CPU proof byte identity and complete discovery remain required.

## Change checklist

Use the owned package contracts and existing developer entrypoints; do not relax pins, floors, proof checks or layer rejection.

## Related documentation

[Restructure plan](../../../../design/repository/restructure-plan.md) and [RFC #344](https://github.com/teddyjfpender/stwo-zig/issues/344).

The public aliases in this package are the concrete source interfaces already consumed by other owners. Each alias resolves to one owned implementation module, so shared records and callbacks retain one canonical nominal identity. Internal declarations in those modules retain their existing Zig visibility. New consumers should depend on the named package instead of a relative filesystem path; changes to these aliases or dependencies require the invariant owner's contract decision.

Request owners retain the original allocation and failure rules. Validate untrusted shapes before publication, complete fallible preparation before a commit boundary, and unwind every acquired resource on cancellation or error. A moved deinit method still owns exactly the same buffers. This split adds no runtime registry, environment policy, protocol revision or new proof format. The same behavior and rejection tests move with each implementation.

The compatibility umbrella continues to assemble the old module names for one minor version. Product-selecting orchestration stays above generic children. Complete Debug and ReleaseFast owner suites, preserved focused-test counts and frozen CPU proof bytes are the acceptance evidence. Syntax checks, a source-tree audit or a successful package build alone do not certify the complete proving pipeline or any GPU path.
