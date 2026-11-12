# `stwo_riscv_memory`

| Fact | Value |
| --- | --- |
| Version | `0.1.0` |
| Layer | `frontend` |
| Owner | `riscv-frontend` |
| Focused CI host | Linux |

## Purpose and architecture

Canonical memory source ownership under RFC #344; public module aliases point to one implementation each.

```mermaid
graph LR
  Consumer --> memory
  memory --> DeclaredProviders
```

## Public API

`@import("stwo_riscv_memory")` exposes these consumed canonical source interfaces:

- `air_blake3_state_tree`
- `air_boundary`
- `air_byte_tree_topology`
- `air_hash_component_prepared_domain`
- `air_hash_component_prepared_support`
- `air_hash_component_reference_test_support`
- `air_hash_component_sampling`
- `air_incremental_boundary_interaction`
- `air_incremental_bridge`
- `air_incremental_bridge_component`
- `air_interaction`
- `air_merkle_node`
- `air_merkle_typed_admission`
- `air_mod`
- `air_poseidon2`
- `air_poseidon2_air`
- `air_poseidon2_call`
- `air_poseidon2_constants`
- `air_poseidon2_degree3_component`
- `air_poseidon2_degree3_schedule`
- `air_poseidon2_degree3_verifier`
- `air_poseidon2_layout`
- `air_poseidon2_universal_equations`
- `air_poseidon2_universal_identity`
- `air_poseidon2_universal_layout`
- `air_poseidon2_wide_equations`
- `air_poseidon2_wide_typed_admission`
- `air_sparse_merkle`
- `air_trace`
- `assets`
- `primitives_aggregation_hash`
- `primitives_common_poseidon2`
- `primitives_prover_poseidon_witness_work`
- `primitives_recursion_blake3_identity_digest`
- `primitives_recursion_poseidon2_channel`
- `prover_authority`
- `prover_provider_order_component`
- `prover_standalone_component`
- `typed_materialization_frontier_cost_model`
- `typed_materialization_frontier_manifest`
- `typed_materialization_frontier_projection`
- `typed_poseidon_layout_benchmark_command`
- `typed_typed_poseidon2`
- `typed_typed_poseidon2_authority`
- `typed_typed_poseidon2_compact`
- `typed_typed_poseidon2_compat`
- `typed_typed_poseidon2_degree5_component`
- `typed_typed_poseidon2_degree5_row_program`
- `typed_typed_poseidon2_degree5_trace`
- `typed_typed_poseidon2_degree_bounded_candidate`
- `typed_typed_poseidon2_degree_bounded_component`
- `typed_typed_poseidon2_degree_bounded_residency`
- `typed_typed_poseidon2_degree_bounded_trace`
- `typed_typed_poseidon2_fixed_polynomials`
- `typed_typed_poseidon2_frontier_artifact`
- `typed_typed_poseidon2_identity`
- `typed_typed_poseidon2_identity_codec`
- `typed_typed_poseidon2_identity_golden`
- `typed_typed_poseidon2_proof_authority`
- `typed_typed_poseidon2_relations`
- `typed_typed_poseidon2_wide`
- `typed_typed_poseidon2_witness`

## Dependencies

- `stwo_core`
- `stwo_prover_api`
- `stwo_prover_engine`
- `stwo_riscv_air_lang`
- `stwo_riscv_isa`

## Build, test, and run

`zig build test --build-file src/frontends/riscv/memory/build.zig -Doptimize=Debug -j2`

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

`aggregation`, `air`, `common`, `prover`, `recursion`, `testing`, `typed`.

These names expose canonical domain owners. The `testing` namespace, when present, is an unstable qualification interface. Production request admission and product orchestration remain in the umbrella.
