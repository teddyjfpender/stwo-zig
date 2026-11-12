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

`@import("stwo_riscv_air_lang")` exposes these canonical domain interfaces:

- `access_transaction_support`
- `capabilities`
- `circuit_layout`
- `compat_manifest_diff`
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
- `evaluation`
- `expr`
- `fixed_polynomial_program`
- `fixed_shift_common`
- `framework`
- `function_activation_alias`
- `function_activation_authority`
- `function_activation_preflight`
- `function_frames`
- `functions`
- `hint_recipe`
- `hints`
- `instruction_effects`
- `ir`
- `lower_effects`
- `manifest`
- `physical_profile`
- `polynomial_encoding`
- `polynomial_replay`
- `program`
- `relation`
- `row_window_runtime`
- `runtime_profile_json`
- `runtime_profile_support`
- `shadow_import`
- `source`
- `static_collections`
- `testing`
- `trace_layout`
- `typed_addi`
- `typed_auipc`
- `typed_base_alu_reg`
- `typed_branch_eq`
- `typed_branch_lt`
- `typed_div`
- `typed_div_evaluator`
- `typed_fence`
- `typed_jal`
- `typed_jalr`
- `typed_load_store`
- `typed_lt_imm`
- `typed_lt_reg`
- `typed_lui`
- `typed_mul`
- `typed_mulh`
- `typed_native_boundary`
- `typed_shifts_imm`
- `typed_shifts_reg`
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

## Interface stability

The Public API list above follows the package contract. These names expose
canonical domain owners; `testing`, when present, is an unstable qualification
interface. Production admission and product orchestration remain above the
native children.
