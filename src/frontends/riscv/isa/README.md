# `stwo_riscv_isa`

| Fact | Value |
| --- | --- |
| Version | `0.1.0` |
| Layer | `frontend` |
| Owner | `riscv-frontend` |
| Focused CI host | Linux |

## Purpose and architecture

Canonical isa source ownership under RFC #344; public module aliases point to one implementation each.

```mermaid
graph LR
  Consumer --> isa
  isa --> DeclaredProviders
```

## Public API

`@import("stwo_riscv_isa")` exposes these consumed canonical source interfaces:

- `access_clock`
- `authority`
- `bulk_memcpy_candidate`
- `bulk_memcpy_private_registry`
- `custom0`
- `decode`
- `execution_profile`
- `host_interface`
- `implementation`
- `opcode_manifest`
- `profile`
- `runner_cpu`
- `runner_decode`
- `runner_execution_boundary`
- `runner_memory`
- `runner_memory_state`
- `runner_state_chain`
- `runner_trace_row`
- `sha256_compression`
- `stack_swap_candidate`
- `stack_swap_private_registry`

## Dependencies

- `stwo_core`

## Build, test, and run

`zig build test --build-file src/frontends/riscv/isa/build.zig -Doptimize=Debug -j2`

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

`access_clock`, `authority`, `bulk_memcpy_candidate`, `bulk_memcpy_private_registry`, `custom0`, `decode`, `execution_profile`, `host`, `instruction_set`, `machine`, `opcode_manifest`, `profile`, `segment_wire_layout`, `sha256_compression`, `span_word_geometry`, `stack_swap_candidate`, `stack_swap_private_registry`.

These names expose canonical domain owners. The `testing` namespace, when present, is an unstable qualification interface. Production request admission and product orchestration remain in the umbrella.
