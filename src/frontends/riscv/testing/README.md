# `stwo_riscv_testing`

| Fact | Value |
| --- | --- |
| Version | `0.1.0` |
| Layer | `frontend` |
| Owner | `riscv-frontend` |
| Focused CI host | Linux |

## Purpose and architecture

Canonical testing source ownership under RFC #344; public module aliases point to one implementation each.

```mermaid
graph LR
  Consumer --> testing
  testing --> DeclaredProviders
```

## Public API

`@import("stwo_riscv_testing")` exposes these canonical domain interfaces:

- `benchmarks`
- `regressions`
- `testing`

## Dependencies

- `stwo_core`
- `stwo_prover_api`
- `stwo_prover_engine`
- `stwo_riscv_air_lang`
- `stwo_riscv_isa`
- `stwo_riscv_memory`
- `stwo_riscv_precompiles`
- `stwo_riscv_recursion`
- `stwo_riscv_recursion_air`
- `stwo_riscv_rv32`
- `stwo_riscv_rv64`

## Build, test, and run

`zig build test --build-file src/frontends/riscv/testing/build.zig -Doptimize=Debug -j2`

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
