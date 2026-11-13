# `stwo_ethereum_statement`

| Fact | Value |
| --- | --- |
| Version | `0.1.0` |
| Layer | `product` |
| Owner | `ethereum-statement` |
| Focused CI host | Linux |

## Purpose and architecture

Ethereum statement orchestration belongs above neutral RISC-V frontends and integrations.
The frontend, CPU and CUDA components are constructed once. CPU imports frontend;
CUDA imports both. The primary module and two legacy exports reuse those instances.
Ethereum request, image, session, publication and recursion policy now live in
this package. Computation, field/curve arithmetic, service ABI and physical
witness storage keep their canonical neutral owners. Strict product placement
is active with zero findings. Whole-package qualification is recorded separately
against immutable source revisions; no GPU qualification is established here.

```mermaid
graph TD
    Primary --> Frontend
    Primary --> CPU
    Primary --> CUDA
    CPU --> Frontend
    CUDA --> CPU
    CUDA --> Frontend
    Frontend --> NeutralProviders
    CPU --> NeutralProviders
    CUDA --> NeutralProviders
```

## Public API

`@import("stwo_ethereum_statement")` exposes `cpu`, `cuda`, `frontend`, `prover`,
`runner` and `statement`. `@import("legacy_riscv_frontend")` and
`@import("legacy_riscv_cpu_integration")` name the exact frontend and CPU component
instances, with no duplicate implementation or nominal records.

## Dependencies

- `stwo_circuit_frontend`
- `stwo_cpu_backend`
- `stwo_metal_backend`

- `stwo_circuit_cpu_integration`
- `stwo_core`
- `stwo_proof_wire`
- `stwo_prover_api`
- `stwo_prover_engine`
- `stwo_riscv_air_lang`
- `stwo_riscv_cpu_integration`
- `stwo_riscv_cuda_integration`
- `stwo_riscv_frontend`
- `stwo_riscv_isa`
- `stwo_riscv_memory`
- `stwo_riscv_precompiles`
- `stwo_riscv_recursion`
- `stwo_riscv_recursion_air`
- `stwo_riscv_rv32`
- `stwo_riscv_rv64`
- `stwo_riscv_testing`

## Build, test, and run

`zig build test --build-file src/products/ethereum/statement/build.zig -Doptimize=Debug -j2 --verbose --summary all`

## Contract and invariants

Keep canonical shared types, profile IDs, protocol bytes, rejection classification,
allocation, cancellation, publication and teardown ordering. Compatibility module
identity is checked in the real build and in concrete primary/legacy consumers.
Legacy aliases are deprecated from 2026-11-09 and retained through at least
2027-02-09 and one subsequent product minor release.

## Change checklist

Migrate all live consumers and discovery roots; activate strict product placement
without exemptions; run frontend Debug/ReleaseFast, CPU negatives and frozen
Native proof-byte parity before calling the extraction complete.

## Related documentation

[RFC #352](https://github.com/teddyjfpender/stwo-zig/issues/352) and
[extraction ledger](../../../../design/repository/ethereum-product-extraction.md).

The primary domain list is deliberately small; it describes ownership rather than
flattening all implementation declarations into a new global surface. The legacy
components preserve the old imported names for migration. Consumers must declare
the real product dependency and bind those names to the corresponding exported
component, rather than compiling the component root again or importing its files
by relative path. Native-only consumers continue using the neutral packages.

The build checks actual component pointers, while the contract tests compare the
module identities and canonical machine, memory, trace and host-interface records.
Those checks are necessary but do not replace execution tests. During extraction,
focused checks are bounded by the laptop memory guard and hold the canonical build
lock. Full combined acceptance is reported separately against its exact source.
No status from the old partial backup establishes acceptance of this package.

Existing CSP qualification commands now belong to this product:
`test-csp-ecdsa-proof`, `test-blake3-csp-ecdsa-jit`, and
`test-blake3-csp-ecdsa-aot` (with the same authenticated bundle option).
The Metal commands are explicit device gates and are outside the default test
step. This migration introduces no device qualification or performance claim.
The CPU CSP target defaults to the committed `vectors/riscv_csp` fixtures.
An explicit `STWO_CSP_FIXTURE_ROOT` retains its existing override behavior.

The retained mixed gate now runs here as `test-retained-typed-components`:
its original floor of21 joins the existing native typed cases and the product
VM cases. The native owner constructs its test module from the selected module
graph; this product does not name a private native test path.
`test-stack-swap-candidate` likewise runs here with its original floor7.
The neutral package’s `test-native-typed-components` covers its mathematical
subset; its default test command still collects all native assertions.

`test-ethereum-runner` and `test-ethereum-minimal-trace` also run here,
retaining floors11 and1. The runner joins the product execution assertions
with actual ISA, recovery-ABI and native signer tests over the selected
module graph; importing a named module alone is not counted as execution.

`test-authenticated-component-profile` isolates the complete all-provider
proof/recorder parity case for3/8/16workers and both control encodings. It uses
the production worker-stack default and remains in the full default suite.
Run this proof-heavy gate on the qualified CPU host; configuration alone does
not establish its proof or timing results.

The hosted CPU diagnostic `ethereum_receiver_releasefast` runs the existing
`test-receiver-boundaries` target through `scripts/dev_test.py`, independently
of the full CSP/mixed-proof lane. Dispatch it with
`gh workflow run ci.yml --ref <source-ref> -f gate=focused-cpu -f cpu_lane=ethereum_receiver_releasefast`.
It preserves both receiver roots, their floors and all physical assertions.
It is marked hosted-only because the physical ReleaseFast case exceeds the
local compiler-memory cap. It does not replace complete product acceptance.
