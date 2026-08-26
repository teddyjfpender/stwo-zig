# `stwo_riscv_metal_integration`

`stwo_riscv_metal_integration` binds the backend-neutral RV32IM frontend to the
fail-closed Metal commitment engine. It preserves frontend-owned execution and
AIR semantics while selecting a manifest-bound Metal proving transaction.

| Property | Value |
| :--- | :--- |
| Version | `0.2.0` |
| Layer | `integration` |
| Owner | `riscv-metal-integration` |
| Public Zig module | `stwo_riscv_metal_integration` |
| Focused CI host | macOS |
| Product state | Parity-gated |

The [package contract](package.contract.json) and [mod.zig](mod.zig) define the
reviewed package boundary.

## Architecture

```mermaid
flowchart LR
    ELF --> Frontend[`stwo_riscv_frontend`]
    Frontend --> Trace[Execution trace and AIR]
    Metal[`stwo_metal_backend`] --> Engine[`MetalProverEngine`]
    Trace --> Engine
    Engine --> Verify[Proof verification]
    Engine -. runtime failure .-> Error[Fail closed]
```

The integration never substitutes the CPU commitment backend when Metal
initialization, admission, or execution fails.

## Public API

```zig
const riscv_metal = @import("stwo_riscv_metal_integration");

var statement = try riscv_metal.proveAndVerifyElf(
    allocator,
    elf_bytes,
    max_steps,
    pcs_config,
);
defer statement.deinit(allocator);
```

| Export | Responsibility |
| :--- | :--- |
| `MetalProverEngine` | Stable transaction instantiated with `MetalCommitBackend` |
| `guest_precompile` | Exact authenticated-AOT admission for `rv32im-zkvm-poseidon2-v1` |
| `proveRiscV` | Prove an execution trace |
| `proveRiscVWithRecorder` | Prove with stage-profile recording |
| `proveRiscVWithPublicData` | Bind explicit public data |
| `verifyRiscV` | Verify proof, statement, and interaction claim |
| `proveAndVerifyElf` | Execute, prove, and verify an ELF |
| `riscv_polynomial_codegen` | Authenticated RISC-V Metal polynomial codegen assets |

## Dependencies

- `stwo_riscv_frontend`
- `stwo_core`
- `stwo_metal_backend`
- `stwo_prover_api`
- `stwo_prover_engine`

`stwo_cpu_backend` is intentionally absent.

## Build, test, and run

The focused package step requires macOS and the Apple Metal SDK. It executes the
device-free contract suite; the real-device proof skips unless its dedicated
lane supplies a bundle:

```sh
zig build test --build-file src/integrations/riscv_metal/build.zig -Doptimize=ReleaseSafe -j2
```

Run the explicit integration acceptance lane on a Metal-capable Mac:

```sh
zig build test-authenticated-aot --build-file src/integrations/riscv_metal/build.zig -Doptimize=ReleaseFast -Dmetal-core-aot-bundle=/absolute/path/to/core -j2
```

Build and exercise the assembled product on a Metal-capable Mac:

```sh
zig build stwo-riscv-metal -Doptimize=ReleaseFast -Dmetal-core-aot-bundle=/absolute/path/to/core
zig build test-riscv-metal -Doptimize=ReleaseFast -Dmetal-core-aot-bundle=/absolute/path/to/core
zig build test-riscv-metal-guest-poseidon2-aot -Doptimize=ReleaseFast -Dmetal-core-aot-bundle=/absolute/path/to/core -j2
zig build riscv-csp-bench-metal -Doptimize=ReleaseFast -Dmetal-core-aot-bundle=/absolute/path/to/core
```

Use `zig-out/bin/stwo-zig-riscv-metal` for the installed CLI; inspect its help
or application registry for the exact current flags. The root build consumes
the explicit retained bundle supplied with
`-Dmetal-core-aot-bundle=<absolute-path>` and installs that authenticated
closure beside the CLI.

The installed CLI keeps the existing base commands unchanged. The only guest
extension routes are explicit:

```sh
zig-out/bin/stwo-zig-riscv-metal guest-poseidon2-prove \
  --elf guest.elf --input input.bin --backend metal --max-steps 900000 \
  --output proof.stw --report-out proof-report.json
zig-out/bin/stwo-zig-riscv-metal guest-poseidon2-verify \
  --artifact proof.stw
```

Both default to the secure PCS policy. `--protocol functional` is an explicit
development/evidence policy and is labelled `functional-development` in the
receipt. No command claims generic guest or generic precompile support.

## Contract and invariants

- API signature: the Metal engine satisfies the shared prover transaction.
- Behavioral invariant: its backend type is exactly `MetalCommitBackend`, so
  the integration cannot select CPU.
- Runtime invariant: prove and bench initialize only from the manifest-bound
  authenticated metallib before warmup; source JIT is not a product fallback.
- Evidence invariant: both resident semantic and lookup polynomial batches must
  dispatch for every verified sample, with zero eligible-route declines.
- Guest-profile invariant: the final caller/provider components carry the exact
  version-1 semantic identities. They intentionally use the reviewed generic
  evaluator because each combines direct and LogUp constraints; that placement
  is not a backend fallback. Every backend fallback counter must remain zero.
- Publication invariant: the product independently verifies the bounded binary
  profile artifact and cleanly shuts down the authenticated runtime before the
  proof becomes visible.

Device acceptance must also prove deterministic parity, real Metal execution,
zero fallback, runtime identity, and successful independent verification.

## Change checklist

1. Keep CPU imports and fallback paths out.
2. Reuse frontend statements and semantics without duplication.
3. Treat runtime admission and telemetry as correctness evidence.
4. Test missing-device and runtime-failure paths.
5. Run focused compile checks and real-device RISC-V Metal gates.

## Related documentation

- [RISC-V frontend](../../frontends/riscv/README.md)
- [Metal backend](../../backends/metal/README.md)
- [CPU integration](../riscv_cpu/README.md)
- [RISC-V Sail differential gate](../../../conformance/riscv-sail-differential-gate.md)
- [Repository RISC-V guide](../../../README.md#risc-v-frontend)
