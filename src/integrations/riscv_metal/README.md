# RISC-V Metal integration

This package binds the typed RV32IM frontend to the fail-closed Metal prover engine. The frontend owns execution and AIR semantics; the integration selects authenticated Metal proving and never substitutes the CPU backend after a runtime failure.

[`mod.zig`](mod.zig) exposes `MetalProverEngine`, RISC-V prove/verify entry points, stage recording, and the guest precompile adapter. The released Metal product and CSP benchmark route build from the repository root with `zig build stwo-riscv-metal` and `zig build riscv-csp-bench-metal` on a Metal-capable Mac with an authenticated AOT bundle.

The package's focused build graph retains device-free contract tests, canonical CSP ECDSA proof/verify gates, and the shared detached SegmentV2 leaf and parent producers:

```sh
cd src/integrations/riscv_metal
zig build test -Doptimize=ReleaseSafe
STWO_CSP_FIXTURE_ROOT="$(pwd)/../../../vectors/riscv_csp" \
  zig build test-blake3-csp-ecdsa-jit -Doptimize=ReleaseFast
zig build build-recursive-segment-v2-detached-leaf-producer \
  build-recursive-segment-v2-detached-parent-producer \
  -Doptimize=ReleaseSafe
```

The authenticated CSP gate is `test-blake3-csp-ecdsa-aot -Dmetal-core-aot-bundle=<absolute-path>`. The CPU package supplies the independent detached leaf and parent verifiers. The Metal producers use the same typed SegmentV2 protocol and require an authenticated AOT runtime for a real proof. The old Stage101 and Ethereum block-v5 command graph is preserved on `archive/riscv-ethereum-block-v5-20261006` (commit `f374b1db6`) and is not a supported Metal product surface.

The package boundary is defined by [`build.zig`](build.zig), [`mod.zig`](mod.zig), and [`package.contract.json`](package.contract.json).
