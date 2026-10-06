# RISC-V CPU integration

This package binds the backend-neutral typed RV32IM frontend to the CPU prover engine. The RISC-V runner, witness, AIR, and statement rules remain owned by `src/frontends/riscv`; this package selects the CPU backend and supplies the proof adapter used by the released CPU product and CSP benchmarks.

The public module is [`mod.zig`](mod.zig). Its supported surface consists of `CpuProverEngine`, native proof and verification entry points, the Poseidon2 guest profile, the CSP-compatible Ethereum guest proof artifact, and the generic recursive FRI outer verifier. The Ethereum guest profile remains because CSP ECDSA uses it. It is distinct from the archived Ethereum **block** proving experiment.

`recursive_segment_v3_native_ingress.proveAndVerify` accepts one real leaf-local runner segment with a global V3 span statement. It projects that segment into the bounded V2 AIR, serializes and freshly verifies its Poseidon2 native proof, then checks a `VerifiedLinkV3` against the global metadata. The returned owner retains proof bytes and the verified capture. This is a native leaf ingress; no detached recursive circuit yet constrains the V3 global position or link. It does not authorize a long-run root proof by itself.

The CPU package also builds four detached SegmentV2 tools. They prove and verify bounded execution leaves and parent nodes; they do not claim whole-block memory/provider closure:

```sh
cd src/integrations/riscv_cpu
zig build build-recursive-segment-v2-detached-verifier \
  build-recursive-segment-v2-detached-parent-verifier \
  build-recursive-segment-v2-detached-leaf-producer \
  build-recursive-segment-v2-detached-parent-producer \
  -Doptimize=ReleaseSafe
```

Run `zig build test -Doptimize=ReleaseSafe` for package contracts and the retained detached-protocol tests. The genuine child-capture test additionally requires `STWO_SEGMENT_V2_CHILD_BUNDLE`, `STWO_SEGMENT_V2_CHILD_KEY_SHA256`, and `STWO_SEGMENT_V2_CHILD_EXPECTED_WIRE` pointing to the admitted fixture. Focused proof/verify checks are `test-secp256k1-precompile-proof` (set `STWO_CSP_FIXTURE_ROOT` to the absolute `vectors/riscv_csp` directory), `test-segment-v2-native-proof`, `test-segment-v3-native-ingress`, and `test-universal-typed-proof`. The V3 check uses an actual two-segment guest ELF and rejects a shifted global position after fresh native verification. Use [`scripts/riscv_recursive_product.py`](../../../scripts/riscv_recursive_product.py) for the end-to-end 1/2/4/8-segment development gate. The released CPU product and CSP benchmark route build from the repository root with `zig build stwo-zig-riscv-cpu` and `zig build riscv-csp-bench`.

The former Ethereum block-v5 architecture, provider experiments, and their build commands are preserved at `archive/riscv-ethereum-block-v5-20261006` (commit `f374b1db6`), rather than part of the supported package. A future block pipeline must define and verify its complete block statement, including memory and provider closure, before it is exposed here.
