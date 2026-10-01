# Circuit recursion CUDA

This package contains the native CUDA circuit prover for the Starknet recursion stack. It implements the four circuit commitment trees, transcript, AIR evaluation, OODS, DEEP quotient, packed-leaf FRI, both proof-of-work grinds, and all Merkle openings in one resident proof transaction. The host prepares authenticated geometry and input data before the transaction and independently verifies the single published proof afterward. The proving stages have no CPU PCS fallback.

The circuit protocol matches `starkware-libs/proving@5a7c5ede4299c91a61df19a07cba4f7502c14230`. In particular, a fold step of four packs four FRI rows into each Merkle leaf. The GPU commitment builder, opening planner, and proof decoder use that same layout. The independent verifier and `CircuitSerialize` SHA-256 comparison are mandatory benchmark gates.

## H100 qualification, 1 October 2026 UTC

Single ReleaseFast runs on one H100 SXM (`sm_90`), canonical circuit FRI security (70 queries, 26 PoW bits, fold step four, blowup one). Inputs were built and preprocessed in the host harness before the timed `prove` call. `prove` includes ingress, the complete resident GPU proof, the one terminal read, and decoding; independent native verification is timed separately. No queueing or PIE construction is included. These are individual measurements, not medians.

| R7 circuit | Channel profile | Prove | Verify | Peak device arena | Rust verifier-proof SHA-256 |
| :--- | :--- | ---: | ---: | ---: | :--- |
| Fibonacci | internal | 0.766 s | 0.143 s | 1.466 GB | `3321ee9222a294f77305dd295bd2d5c1cef49878b2f6964d28d23a9b28d41a55` |
| Fibonacci | root | 0.610 s | 0.145 s | 1.466 GB | `875b48eb210f9b3833b65bc2af7e3dc5c77436b9e3c91c705214f2748f561aa8` |
| Blake G gate | internal | 0.556 s | 0.141 s | 1.465 GB | `b5f3f88e8784978a3699ab528b9a07ae34a4c5f257aad99d18b5cdbde5dbb222` |
| Blake G gate | root | 0.560 s | 0.138 s | 1.465 GB | `fc4bd58fa88606312b45e18645e8ba78f5fcd6269da3610783bf962c555a1884` |

All four proofs passed independent native verification, matched the pinned Rust `CircuitSerialize` byte length (474,184) and digest, and reported one terminal proof transfer with zero CPU fallback or runtime-compilation attempts. The fixed proof transport is 3,295,392 bytes after bounding FRI Merkle staging against four-row packed leaves, down from 9,119,392 bytes with the earlier conservative bound. The measured device stages total roughly 50–60 ms per run. The gap to 0.56–0.77 s is predominantly host launch, preparation, and transaction overhead, and is the first optimization target. The 1.47 GB result is the allocated resident arena for these R7 shapes, not a full PIE-to-root pipeline peak.

To reproduce on an NVIDIA host, use the root build product and then the benchmark executable:

```sh
zig build benchmark-circuit-cuda-resident -Doptimize=ReleaseFast \
  -Dcuda-nvcc=/usr/local/cuda/bin/nvcc \
  -Dcuda-host-cxx=/usr/bin/g++ \
  -Dcuda-host-runtime=/usr/lib/x86_64-linux-gnu/libstdc++.so.6 \
  -Dcuda-host-unwind-runtime=/usr/lib/x86_64-linux-gnu/libgcc_s.so.1 \
  -Dcuda-ar=/usr/bin/ar -Dcuda-home=/usr/local/cuda \
  -Dcuda-library-dir=/usr/local/cuda/lib64 -Dcuda-arch=sm_90
LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH:-} \
  ./zig-out/bin/stwo-circuit-cuda-resident-bench fibonacci internal \
  vectors/circuit/r7/prove_profiles.json
```

Use `fibonacci` or `blake_g_gate` as the circuit and `internal` or `root` as the channel profile. The command exits nonzero on an invalid proof, any nonresident proof event, or a Rust digest mismatch. Local shape, binding, emulation, and decoder checks run with `zig build --build-file src/integrations/circuit_cuda/build.zig test -Dtest-filter=resident -Doptimize=ReleaseSafe`.

## Pipeline status

The standalone circuit proving stages are GPU resident and qualified above. The existing `circuit-recursion-cuda-hybrid` CLI is a historical baseline: its circuit PCS and Cairo PIE proving still run on CPU, while only the two grinds run on CUDA. It must not be used as evidence for a full CUDA pipeline. The remaining integration is to feed verified CUDA Cairo PIE proofs into resident leaf wraps, use resident circuit proofs for each wrap and fold, and publish the root from the same fully GPU-proven recursion tree. The typed Cairo verified-proof sink exists, but that end-to-end command and its CPU/Metal/CUDA phase comparison are not yet qualified.

For context, the earlier two-PIE CPU pipeline took 106.126 s and Metal took 75.979 s on the M5; the old H100 hybrid diagnostic took 296.902 s because its Cairo, wrap, and fold PCS ran on the host. Those figures use the complete adapted-input-to-root scope and are not comparable to the standalone 0.59–0.74 s circuit proofs above. The next benchmark must report Cairo PIE proving, each wrap, each fold/root proof, verification, ingress, peak memory, and overall wall time separately.
