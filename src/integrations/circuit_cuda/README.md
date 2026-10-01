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

For repeated builds on one GPU host, set `STWO_CUDA_ARCHIVE_CACHE` to a persistent absolute directory before the build. The native archive cache keys only authenticated native/AOT source and toolchain identity, so Zig-only recursion edits can reuse the expensive CUDA cubins even when the product executable must be relinked. Preserve that directory across ephemeral pod lifetimes if using RunPod; otherwise the generated Pedersen kernel can add several minutes to each cold build.

Use `fibonacci` or `blake_g_gate` as the circuit and `internal` or `root` as the channel profile. The command exits nonzero on an invalid proof, any nonresident proof event, or a Rust digest mismatch. Local shape, binding, emulation, and decoder checks run with `zig build --build-file src/integrations/circuit_cuda/build.zig test -Dtest-filter=resident -Doptimize=ReleaseSafe`.

## PIE-to-root pipeline

`circuit-recursion-cuda-resident` builds `stwo-circuit-recursion-cuda` with the full Cairo and circuit CUDA archive. Its `leaf-wrap` command proves the adapted Cairo PIE on CUDA, verifies its published proof, constructs the leaf verifier circuit, proves that circuit on CUDA, and writes the serialized leaf. Its `fold-tree` command builds the canonical multiverifier and proves every internal fold and the root on CUDA. Host-side circuit construction, proof verification, and wire conversion remain; neither command calls a CPU STARK prover. The older `circuit-recursion-cuda-hybrid` is retained as a separate historical comparison.

The continuous-PIE benchmark driver is `tools/starknet-block-collector/circuit_pipeline.py --backend cuda-resident`. It checks block/root continuity and PIE digests, runs both commands, records Cairo receipt and wrap/fold wall time, and compares all three root files with the pinned Rust reducer when requested. `--adapted-dir` reuses an already adapted, separately authenticated input set to avoid rebuilding the Rust adapter on the GPU host. The reused input and preimage digests are written into the receipt. Qualify an end-to-end result only after the resident Cairo receipt, every circuit proof's resident verdict and native verification, and Rust root equality all pass.

The dedicated package build check is `zig build --build-file src/integrations/circuit_cuda/build.zig circuit-cuda-resident-pipeline-check -Doptimize=ReleaseFast`. The full Linux GPU product can be built with `zig build circuit-recursion-cuda-resident -Doptimize=ReleaseFast` and the same CUDA toolchain flags shown above.

The Cairo CUDA product requires an absolute `STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS` path. Generate the canonical artifact on the GPU host with `zig build cairo-preprocessed-export -Doptimize=ReleaseFast` followed by `zig-out/bin/cairo-preprocessed-export /absolute/path/preprocessed.bin canonical`. The exporter is deterministic: the 2.02 GiB canonical artifact produced on the M5 for this run had SHA-256 `4d4fda06dfa3bca19554510a158f6c50abad06a74d29c17885ed4cbb88ada34d`. The adapted PIE inputs can be regenerated by the pinned Rust oracle or reused with the driver's `--adapted-dir`; the latter verifies and records their digests.

The first complete two-PIE run on an H100 SXM 80 GB (`sm_90`, ReleaseFast, 1 October 2026 UTC) used the continuous mainnet PIEs `15627902-15627904` and `15627905-15627907`, the production circuit registry, and already adapted inputs. It proved both Cairo executions and both leaf wrappers on CUDA, then proved the root fold on CUDA. Every circuit proof passed the independent native verifier with no CPU proving fallback. The resulting `root.proof`, `root_outputs.json`, and `root_packed.json` are byte identical to the pinned Rust reducer; the root proof SHA-256 is `9093f941c4a9144fd653441c582cc0921bac8431df8df46bdd556b8e661af724`.

| Stage | Wall time | Resident circuit prove | Circuit verification | Device arena |
| :--- | ---: | ---: | ---: | ---: |
| PIE `15627902-15627904`: Cairo prove | 4.984 s | — | — | 51.507 GB planned Cairo arena |
| First leaf wrap | 6.289 s | 2.328 s | 1.702 s | 28.124 GB |
| PIE `15627905-15627907`: Cairo prove | 4.511 s | — | — | 50.894 GB planned Cairo arena |
| Second leaf wrap | 6.290 s | 2.855 s | 1.442 s | 28.124 GB |
| Root fold, including circuit build | 9.021 s | 3.003 s | 1.477 s | 28.133 GB |
| Adapted input to root | **32.308 s** | — | — | 5.044 GB peak host RSS |

These are one-run times, excluding PIE execution, Rust adaptation, queueing, and build time. The Cairo proof itself executes and decodes in 0.467/0.476 s; Cairo ingress takes 4.460/3.979 s, including about 2.1 s of static initialization per separately launched PIE. The default driver starts a new process for each leaf, so it cannot reuse the Cairo runtime or its preprocessed snapshot. The circuit timings include roughly 44.5 million variables per wrap; the fold log attributes 1.475 s to root circuit construction and 4.480 s to proving plus verification. Device arena figures are reserved/planned extents, not a sampled whole-device peak; the latter remains to be measured. The Cairo receipt currently labels standalone Rust verification pending, while the aggregated root files have exact Rust parity.

The qualified Cairo receipts also report 2.551/2.520 GB of host-to-device ingress traffic and about 2.240 GB of device-to-device ingress work for each PIE. The ingress stage's 2.452/2.415 s elapsed counters include host activity, so they are not isolated GPU transfer times. The next run's static-phase timers distinguish initial upload, loading the fixed coefficient artifact, and materializing its base evaluations before changing the transfer design.

The follow-up `--cuda-batch` driver mode sends distinct leaves to `leaf-wrap-batch` in one process. Cairo and circuit proofs share one CUDA runtime and loaded modules. The completed Cairo arena is released before its circuit wrap so the roughly 51 GB and 28 GB arenas do not remain allocated together. This means the batch mode currently forfeits Cairo prepared-arena/static-snapshot reuse; its expected gain is context/module reuse and the checked leaf-topology cache. Each PIE still gets an independent proof, verification, wrap, and receipt. These two leaves have the same topology key. This mode passes the local compile gate but does not yet have a GPU parity or timing result. Compare it against the qualified 32.308 s run before claiming a gain.

An experimental `--cuda-static-image` option alongside `--cuda-batch` retains the first PIE's validated fixed coefficients in a separate process-owned CUDA allocation (`STWO_CAIRO_CUDA_STATIC_IMAGE=1` at the product level). Once that Cairo proof verifies, later PIEs with the same coefficient layout restore the exact words device-to-device; the large proof arena can still be released before each wrap. The image is keyed by the artifact path, fixed-column identities and prepared commitment identity, and is freed before the runtime closes. It adds approximately 2.17 GB of device residency, so leave it disabled until a paired H100 run confirms exact proof/root parity, lower wall time and an acceptable sampled peak. The driver records the option in its receipt. Local lifecycle and copy tests pass; there is no GPU timing result yet.

The sanitized benchmark receipt is `vectors/reports/recursive-product-20260918/cuda-resident-pipeline-h100-20261001/receipt.json`; it records input, binary, registry, leaf, and root digests alongside the phase and memory figures.

A second, locally compiled optimization passes the registry-bound leaf root or independently built fold root to the resident circuit prover and verifier. The verifier still compares that expected root with tree zero of the GPU proof. This avoids recomputing the same large preprocessed CPU commitment twice for each production circuit proof; the exact time saving and final proof parity await a GPU run. Standalone R7 benchmarks retain the original root calculation when no expected root is supplied.

The next GPU comparison can add `--sample-device-memory` to the pipeline driver. It samples whole-device `nvidia-smi` used memory every 250 ms and records both idle and peak values; this is distinct from the planned arena extent and may include other GPU processes. The driver also records per-proof plan, static hash, ingress, schedule, finish, and decode timings to identify the remaining circuit cost.

Each new pipeline receipt also carries Cairo CUDA ingress traffic, persistent and peak live bytes, kernel launches, and ingress-stage elapsed time. The driver rejects any Cairo receipt whose provider is not NVIDIA CUDA, reports a CPU fallback, or lacks its single terminal proof read. This is the provenance gate for comparing default batch mode with `--cuda-static-image`.

For context, the earlier two-PIE CPU pipeline took 106.126 s and Metal took 75.979 s on the M5; the old H100 hybrid diagnostic took 296.902 s because its Cairo, wrap, and fold PCS ran on the host. Those figures use the complete adapted-input-to-root scope and are not comparable to the standalone 0.59–0.74 s circuit proofs above. The next benchmark should repeat the complete H100 run with sampled whole-device peak, the batch mode, phase timers, and exact Rust root comparison.
