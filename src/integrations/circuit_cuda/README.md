# Circuit recursion CUDA integration

This integration proves circuit-recursion statements on resident NVIDIA CUDA
hardware. It implements four commitment trees, transcript operations, AIR
composition, OODS, DEEP quotient, packed-leaf FRI, both proof-of-work grinds,
and Merkle openings. Host code authenticates geometry and inputs, constructs the
circuit, and independently verifies the published proof. Circuit PCS work has
no CPU proving fallback.

The proof protocol is pinned to
[`starkware-libs/proving@5a7c5ed`](https://github.com/starkware-libs/proving/tree/5a7c5ede4299c91a61df19a07cba4f7502c14230).
A fold step of four packs four FRI rows per Merkle leaf. Commitment, opening,
and decoding use the same layout. Independent verification and comparison with
the pinned Rust `CircuitSerialize` digest are required for qualification.

## Build and test

The owner-local test and compile checks do not require a GPU:

```sh
zig build --build-file src/integrations/circuit_cuda/build.zig test \
  -Dtest-filter=resident -Doptimize=ReleaseSafe
zig build --build-file src/integrations/circuit_cuda/build.zig \
  circuit-cuda-resident-pipeline-check -Doptimize=ReleaseFast
```

On an NVIDIA host, build the integrated product and R7 benchmark from the
repository root with explicit toolchain paths. `sm_90` selects the H100 used
in the retained measurements; select the host's actual SM target for a new
run.

```sh
zig build circuit-recursion-cuda-resident benchmark-circuit-cuda-resident \
  -Doptimize=ReleaseFast \
  -Dcuda-nvcc=/usr/local/cuda/bin/nvcc \
  -Dcuda-host-cxx=/usr/bin/g++ \
  -Dcuda-host-runtime=/usr/lib/x86_64-linux-gnu/libstdc++.so.6 \
  -Dcuda-host-unwind-runtime=/usr/lib/x86_64-linux-gnu/libgcc_s.so.1 \
  -Dcuda-ar=/usr/bin/ar -Dcuda-home=/usr/local/cuda \
  -Dcuda-library-dir=/usr/local/cuda/lib64 -Dcuda-arch=sm_90

LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH:-} \
  zig-out/bin/stwo-circuit-cuda-resident-bench fibonacci internal \
  vectors/circuit/r7/prove_profiles.json
```

The benchmark also accepts `blake_g_gate` and the `root` channel profile. It
fails on an invalid proof, nonresident proof event, or Rust digest mismatch.
Set `STWO_CUDA_ARCHIVE_CACHE` to a persistent absolute directory to reuse
source- and toolchain-bound cubins across Zig-only edits.

## PIE-to-root pipeline

`stwo-circuit-recursion-cuda leaf-wrap` proves an adapted Cairo PIE on CUDA,
verifies that Cairo proof, passes the decoded proof directly to the leaf
verifier circuit, and proves the circuit on CUDA. The integrated handoff
publishes a verified-sink Cairo receipt rather than a separate Cairo JSON.
The standalone `stwo-cairo-cuda prove` command still publishes canonical
Rust-verifier JSON and its own receipt.

`fold-tree` constructs the canonical multiverifier and proves each internal
fold and root on CUDA. Circuit construction, wire conversion, and independent
verification remain host operations. The historical
`circuit-recursion-cuda-hybrid` product is a separate CPU-PCS comparison, not
the resident result.

The [Starknet block collector](../../../tools/starknet-block-collector/README.md)
runs continuous PIEs with `circuit_pipeline.py --backend cuda-resident`. It
checks block continuity and input digests, records each Cairo, wrap, and fold
stage, and can compare the three root files with the pinned Rust reducer.
`--adapted-dir` reuses separately authenticated adapted inputs and records
their digests. The default driver launches a process per leaf;
`--cuda-batch` uses one runtime for distinct leaves. The optional
`--cuda-static-image` retains authenticated fixed Cairo coefficients between
batch leaves. The [H200 pipeline report](../../../vectors/reports/recursive-product-20260918/cuda-resident-pipeline-h200-20261001/README.md)
qualifies the combined shared-process canonical path against the pinned Rust
proof digests. Its runs do not isolate the effect of each option, and most do
not include sampled whole-device memory.

The CUDA Cairo product requires an absolute
`STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS` path. Generate a canonical artifact
on the GPU host with `zig build cairo-preprocessed-export -Doptimize=ReleaseFast`,
then run `zig-out/bin/cairo-preprocessed-export
/absolute/path/preprocessed.bin canonical`. The retained artifact's SHA-256
is `4d4fda06dfa3bca19554510a158f6c50abad06a74d29c17885ed4cbb88ada34d`;
a new run must authenticate its own artifact and inputs.

## Retained H100 qualification (1 October 2026)

The R7 measurements below are single ReleaseFast runs on one H100 SXM at
canonical circuit security: 70 queries, 26 PoW bits, fold step four, and
blowup one. Inputs and fixed preprocessing were prepared before the timed
`prove` call. The timer includes ingress, resident proving, the terminal
read, and decoding; native verification is separate. These are not medians.

| R7 circuit | Channel profile | Prove | Verify | Allocated device arena |
| :--- | :--- | ---: | ---: | ---: |
| Fibonacci | internal | 0.766 s | 0.143 s | 1.466 GB |
| Fibonacci | root | 0.610 s | 0.145 s | 1.466 GB |
| Blake G gate | internal | 0.556 s | 0.141 s | 1.465 GB |
| Blake G gate | root | 0.560 s | 0.138 s | 1.465 GB |

All four passed independent native verification and matched the pinned Rust
serialized length (474,184 bytes) and digest. The retained
[qualification receipt](../../../vectors/reports/recursive-product-20260918/cuda-resident-pipeline-h100-20261001/receipt.json)
records source and proof identities. The approximately 50–60 ms device-stage
sum leaves host preparation and launch overhead as a significant measured
cost. Arena sizes are planned allocations, not sampled whole-device peaks.

The first complete resident run used continuous mainnet PIEs
`15627902-15627904` and `15627905-15627907` under the production circuit
registry. It proved both Cairo leaves, both wraps, and the root fold on CUDA;
every circuit proof passed independent native verification. Its `root.proof`,
`root_outputs.json`, and `root_packed.json` matched the pinned Rust reducer
byte for byte. The root proof SHA-256 was
`9093f941c4a9144fd653441c582cc0921bac8431df8df46bdd556b8e661af724`.

| Stage | Wall time | Resident circuit prove | Circuit verification | Planned device arena |
| :--- | ---: | ---: | ---: | ---: |
| First Cairo leaf | 4.984 s | — | — | 51.507 GB |
| First leaf wrap | 6.289 s | 2.328 s | 1.702 s | 28.124 GB |
| Second Cairo leaf | 4.511 s | — | — | 50.894 GB |
| Second leaf wrap | 6.290 s | 2.855 s | 1.442 s | 28.124 GB |
| Root fold, including circuit build | 9.021 s | 3.003 s | 1.477 s | 28.133 GB |
| **Adapted input to root** | **32.308 s** | — | — | — |

The run excludes PIE execution, Rust adaptation, queueing, and build time;
its peak host RSS was 5.044 GB. The Cairo proof-execution/decode portions
were 0.467/0.476 s, with 4.460/3.979 s of cold ingress. The two Cairo proof
JSON files from this particular pipeline run were not retained for direct
Rust verification. A separate qualification of the same two adapted leaves
passed the pinned Rust verifier; see the
[Cairo CUDA qualification](../cairo_cuda/README.md#production-registry-mainnet-leaf-qualification-on-h100).
Future complete runs should retain both Cairo JSON files, require their pinned
Rust verification, and record sampled whole-device memory alongside the
planned arenas. The
[benchmark receipt](../../../vectors/reports/recursive-product-20260918/cuda-resident-pipeline-h100-20261001/receipt.json)
contains exact input, registry, leaf, and root digests and stage timings.

## Retained H200 pipeline qualification (1 October 2026)

The same two adapted PIEs were subsequently proved on an H200 SXM using a
shared process. The integrated canonical-root trials kept the runtime, AIR
catalog, and leaf topology alive across the pipeline. Both matched the pinned
Rust-qualified leaf proofs, root proof, root outputs, and packed-root digests.

| Configuration | Process wall | Adapted input to root | Cairo | Wraps | Fold |
| :--- | ---: | ---: | ---: | ---: | ---: |
| Shared process, separate fold | 17.565 s | 18.315 s | 7.041 s | 4.058 s | 5.608 s |
| Integrated canonical root, trial 1 | 15.195 s | 15.900 s | 7.321 s | 3.983 s | 2.904 s |
| Integrated canonical root, trial 2 | 15.323 s | 16.008 s | 7.349 s | 4.220 s | 2.914 s |

These configurations and hardware differ from the earlier 32.308-second H100
run, so the table does not measure a hardware-normalized speedup. The H200
trials above did not sample whole-device memory. An experimental compact
terminal-root trial reached 13.363 s process wall (14.143 s adapted input to
root), but changes the outer circuit: its root proof and packed-root digests
therefore differ. It requires a versioned registry and external verifier
acceptance before it can replace the canonical path. The complete
[H200 report](../../../vectors/reports/recursive-product-20260918/cuda-resident-pipeline-h200-20261001/README.md)
records the phases, comparison limits, and proof identities.
