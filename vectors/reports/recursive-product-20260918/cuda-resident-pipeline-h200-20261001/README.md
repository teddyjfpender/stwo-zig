# Two-PIE recursive CUDA pipeline, H200, 2026-10-01

This report measures adapted input to a single recursive root for continuous
Starknet PIEs `15627902-15627904` and `15627905-15627907`. The phase and digest
data are in [measurements.json](measurements.json). The original 32.308-second
H100 receipt is [here](../cuda-resident-pipeline-h100-20261001/receipt.json).
Its phases were Cairo proving 9.494 s, two circuit leaf wraps 12.579 s, root
fold 9.021 s, and process overhead 1.214 s. These are one H100 run, not a
distribution. The two PIEs were already adapted; these times exclude adapting
them and external queueing.

| Configuration | Process wall | Cairo | Wraps | Fold | Overhead |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original H100, separate processes | 32.308 s | 9.494 s | 12.579 s | 9.021 s | 1.214 s |
| H200, shared process, separate fold | 17.565 s | 7.041 s | 4.058 s | 5.608 s | 0.858 s |
| H200, integrated canonical root, two trials | 15.195–15.323 s | 7.321–7.349 s | 3.983–4.220 s | 2.904–2.914 s | 0.868–0.960 s |
| H200, integrated compact terminal root, warmed trial | 13.363 s | 6.987 s | 4.074 s | 1.340 s | 0.962 s |

The H200 rows are different software configurations on a different GPU from
the H100 row. The integrated canonical root keeps the CUDA runtime, authenticated
AIR catalog, and leaf topology alive through the fold. The terminal root also
sizes its own AIR to the two-child circuit, reducing padded variables from
45.1 million to 19.6 million and its GPU arena from 28.1 GB to 13.0 GB.
It uses a pinned preprocessed key to skip a second host commitment; the
independent resident verifier still checks the proof's commitment against it.
The terminal root GPU proof takes about 0.25 s. The full fold takes 1.34 s,
which includes building the verifier witness and output publication.

Canonical integrated trials matched the pinned Rust-qualified leaf, root
proof, outputs, and packed-root digests. Compact terminal trials matched both
leaf proof digests and root output digest; root proof and packed-root digests
change because the outer circuit changes. The compact option is experimental
and needs a versioned registry and an external verifier that accepts its new
key before it can become the default protocol.

The 3.23-second target (10× the H100 receipt) remains unmet. In the 13.363 s
trial, 6.987 s is Cairo proving and 4.074 s is leaf wrapping. Even removing
the fold entirely would leave 12.023 s. The next architectural work must
eliminate repeated Cairo static-image preparation, compile and replay the
fixed leaf verifier topology instead of reconstructing roughly 32 million
raw variables per PIE, and overlap independent PIE lanes within a bounded GPU
memory budget. Those changes require their own same-host, end-to-end proof
parity measurements; the current numbers do not establish a projected 10×.

The optional verifier-stage timer attributes about 0.74 s of the two leaf
circuit builds to Merkle decommitment and 0.39 s to FRI decommitment; leaf
padding adds about 0.47 s. The two resident leaf circuit proofs take about
1.0 s together. Two independent `leaf-wrap` processes retained their Cairo
arenas while wrapping, and one returned `InsufficientDeviceMemory`. Two
parallel single-item `leaf-wrap-batch` processes released each arena before
wrapping; both passed with the expected leaf digests, but the pair took
15.106 s, versus about 11.4 s for both leaves in the sequential shared-runtime
batch. Independent processes duplicate static setup and compete for the same
GPU. A parallel scheduler needs a shared prepared image and measured wins; the
current process-level overlap is a regression.

The H200 was a RunPod H200 SXM with 143,771 MiB device memory. The benchmark
used ReleaseFast, the production Cairo/circuit registry, and the same adapted
PIE inputs as the H100 receipt. The uninstrumented H200 trials above exclude
device-memory sampling; a separate sampled compact trial reported about
54.9 GB whole-device peak. The compact mode was invoked with
`--backend cuda-resident --cuda-batch --cuda-static-image --cuda-integrated
--cuda-compact-root` via `tools/starknet-block-collector/circuit_pipeline.py`.
