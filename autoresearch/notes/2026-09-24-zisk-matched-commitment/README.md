# Matched commitment systems benchmark — 2026-09-24

Latest retained optimization: [short-message BLAKE3 results](optimization/README.md). The tables below preserve the original baseline.

This measures a complete commitment subsystem: hash identical input rows, allocate and build a binary Merkle tree, extract 70 authentication paths, authenticate those paths, and free the tree. It is not a full STARK proof or recursion benchmark.

## Contract and limitations

- Both arms receive exactly the same canonical GL64 little-endian bytes and use ZisK’s BLAKE3 digest canonicalization and binary-tree protocol. All nodes, roots, and paths match byte for byte. Both verifiers accept the other implementation’s paths and reject corrupted paths and roots.
- Local uses the actual `MerkleProverLifted.fromOwnedLeaves` production tree builder with a **research-only peer-protocol hasher**. Production STWO domain separation is unchanged. This isolates implementation costs; these are not native STWO proof timings.
- Peer uses pinned proofman `d485fac207679076958b502554fb595568c2f954`, actual `Blake3Goldilocks::merkletree` and `linearHash`.
- Opening extraction and authentication are benchmark adapters over actual tree layouts/hash implementations, not either system’s production proof parser or compressed multiproof codec. Exactly 70 fixed query indices; no transcript or PoW.
- One CPU worker each, ARM-native ReleaseFast/O3; peer portable C++ BLAKE3, no OpenMP parallel compilation, x86 SIMD, CUDA, or Metal. Local upper-layer worker override is explicitly one.
- Same M5 Max host, **battery** throughout; seven alternating-order samples after a warm-up pair. Results are not pooled with earlier AC campaigns.
- Wall time includes internal tree allocation/free and opening extraction; input generation, library loading, output buffer allocation and full-node qualification copies are excluded. Paths are verified before the timer stops. Same row-major input layout and byte widths in both arms.
- Initial input fixture and full-node qualification buffers remain resident in both arms; no peak-RSS conclusion is drawn.

## Results

Medians in milliseconds; total medians are measured directly, not sums of independent medians.

| Rows | Bytes/row | Local commit + open | Peer commit + open | Local verify | Peer verify | Local total | Peer total | Local relative time |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,024 | 32 | 0.259 | 0.213 | 0.095 | 0.088 | 0.354 | 0.301 | 1.177× |
| 65,536 | 32 | 9.253 | 8.538 | 0.094 | 0.087 | 9.347 | 8.625 | 1.084× |
| 1,048,576 | 32 | 147.725 | 134.813 | 0.135 | 0.127 | 147.860 | 134.942 | 1.096× |
| 65,536 | 256 | 18.762 | 20.863 | 0.107 | 0.103 | 18.880 | 20.973 | 0.900× |
| 65,536 | 1024 | 56.778 | 70.797 | 0.153 | 0.163 | 56.931 | 70.960 | 0.802× |

The measured crossover is useful: narrow rows trail the peer, while wider rows lead. This identifies the next profiling experiment: separate leaf hashing, upper-tree hashing, and allocator costs on the same fixture before attributing the gap to any one cause. It does not establish that allocation alone is responsible.

## Next system boundaries

1. Profile and optimize the narrow-row commitment gap against this fixed matched workload; qualify retained changes on native framed commitments too.
2. Complete polynomial commitment / FRI prover and verifier: identical polynomial statement and dimensions where mathematically possible, otherwise explicitly matched security and useful input size. Circle/M31 and multiplicative/GL64 native transforms cannot be labelled byte-identical work. Include commitments, transcript, folding, queries, proof encoding, verification, and peak memory.
3. Full hash AIR proofs at several batch sizes: same hash messages and outputs, setup excluded from warm proving but reported separately, matched soundness assessment. Peer proofman hash setup/proving keys still need generation. Existing local canonical Keccak timing is not a peer comparison.
4. Recursive aggregation at fan-ins 2/8/32: equivalent verified child statements and security, total latency/throughput/peak memory, then equal worker budgets. Neither the old native LDE stage comparison nor this commitment benchmark establishes full-prover superiority.

## Reproduction

Run `python3 autoresearch/notes/2026-09-24-zisk-matched-commitment/build.py`, then `run.py` from the same directory, then `report.py`. Build and timing scripts take the repository-wide serialization lock. Peer checkout is expected at the pinned research path in `build.py`. `results.json` preserves every sample, fixture/root hashes, binary hashes, and before/after power readings. `local-source.tar.gz` freezes source files without build caches. `SHA256SUMS` covers the retained artifacts.
