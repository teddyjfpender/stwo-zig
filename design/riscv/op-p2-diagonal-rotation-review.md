# SIMD diagonal rotation: measured negative

Do not adopt this candidate. On the M5 Max, nine quiet interleaved rounds give the following medians for four-lane hashing. Every output checksum matches.

| Message shape | Original | Rotation candidate | Ratio |
|---|---:|---:|---:|
| Node, 18 words | 80.128 ms | 80.223 ms | 0.9988× |
| Leaf, 64 words | 240.685 ms | 240.143 ms | 1.0023× |
| Leaf, 128 words | 442.304 ms | 441.136 ms | 1.0026× |
| Balanced 18/64/18/128 | 212.530 ms | 210.936 ms | 1.0076× |

Each sample hashes 32,768 groups of four messages. The baseline uses the original SIMD Ops without a power-of-two hook. The candidate uses exactly the same permutation parameters, absorption, padding and serialization, with 31-bit rotations for diagonal entries 3..23. This measures the numeric hashing used by node/streaming-leaf paths; it does not include full PCS allocation, column gathering or worker scheduling. A gain below one percent here is insufficient evidence for adoption.

The baseline is not already strength-reduced: AArch64 assembly retains the diagonal MUL/SQDMULH pair and reduction. The candidate emits four instructions, SHL/BIC/USHR/OR, rather than the hoped-for three. It also changes a compact loop into an unrolled body: the permutation has 437 versus 581 static instruction sites, uses v0..v7 versus v0..v31, and grows its stack frame from 32 to 96 bytes for callee-saved registers. No loop stack spills were observed. Those static counts do not establish exact pipeline stalls, but they invalidate an instruction-count-only prediction.

An additional isolated permutation sample also moves only 1.0041×. That diagnostic was outside the coordinated quiet window and is not a second performance claim. It gives no support to blaming state transpose or sponge serialization for the absent gain. The unchanged canonical additions, matrix work, S-box chains and their scheduling remain substantial. Hardware-counter or Instruments evidence would be needed to identify the exact limiting dependency or execution port.

The candidate passes 22,344 diagonal edge/random checks, scalar lane parity, dense/pinned permutation vectors, all sponge domains, rate boundaries and state transfer. Parameter identity is unchanged. The default-absent operation stream remains 4040 events with SHA256 `8240740eb07c131ea9f8c41442be88c500367839c4afe02da46ba702f1615108`.

Production arithmetic has been restored exactly. The generic permutation file has no diff. Only useful parity coverage remains beside Sponge4. Reproduce the rejected experiment with `python3 scripts/bench_poseidon2_diagonal_rotation.py`; it copies a bounded source set, applies the candidate in a temporary directory, checks parity and interleaves both implementations in one binary. `--parity-only` skips timing. Establish a quiet machine before interpreting new timings.

The next concrete lever is fewer committed rows and columns: R7's dot provider and the serialized sponge frontier remove complete hashing, extension and opening work. They should take priority over another diagonal substitution. If the hash kernel is revisited, profile the unchanged matrix/reduction dependency chains and independent-state scheduling before choosing a new representation. This result changes no security profile and makes no heavy-block speed claim.
