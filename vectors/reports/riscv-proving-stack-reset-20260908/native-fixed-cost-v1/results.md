# Small native and recursive proof ladder results

All **66 retained runs passed**: 12 runs in each of the four instruction arms (1/4/16/64 retired instructions × three samples), plus nine per memory backend (1/4/16 addresses × three samples). Every log hash, retained binary hash, and arm source-patch hash was rechecked. Each log confirms 39 outer AIR components, exact 47-domain closure, canonical serialization, producer destruction, fresh decoded verification, truncated/trailing artifact rejection, and zero remaining native/outer producer allocator bytes. `summary.json` contains the checked per-run pins, extracted geometry, and medians.

The instruction optimization and original 66-run source checkpoint is `ad273a96721e1ccc1dd62a861fac11b44d0c680d`. Baseline reconstruction uses `a66af315ec1752635a2349b65b3a8daf6bee47e3` plus `baseline-source.patch` and `baseline-new-source/`. Instruction receipts were created before the final commit and therefore record the earlier HEAD plus their exact dirty source patch; the memory arms reuse the same pinned optimized binaries after the commit. Do not interpret the receipt HEAD alone as the complete build source.

Native queries remain 1, outer queries 3, PoW bits 0: these are development profiles, not production-security benchmarks. Native Metal runs use the authenticated AOT route and record actual dispatch. Fresh native verification and the outer proof remain CPU operations on both backends. The outer verifier consumes admitted native preparation; this is **native-assisted recursive verification**, not a detached key-only root. Each request proves one first native child and its outer proof; its 16-instruction continuation is executed and checked, not separately proved.

## Instruction ladder: medians of three

Request includes the complete process and its setup/teardown. Native prove/verify are timed call intervals. RSS is maximum process resident set size, not the allocator-tracked payload peak. Proof bytes are native / outer canonical artifact bytes. The detailed outer preparation and verification durations remain in `summary.json`.

| Native backend | Arm | Instructions | Request s | Native prove ms | Native verify ms | RSS MiB | Proof bytes native / outer |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cpu | baseline | 1 | 7.920 | 4462.876 | 867.347 | 990.34 | 24,790 / 89,462 |
| cpu | baseline | 4 | 8.851 | 5180.876 | 1017.676 | 990.64 | 26,555 / 90,878 |
| cpu | baseline | 16 | 8.908 | 5257.666 | 1028.024 | 990.64 | 27,032 / 92,201 |
| cpu | baseline | 64 | 8.963 | 5267.121 | 1041.413 | 990.97 | 27,068 / 87,283 |
| cpu | optimized | 1 | 4.794 | 2092.351 | 359.219 | 990.36 | 24,790 / 89,462 |
| cpu | optimized | 4 | 5.188 | 2376.558 | 415.737 | 990.72 | 26,555 / 90,878 |
| cpu | optimized | 16 | 5.212 | 2388.609 | 408.241 | 990.66 | 27,032 / 92,201 |
| cpu | optimized | 64 | 5.340 | 2418.518 | 443.795 | 990.98 | 27,068 / 87,283 |
| metal | baseline | 1 | 4.766 | 1198.694 | 862.643 | 532.80 | 24,790 / 89,462 |
| metal | baseline | 4 | 5.048 | 1244.631 | 1012.729 | 532.77 | 26,555 / 90,878 |
| metal | baseline | 16 | 4.817 | 1034.893 | 1013.182 | 532.78 | 27,032 / 92,201 |
| metal | baseline | 64 | 5.074 | 1280.657 | 997.080 | 534.27 | 27,068 / 87,283 |
| metal | optimized | 1 | 3.812 | 986.111 | 362.060 | 534.39 | 24,790 / 89,462 |
| metal | optimized | 4 | 3.954 | 1015.894 | 411.461 | 533.22 | 26,555 / 90,878 |
| metal | optimized | 16 | 3.966 | 1019.483 | 415.454 | 533.70 | 27,032 / 92,201 |
| metal | optimized | 64 | 3.978 | 1048.260 | 423.624 | 533.19 | 27,068 / 87,283 |

At 64 instructions:

- CPU: request time fell 40.4%, native proving 54.1%, and fresh native verification 57.4%. Outer transaction time fell 8.6%.
- METAL: request time fell 21.6%, native proving 18.1%, and fresh native verification 57.5%. Outer transaction time fell 10.3%.

The optimized diagnostic Metal profile reports **852.902 ms** native proving; the unprofiled 64-step median is **1,048.260 ms**. These are different observations, not interchangeable speed claims. Structured profiling also changes native host scheduling. The SIMD host optimization affects CPU verification and CPU outer work for both backends; these results do **not** establish faster Metal device kernels. Native CPU proving improves substantially while the native memory footprint remains broadly unchanged. Timing changes in the smallest rows should be read with only three samples and sequential arm execution in mind.

## Historical contiguous-word memory fixture: medians of three

Every case keeps 64 first-child instructions: 21 loads and 20 stores, using the same code/data lengths and varying only 1/4/16 distinct accessed addresses. The checked 16-step continuation adds five loads and six stores. This is an address-diversity experiment at fixed instruction count, not a larger block workload.

| Native backend | Addresses | Request s | Native prove ms | Native verify ms | RSS MiB | Proof bytes native / outer |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cpu | 1 | 5.108 | 2034.073 | 412.095 | 1011.84 | 29,023 / 91,820 |
| cpu | 4 | 5.103 | 2018.864 | 415.663 | 1011.81 | 29,062 / 91,302 |
| cpu | 16 | 5.074 | 1986.995 | 409.040 | 1011.77 | 29,030 / 89,813 |
| metal | 1 | 4.305 | 1168.447 | 408.887 | 537.80 | 29,023 / 91,820 |
| metal | 4 | 4.303 | 1145.836 | 417.785 | 538.78 | 29,062 / 91,302 |
| metal | 16 | 4.262 | 1087.668 | 409.753 | 538.72 | 29,030 / 89,813 |

## Actual geometry and padding floors

Every native trace contains exactly its requested retired rows (1/4/16/64 for the instruction ladder; 64 for memory). All four native commitment-tree heights remain `[21, 21, 21, 21]` across all 66 runs because the fixed lookup domains dominate. The instruction workload has 184 sparse-node Poseidon calls and native Merkle/Poseidon logs 8/8. All memory cases have 560 calls and logs 10/10; varying addresses within this fixture does not change those counts. Outer provider log remains 11, and outer row 35 remains log 16. The 560 calls split into 420 program nodes, 69 entry-memory nodes and 71 exit-memory nodes. Every case initializes the same 16 contiguous words (15 nonzero), then finishes with 16 nonzero words. This fixture is retained as valid proof evidence and superseded as the address-growth experiment by a zero-initialized, 128-byte-stride fixture. Thus the historical memory ladder is on a measured padding plateau; flat or slightly declining timings do not show that memory cost decreases with more addresses.

The following zero-based 39-entry vectors are extracted from the logs. Each vector is identical across its three repetitions and both backends; full per-case copies are in `summary.json`. Only one vector is needed per distinct shape:

- instructions 1: `[9, 10, 10, 8, 13, 13, 4, 4, 4, 4, 4, 10, 5, 4, 4, 10, 5, 7, 12, 8, 4, 7, 6, 8, 14, 7, 4, 5, 6, 10, 14, 8, 14, 8, 11, 16, 10, 6, 8]`.
- instructions 4, instructions 16, instructions 64: `[9, 11, 11, 8, 13, 13, 4, 4, 4, 4, 4, 10, 5, 4, 4, 10, 5, 7, 12, 8, 4, 7, 6, 9, 14, 7, 4, 5, 6, 10, 14, 8, 14, 8, 11, 16, 10, 6, 8]`.
- memory addresses 1, memory addresses 4, memory addresses 16: `[9, 11, 11, 9, 13, 13, 4, 4, 4, 4, 4, 10, 5, 4, 4, 10, 5, 7, 13, 8, 4, 7, 6, 9, 14, 7, 4, 5, 6, 10, 14, 8, 15, 8, 11, 16, 10, 6, 8]`.

Canonical proof byte sizes vary with the statement and openings even when the padded component shape is unchanged. All instruction proof sizes are preserved across baseline/optimized and CPU/Metal arms. No whole-block, second-child proof, production-security, or CSP regression result is inferred from this ladder; those have separate acceptance gates.
