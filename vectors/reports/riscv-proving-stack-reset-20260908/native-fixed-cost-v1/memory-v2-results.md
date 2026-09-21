# Revised memory ladder: varying sparse-tree work at 64 instructions

All **18 new runs passed**: three repetitions at 1/4/16 addresses on each native backend. Log hashes, source patches, retained binaries, and build/run receipt agreement were checked. Every run records the 39-component outer proof, exact 47-domain closure, canonical serialization followed by producer destruction and fresh decoded verification, truncated/trailing artifact rejection, and zero tracked native/outer producer bytes after destruction. Metal runs additionally record actual device dispatch. The original `summary.json` and `results.md` retain their historical 66-run dataset unchanged.

These builds use `ad273a96721e1ccc1dd62a861fac11b44d0c680d` plus `memory-v2-source.patch`, SHA-256 `c0cddd93527a61df6ad35784e1415e0e1dc04612d96f5faba643f95d37e21523`. `memory-v2-cpu-binary.json` and `memory-v2-metal-binary.json` pin their build commands and binaries; `memory-v2-summary.json` records rechecked receipt/log hashes and all extracted measurements.

The initial contiguous-word fixture produced 560 sparse-node calls at every address count: its fixed 420 program calls plus 69 entry and 71 exit calls obscured the intended growth axis. Those proofs remain valid historical results. This revised fixture starts data at zero and spaces words 128 bytes apart, retaining the same program family, code/data lengths, and 64-instruction first segment. Its measured sparse-node calls now grow **450 → 473 → 569**. This supersedes the initial fixture as the memory-growth experiment; the two fixtures are not a before/after performance optimization comparison.

## Execution and geometry checks

Every first segment retires exactly 64 instructions, including 21 loads and 20 stores. Its entry has zero nonzero data words and its exit has exactly 1/4/16 nonzero words. The executed 16-instruction continuation adds five loads and six stores, retaining 1/4/16 nonzero words at both boundaries. First-segment distinct-address counts are 1/4/16; continuation counts are 1/4/6. Every log records stride 128 bytes and the checked state counts. The continuation is executed and validated, **not separately proved**: each request proves one native first child and its outer proof.

| Addresses | Sparse-node Poseidon calls | Native Merkle log | Native Poseidon log | Native trace rows | Native commitment-tree heights |
| --- | ---: | ---: | ---: | ---: | --- |
| 1 | 450 | 9 | 9 | 64 | `[21,21,21,21]` |
| 4 | 473 | 9 | 9 | 64 | `[21,21,21,21]` |
| 16 | 569 | 10 | 10 | 64 | `[21,21,21,21]` |

These counts and logs were observed in all three repetitions on both backends. The 16-address case crosses the hash-AIR padding threshold, while the native global commitment heights remain dominated by the fixed lookup-table floor. Outer row 35 remains log16 and the shared provider remains log11.

## Medians of three

Request time includes the entire process. Native verify uses CPU on both backends. RSS is process maximum resident set size; it is distinct from the caller-allocator payload tracker. Proof sizes are canonical native / outer bytes.

| Native backend | Addresses | Request s | Native prove ms | Native verify ms | RSS MiB | Proof bytes native / outer | Outer transaction ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cpu | 1 | 4.879 | 2010.265 | 419.448 | 1009.06 | 29,034 / 92,032 | 2256.998 |
| cpu | 4 | 4.907 | 2018.064 | 407.255 | 1009.06 | 29,085 / 89,467 | 2287.610 |
| cpu | 16 | 5.081 | 2030.077 | 412.350 | 1011.77 | 29,033 / 92,041 | 2440.033 |
| metal | 1 | 4.279 | 1339.244 | 408.716 | 535.20 | 29,034 / 92,032 | 2308.280 |
| metal | 4 | 4.077 | 1071.197 | 411.730 | 535.50 | 29,085 / 89,467 | 2366.234 |
| metal | 16 | 4.293 | 1099.468 | 409.261 | 538.45 | 29,033 / 92,041 | 2508.728 |

The CPU request median rises from 4.879 to 5.081 seconds as sparse-node work grows and the hash domain doubles. Metal request medians are 4.279/4.077/4.293 seconds and are not monotonic; three samples do not establish a timing growth law or decreasing cost with address count. The geometry change is directly measured even where global table floors and runtime variation mask it in elapsed time. This experiment does not measure a change to Metal kernels.

The zero-based outer component-log vectors below are identical across repetitions and both backends. Canonical proof sizes can differ despite equal padded shapes; size equality across backends is not a byte-for-byte proof identity claim.

- Addresses 1: `[9, 11, 11, 9, 13, 13, 4, 4, 4, 4, 4, 10, 5, 4, 4, 10, 5, 7, 13, 8, 4, 7, 6, 9, 14, 7, 4, 5, 6, 10, 14, 7, 15, 8, 11, 16, 10, 6, 8]`.
- Addresses 4, 16: `[9, 11, 11, 9, 13, 13, 4, 4, 4, 4, 4, 10, 5, 4, 4, 10, 5, 7, 13, 8, 4, 7, 6, 9, 14, 7, 4, 5, 6, 10, 14, 8, 15, 8, 11, 16, 10, 6, 8]`.

The unchanged profiles use native q1, outer q3, PoW0 and are development parameters. The outer verifier retains admitted native preparation: this is native-assisted recursion, not a detached key-only root. The new 18 runs neither prove a second child nor a whole block and do not replace the separate CSP regression gate. Artifact-negative claims here cover the recorded truncated/trailing codec cases, not every cryptographic public-statement mutation.
