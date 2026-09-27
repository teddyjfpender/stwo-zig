# Tiled shared witness column projection

The preceding CPU Keccak sampling report (`../2026-09-23-witness-profile`) identifies small-chunk logical-row projection as a major witness-preparation stack. The old small-chunk path copied a logical row and scattered it across every destination column before advancing to the next row, cycling across many independent large buffers.

The shared framework writer now computes physical row indices in tiles of at most 128 and writes one destination column at a time. Scratch is a fixed 128-index array; work remains proportional to the supplied chunk, with no full-domain scan for small chunks. The existing full-domain projection is unchanged. The research control `STWO_ZIG_ROW_MAJOR_WITNESS_COPY=1` selects the old copy order. Proof layout, padding, constraints, parameters and transcript semantics are unchanged.

Focused ReleaseSafe projection tests pass. They compare the destination against the independent inverse domain mapping, including every small-log subrange and wide 140-field rows with 129-, 255- and 511-row chunks, nonzero offsets and untouched sentinels. Tests cover both main and fixed projection. Both ReleaseFast builds passed. All 48 measured proofs verified in process; all 16 retained artifacts freshly verified with unchanged preceding proof hashes.

The harness uses the same frozen binary for both arms, canonical 70 queries / 26 PoW bits, 16 workers and ECDSA precompile. Three samples per arm, fixed control/candidate order and no explicit warmup. Every retained artifact must match the preceding full-suite proof hash and freshly verify. Complete transaction includes admission, encoding and fresh verification; this is not a new full-suite result.

| Workload | CPU row-major → tiled s | Metal row-major → tiled s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.133750 → 1.111691 | 1.232744 → 1.122357 |
| sha256-128 | 2.669495 → 2.501617 | 2.581133 → 2.412677 |
| sha256-2048 | 4.827809 → 4.867072 | 4.707550 → 4.826029 |
| keccak-128 | 4.600288 → 4.609555 | 4.440568 → 4.411457 |

ECDSA witness medians fell CPU 0.139971 → 0.089979 s and Metal 0.138310 → 0.090817 s. SHA-128 witness fell CPU 0.801336 → 0.650418 s and Metal 0.822144 → 0.661507 s. Large SHA/Keccak witness and total differences are small/mixed; this is not evidence of a broad recovery. No new recursion latency or full-suite result is claimed.

On the original execution+witness+proving scope, candidate ECDSA medians are CPU 0.949722 s / Metal 0.948268 s, still above original means of about 0.882 / 0.864 s. Sampling protocols differ. Keep original-suite performance as the success criterion.

The sampling report also identifies generic BLAKE3 compression/update as substantial CPU work. Local Zig 0.15.2 std/crypto/blake3.zig selects CompressVectorized only for x86_64 (lines 203–206); the ARM host uses CompressGeneric. Investigate shared batched/SIMD commitment hashing with exact streaming/chunk-boundary parity rather than assuming native BLAKE3 throughput is already optimized. No such optimization is implemented or measured here.
