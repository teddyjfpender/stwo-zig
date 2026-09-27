# Preserve streaming LDE preparation arenas

Streaming PCS commits now retain preparation arenas and their allocation alignment through sampling, quotient evaluation and decommitment. A mixed allocation list owns either a full aligned batch arena or an individually allocated column; column descriptors are views. Final tree transfer and failure cleanup preserve allocator custody. Explicit file-backed retained storage still detaches and relocates independent columns. Coefficient arena preservation from the preceding experiment remains enabled in both arms.

The control `STWO_ZIG_DETACH_STREAMING_LDE=1` restores LDE detachment. This is a shared core policy, with no workload-specific selection. Source changes relative to the preceding streaming-coefficient-arenas checkpoint are retained in `source/`.

ReleaseSafe qualification passed 25/25 focused tests: mixed-height FFT/Merkle/value parity, streaming ownership, allocation-failure injection, borrowed caller ownership, shared tree lifetimes and retained/file-backed storage. Both ReleaseFast product builds passed. Frozen binaries and matching Metal bundle are in `candidate-products`.

The same-binary comparison uses canonical 70 queries / 26 PoW bits, 16 workers and the ECDSA precompile. Three measured samples per arm, fixed control/candidate order, no explicit warmup. Every retained artifact must match preceding full-suite proof hashes and freshly verify. These complete-transaction timings include admission, encoding and fresh verification, and are not a replacement full suite.

## Quotient diagnostic

Separate one-sample diagnostic runs both verified in process and matched canonical proof bytes. ECDSA quotient source runs fell 1,305 → 279, but quotient GPU time was 195.283 → 198.056 ms and wall time 245.580 → 244.987 ms. Both selected GPU-flat with zero resident sources, 238,013,312 raw bytes, 44,866 views and 524,288 rows. These runs are excluded from performance medians. This evidence does not support fragmentation as the dominant remaining ECDSA quotient cost.

The next candidate is grouped quotient evaluation for flattened inputs: the existing grouped-partial optimization in `runtime/quotients.m` is gated on resident multi-source input, while these proofs select the flat input path. Investigate the actual per-batch work and reuse existing checked grouping and scratch bounds rather than changing proof parameters. This is a research direction, not an implemented or measured improvement.

| Workload | CPU control → candidate s | Metal control → candidate s |
| --- | ---: | ---: |
| ecdsa_secp256k1-32 | 1.188439 → 1.194217 | 1.479434 → 1.493740 |
| sha256-128 | 2.802411 → 2.857686 | 2.737400 → 2.636422 |
| sha256-2048 | 5.074681 → 5.160547 | 4.898770 → 4.752674 |
| keccak-128 | 4.818844 → 4.852295 | 4.603177 → 4.406811 |

All 48 measured proofs verified in process, and all 16 retained arm artifacts freshly verified with unchanged proof bytes. The larger Metal cases improved roughly 3–4% in this fixed-order sample; this is modest evidence, not a claimed recovery or order-of-magnitude improvement. CPU differences are small and slightly slower; this sampling protocol does not establish a reliable CPU change. ECDSA did not improve. Footprint remained approximately stable (Metal ECDSA 1.313 → 1.290 GB; SHA-2048 7.967 → 7.964 GB). Original CSP performance remains unrecovered.

Canonical base child/parent qualification passed (`canonical-parent.log`), both at 70 queries / 26 PoW bits with independent verification. Transcript replay, fixed-plan reuse, worker rekey and output lifetime checks passed. This is functional qualification, not a matched recursion timing result.

Implementation direction for the next quotient experiment: `stwo_zig_prepare_raw_quotient_views_for_single_source` already produces the same checked resident-view descriptor format with source_slot=0. Feed those descriptors/batch offsets into the existing grouping planner when using a flat source. Bind the flat buffer in the grouped kernels, preserve the 1 GiB temporary cap and checked work comparison, and preserve direct/segmented fallback paths. Qualify raw outputs against CPU with the existing quotient parity hook as well as canonical proof bytes; receipt/path reporting must reflect the selected execution. No change has yet been made to that runtime.

