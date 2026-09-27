# Grouped quotient evaluation for flat inputs

The existing native-height grouping planner and GPU kernels were available only for resident multi-source inputs. Flat raw inputs already had validated descriptors in the same ABI with source_slot=0, but bypassed grouping. They now use the common planner and bind their flat buffer to the grouped kernels. The existing checked work estimate (at least 2x fewer evaluated cells) and 1 GiB temporary bound remain. Segmented/direct fallback paths remain available. The research control `STWO_ZIG_METAL_DIRECT_FLAT_QUOTIENT=1` restores direct flat evaluation without changing resident grouping. Diagnostic path labels now distinguish flat-partials from resident-partials; existing grouped work receipts account for either source custody.

The first diagnostic proof was byte-identical but failed the script's raw-output assertion: the existing parity hook did not run in the fused quotient/FRI route. That attempt is retained under `*-before-hook.*`, with its executable. The fused route now invokes the common backend parity helper after return-value cleanup owners are armed. This is an opt-in diagnostic; normal timing runs clear the parity flags.

## Qualification

The final ReleaseFast Metal build passed. Diagnostic ECDSA and SHA-256/2048 proofs used flat-partials, matched the preceding canonical proof hashes and verified in process. Their entire first quotient column matched the ordinary CPU reconstruction: respectively 2,097,152 and 8,388,608 M31 values. ECDSA used 58 groups / 32,244,928 scratch bytes; SHA used 45 groups / 124,400,704 bytes. These diagnostic runs are excluded from timings.

Same-binary measurements: 16 workers, canonical 70 queries / 26 PoW bits, ECDSA precompile, three samples per arm without explicit warmup, fixed arm order. Complete time includes execution, witness, admission, proving, encoding and fresh verification. All 24 measured proofs verified in process; all eight retained arm artifacts independently verified with unchanged prior-suite proof hashes.

| Workload | Metal direct → grouped s |
| --- | ---: |
| ecdsa_secp256k1-32 | 1.484736 → 1.260305 |
| sha256-128 | 2.580736 → 2.596795 |
| sha256-2048 | 4.620741 → 4.673753 |
| keccak-128 | 4.354035 → 4.358828 |

ECDSA's measured quotient-build/commit median fell 0.269095 → 0.092534 s; its complete transaction fell 15.1%. The isolated diagnostic GPU quotient time was 12.161 ms, compared with approximately 195 ms in the preceding direct-path diagnostics; that is not a matched end-to-end speedup. SHA/Keccak quotient stages improved by 15–27 ms, but their total timing differences are small and mixed. No overall improvement is established for those cases.

The scratch tradeoff is visible: measured process lifetime footprint rose by about 37 MB for ECDSA and about 124 MB for SHA-2048 and Keccak-128. The temporary bound is not a total process bound. CPU implementation is unchanged and was not rebuilt or benchmarked for this runtime-only experiment. Original CSP performance remains unrecovered; this is not a new full suite or a recursion latency qualification.

Focused ReleaseSafe FRI/parity tests passed 13/13, covering BLAKE3/BLAKE2s quotient/FRI transactions, roots, challenges, folds, verification and diagnostic CPU parity logic. The canonical large-input diagnostics above specifically exercise the new flat-partials selection. Frozen executable, matching Metal bundle, changed source snapshot and raw artifacts are retained in this directory.
