# Recursive polynomial residency research

Scope: CPU, full-width BLAKE3, canonical 70 queries / 26 PoW bits. The transaction-authentication fixture includes Keccak and signer-recovery precompiles. Transaction counts below are **one execution leaf plus one native recursive parent**, not leaf counts or full Ethereum block proofs.

The selected direction preserves commitment roots, transcript, constraint roster, and proof bytes. Large host commitment columns retain native coefficients instead of the blown-up evaluation domain. Streaming commitments absorb and release each incoming LDE batch. DEEP folds coefficients before expansion. Composition evaluates bounded native-size cosets, with full-domain storage only for the four rotated interaction coordinates. Merkle openings regenerate bounded parallel batches (128 MiB aggregate, or one column if individually larger).

The capped Merkle leaf state reuses standard BLAKE3 and admits at most 16 KiB of framed leaf data; it does not replace the general hash implementation. The column-count limit is checked before absorption. The retained coefficient path is the default for host native recursive parents. `STWO_RISCV_MATERIALIZED_POLYNOMIALS=1` selects the materialized research oracle. Device-backed commitments keep their existing residency policy.

## Latest qualified default result

| Transactions | Total seconds | Recursive parent seconds | Tracked worker GiB | Process peak GiB |
| --- | ---: | ---: | ---: | ---: |
| 16 | 44.331 | 17.471 | 9.281 | 9.625 |
| 32 | 49.465 | 19.244 | 9.584 | 10.009 |
| 64 | 52.797 | 18.421 | 9.584 | 9.858 |

Artifacts: `auth-{16,32,64}-assembly-release.{json,log,proof}`, associated invocation manifests, and `assembly-release-auth-summary.json`. All verified and byte-identical to the previously qualified cubic/four-shard proofs. The preceding 16-transaction baseline was 40.012 seconds / 14.524 GiB tracked worker memory. The 32/64 reference worker peak was 15.095 GiB. These are single qualification runs, not medians.

Worker peaks count requested live allocation bytes. Process peaks are Darwin physical footprints from `/usr/bin/time -l`, including preparation and host overhead. Do not compare the two counters as if they were the same measurement.

Assembly now finishes the directly projected hash/route cohorts first, releases copied transcript/path sources, and then lowers arithmetic. Independent fusion owners actually free their scratch instead of returning it to a retaining parent arena. Source graph ownership lasts until lowering completes. Column ownership transfers only after successful final assembly; consuming preparation states remain safe to destroy after failure. Both execution leaves and recursive aggregation use this path. The 16-transaction process peak fell from 13,812,495,008 bytes in the intermediate coefficient-batched candidate to 10,334,906,856 bytes.

## Complete recursive trees

The complete 16-leaf tree contains 31 recursive proof jobs and four aggregation levels. Its root freshly verifies and is byte-identical to the earlier root.

| Measurement | Previous 16 leaves | Current 16 leaves | Current 32 leaves | Current 64 leaves |
| --- | ---: | ---: | ---: | ---: |
| Tracked peak GiB | 18.058 | 10.090 | 10.091 | 10.091 |
| Physical process peak GiB | 14.400 | 9.303 | 9.272 | 9.279 |
| End-to-end seconds | 678.914 | 794.598 | 1562.103 | 3137.641 |

Tracked peak fell **44.1%**, physical peak fell **35.4%**, and CPU runtime increased **17.0%**. This is a deliberate memory/time tradeoff, not a throughput improvement. See `assembly-release-tree16-summary.json` and `stream-assembly-release-auth1-canonical-2048.{json,log,proof}`.

The complete **32-leaf tree freshly verifies**, with 63 recursive proof jobs and five aggregation levels. Its tracked peak is only **0.00624%** above 16 leaves (675,866 bytes), and its complete execution statement, ELF, input and output hashes match the 16-leaf run. Root proof bytes differ with tree geometry, as expected. See `memory-scaling-qualified-summary.json`; `summarize_memory_scaling.py` validates the saved artifacts and regenerates that summary. The measured workload is the same guest split into more leaves, isolating recursion-depth scaling from increasing individual leaf geometry.

The complete **64-leaf tree freshly verifies**, with 127 proof jobs and six aggregation levels. Tracked peak is 10,835,361,718 bytes and physical process peak is 9,962,792,544 bytes. Total time is 3137.641 seconds (52.294 minutes). Compared with 16 leaves, tracked peak grows only 886,364 bytes / **0.00818%**; compared with 32 leaves it grows 210,498 bytes. The complete execution statement and ELF/input/output identities match both smaller trees. Root proof SHA-256: `8283d466fa752e00de4490f53c0b85212c0ace28a28ce3f095edfcf58c2f42cb`. Run `python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/summarize_memory_scaling.py --include-64` to validate all three saved qualifications. These are single observations on AC power, using the saved memory-optimized binary; subsequent SHA/compiler source changes are outside that binary's provenance.

The original 32-leaf counting preflight exposed a terminal-output boundary problem before proving began. Counting chunks now collect output access locations; the final balanced schedule reserves enough terminal instructions to include all last output accesses. Actual proof replay retains strict output access-clock validation. The pinned guest needs a 349-cycle suffix: 16/32 leaves naturally allow 1352/676 cycles; a 64-leaf schedule must enlarge its final leaf from 338 to 349 cycles. Strict replay passed at 16, 32 and 64 leaves against the original admitted endpoint constructor (`preflight-replay-{2048,1024,512}.log`). The corrected 64-leaf schedule subsequently completed the full recursive proof and freshly verified its root. This scheduling correction changes neither proof security parameters nor the verifier.

## Rejected experiment

Wider LogUp batches required a larger quotient domain. Four shards increased memory; eight shards made only a small improvement while increasing proof size and runtime. The production roster remains cubic with four G shards. See `wide-batch-scaling-summary.json`.

## Focused validation

Exact commitment/opening parity, duplicate-query ordering, missing Merkle layers, shared ownership, every allocation failure, folded DEEP quotient equality, capped BLAKE3 byte-length/carry boundaries, full-domain versus coset composition, and allocation-free prepared execution have passed focused tests. Deferred-commit failure cleanup, G-partition allocation failures, and a real runner proof through two recursive levels also passed; the latter exercises source consumption, rejects reuse, and runs with the testing allocator. The terminal-publication regression and public-data validation gate passed all 15 tests (`test-terminal-planning-5.log`), including strict rejection of missing local output accesses, corrected replay, invalid output oracles and an insufficient final-leaf budget. The consuming-row failure test also passed through two recursive levels (`test-recursive-row-failed-consumption.log`). Full proof verification remains mandatory for each retained benchmark. Operator census completeness is explicitly false for the compact quotient path until its FFT folding is accounted for.

## Repeat a measurement

The run scripts use the saved ReleaseFast binaries and reject existing output files. `--run-id` creates fresh artifact names without rebuilding or overwriting the qualification results:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/run_auth_assembly_release.py --batch 64 --run-id repeat1
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/run_stream_terminal_planning.py --profile canonical --limit 1024 --run-id repeat1
```

For stage attribution, set `STWO_HOST_MEMORY_PROFILE=1`. Both runners serialize with the repository build/proof lock and record binary/fixture hashes, selected STWO environment variables, exit status, wall time, verifier output and process resource usage. Stream limits 2048, 1024 and 512 produce balanced 16-, 32- and 64-leaf schedules for this pinned 21,635-cycle guest. The canonical profile is the stream runner default.

## Scaling boundary

With bounded execution segments and fixed proof geometry, the large polynomial/witness buffers belong to the currently proved leaf or aggregate. The stream frontier retains at most one verified subtree per level (O(log N) nodes), and the folder replaces its previous key-specific worker before preparing the next one. It does not retain every leaf witness. This is why doubling the number of leaves need not double memory.

Increasing the size of a single unsegmented guest can still cross a power-of-two trace-domain boundary and increase its working set. The 16/32/64-transaction table and the 16/32/64-leaf tree tests answer different scaling questions; neither establishes a constant footprint for arbitrary unsegmented programs.

## Source provenance

`memory-scaling-final-source.tar.gz`, its SHA-256 sidecar and source manifest preserve the final implementation and focused fixtures. Benchmark invocation manifests pin the executed binaries and guest/input/oracle files. Post-build edits to the preflight module were confined to its unit fixture; the manifest describes them. Earlier candidate archives and failed counting/test attempts are retained as research history.
