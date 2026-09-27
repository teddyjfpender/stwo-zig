# Four-message BLAKE3 leaf continuation

The preceding sampling report identified substantial standard-library generic BLAKE3 compression/update on ARM. The shared streaming leaf builder now dispatches BLAKE3 to four independent SIMD lanes, using the canonical compression schedule. The standard library still owns chunk-tree merges and finalization. State is mutated in place, avoiding copies of the complete CV stack on each update. Column gathering uses a bounded 1 KiB byte tile. Divergent stream geometry or input lengths fall back to independent standard-library updates.

No framing, constraint, parameter, transcript or proof-format change is intended. This optimizes shared prover leaf hashing; it does not remove BLAKE3 AIR constraints or claim a recursion speedup.

Focused ReleaseSafe streaming tests and existing Merkle tests pass. Streaming coverage includes block and multi-chunk boundaries, differently split updates, column gathering, tails, and divergent streams. A development test caught narrow integer inference in the tile byte-length expression; the tile count is now explicitly usize.

The initial continuation-only comparison did not demonstrate an E2E gain: CPU control/candidate medians were ECDSA 1.069586 / 1.078733, SHA128 2.468606 / 2.460993, SHA2048 4.732036 / 4.832784, Keccak128 4.497955 / 4.567966 seconds. All 24 timed proofs passed and all eight retained artifacts matched and freshly verified. These binaries and records are retained under `continuation-only/`; absolute candidate paths in their original command metadata refer to the pre-archive location.

Inspection of the sampled call stacks also identifies ordinary batched leaves and Merkle parent hashing. The expanded candidate therefore includes four-lane hashing for heterogeneous lifted leaves, parent nodes, first-FRI quotient leaves, and single-chunk finalization. Multi-chunk finalization still uses std. The expanded candidate also failed the performance gate and is not promoted. Production integration and build-target edits from this experiment have been removed; source and frozen binaries remain here for reproducibility. The control is the frozen preceding tiled-witness candidate; the candidate contains the leaf adapter. The harness uses 70 queries / 26 PoW bits, 16 workers, three samples per arm and precompiled ECDSA, checking preceding proof hashes and fresh artifact verification. Fixed order and no explicit warmup limit confidence in small differences.


## Expanded candidate result — not promoted

| Workload | Previous CPU s | Expanded SIMD CPU s |
| --- | ---: | ---: |
| cpu-ecdsa_secp256k1-32 | 1.114206 | 1.095495 |
| cpu-sha256-128 | 2.507878 | 2.465622 |
| cpu-sha256-2048 | 4.694066 | 4.747142 |
| cpu-keccak-128 | 4.360601 | 4.447353 |

All 24 primary timed proofs verified in process; all eight retained artifacts freshly verified and matched the preceding canonical proof hashes. The 25 focused ReleaseSafe tests passed. The CPU ReleaseFast build passed. No Metal performance claim or new recursion qualification is made.

The first expanded Keccak candidate measurement overlapped a focused test build. Those measurements are preserved separately in `overlapped-keccak/` and excluded from the primary table. Both Keccak arms were rerun alone after the build and proof processes were terminal. An initial rerun refused existing output artifacts; the archived outputs were removed from the primary destinations before the successful rerun.

The expanded candidate changes heterogeneous lifted leaves, Merkle parents, first-FRI leaves, streaming continuation and single-chunk finalization. Despite broader coverage, total gains on ECDSA/SHA128 are small while larger SHA/Keccak regress. These three-sample results do not establish a benefit. Do not leave extra production complexity enabled on that evidence.

This result does not establish that all native BLAKE3 implementations are equivalent or that hashing cannot be improved. It rejects this adapter as an E2E optimization. Further work must establish isolated throughput and attributable stage savings before another full prover integration. The original CSP suite remains the performance target; the migration has not met it.

To reproduce this unpromoted candidate, overlay `source/` onto the corresponding preceding worktree, run the focused `src/prover` `test-blake3-stream test-merkle` ReleaseSafe targets and rebuild the CPU ReleaseFast product. `measure.py` uses frozen control/candidate products and refuses existing output artifacts; archive the previous run before re-running. The continuation-only version is preserved as a binary/measurement checkpoint; `source/` describes the expanded candidate only.
