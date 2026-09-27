# Canonical Merkle-plan reuse in recursive preparation

The preceding goal turn qualified the narrower shared BLAKE3 G. This checkpoint
addresses repeated preparation work under the original persistent-plan goal.

Opening preparation previously rebuilt canonical hash graphs for sizing, each
live/fixed leaf or node frame, and output-wire discovery. A per-preparation owner
now caches the node graph and the current leaf-length graph. Frame emission,
fixed preprocessing and output endpoints all reuse those immutable plans.
Changing leaf geometry builds its replacement before releasing the old graph;
an allocation failure preserves the previous entry. At most two plans remain
cached between calls; replacement briefly owns the new and old leaf plans.

The cache contains topology only. Witness bytes, namespace, root, query index,
caller bindings and transcript state remain per opening. Existing admission and
statement/destination checks are retained. Borrowed views must finish emission
before the next cache request; this owner is local and is not a cross-thread cache.
The destination-with-plan API rejects mismatched row/column metadata before writes.

The focused guarded frame/witness test passes. It checks full-row and main-column
parity for repeated cached emission, selected and ordinary Merkle paths, malformed
destinations, borrowed-output lifetime, all partial allocation failures, cache
replacement failure/recovery, and exact fresh/cached graph structure. The canonical
CPU child/parent proof passes at q70/PoW26 on both levels with identical artifact
SHA256 87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b.
The initial qualification reports 1540 openings, six graph builds and two retained
plans. Transcript replay, fixed-plan reuse, rekey and ownership checks pass.

This targets preparation, which is excluded from the existing parent-stage sum.
The matched comparison uses frozen previous/candidate parent-test executables,
control/candidate/candidate/control, one observation per block, no warmup, and
two parent workers. Compilation is excluded. Complete test-process wall time
includes child proving, preparation, parent proving, validation and teardown;
it is not a production recursive-tree latency measure. `/usr/bin/time -l` records
process peak RSS separately from the prover's tracked parent-allocation peak.
Both binaries must produce the same artifact and pass all canonical checks.

The change affects shared recursive Merkle witness preparation. It changes no
AIR, shader, security parameter or ordinary CSP proving route. Full CSP recovery,
whole-tree recursion, deeper PCS/DEEP fusion, compact metadata/final-layout work,
scheduling overlap and the separately reviewed parameter experiment remain open.

## Qualified comparison

| Metric | Control | Candidate |
| --- | ---: | ---: |
| Complete fixture wall median (s) | 75.729202 | 61.192215 |
| Recorded parent-stage median (s) | 43.534392 | 43.539514 |
| Maximum process peak RSS (bytes) | 16339468288 | 16339517440 |

The complete diagnostic fixture is 19.2% faster in these four ordered runs
(two observations per arm). Parent proving stages and peak RSS are effectively
unchanged. The improvement is outside the recorded parent proving stages,
consistent with removal of repeated witness/preprocessing graph construction.
This is not subsecond recursion, a whole-tree throughput result, or an isolated
measurement of production preparation alone. All four runs preserve exact parent
proof bytes and pass canonical child/parent verification, transcript replay,
fixed-plan reuse, rekey and ownership checks.

The retained final version also passes the focused witness safety gate and an
additional complete canonical parent qualification after the metadata-alias guard
was added. `final-safety.log` and `final-parent.log` record those gates.

The next larger target is actual native BLAKE3 parent Metal coverage. See
[next-coverage-audit.md](next-coverage-audit.md): detached-recursion catalog coverage
must not be confused with native-parent qualification, and native interaction
generation currently explicitly uses the CPU parallel path for every backend.
