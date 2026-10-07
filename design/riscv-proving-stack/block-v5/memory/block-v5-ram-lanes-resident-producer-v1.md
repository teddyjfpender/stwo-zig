# Canonical RAM resident producer

This producer revision has passed four CPU metadata/census/claim/alignment
checks and actual Metal collection/replay/requester/provider/original-STARK body
compilation. A regenerated six-program library with the lane witness helper
compiles with the real offline Metal compiler. No device execution, STARK
proof, segment run or speed measurement has been performed for this revision.

The subsequent shared heap/external-budget revision is source-only and awaits
its device-free ownership/extent and production-body checks. The historical
qualified snapshot below precedes that revision.

`block_v5_ram_lanes_replay_v1.ForBackend(Backend)` now supplies a resident
sorted-record callback when the backend exposes `RamLaneResident`. The Metal
backend exposes that capability. Its physical-domain minimum is row log 12;
`Replay.admittedLimits` applies the minimum before independent plan selection
and first-root collection. Small shards have actual 4,096-row domains, subject
to the configured maximum and ordinary proof/resource limits. CPU admission
and layouts retain their existing behavior.

One sorted shard is serialized as six full u32 words per event, uploaded once,
and released before witness generation. Full u64 clocks and unmodified before/
after words are preserved. The same real source produces an independent
65,536-value range histogram using stack-only typed `Word.witness` and
`Word.rangePoints`. No CPU fixed/main trace is materialized in this route.
`Source.Lease` owns the resident records and bounded histogram until release.
Every replay checks exact order, endpoints, census and EOF; failures poison it.

The AOT lane witness kernel reuses the existing word event emitter and routes
two events into fixed 24/main 54 at the canonical committed physical row. The
second lane is inactive on an odd tail. Sorting, predecessor values, spaces,
integer carries and endpoints are device checked before publication. This adds
one witness symbol to the Metal AOT source roster; regenerated sources and
binary pins are required. Historical qualified AOT artifacts are unchanged.

First-round collection uses `Session.initFirstRound`, which has no challenge
or inverse table. Requester fixed/main and provider fixed/main commitments all
use an explicit strict uniform PCS route. Warm proving independently matches
those roots, the requester histogram digest and counts before advancing B5SS.
After sealing, one resident range inverse table is generated from the exact
range challenge and shared across every requester/provider. The lane 23-plane
and range 2-plane fractions are lowered from the existing typed Algebra.
Scans and mean centering remain device operations, with active poles causing
an error before claims or columns can be admitted.

Only 23 secure requester totals (368 bytes), two secure provider totals (32 bytes)
and completion/status words cross the CPU transcript boundary. Claim counts
and normalization follow the unchanged typed protocol. Device columns are
blitted into aligned allocator-owned PCS arenas; no full-column host readback,
CPU scatter or CPU interaction fallback is selected. A precommit decline is
an error. Coefficient and evaluation backing alignment survives ownership
transfer and final `rawFree`. Temporary witness/interaction buffers are
released before the core prover consumes the original PCS owner.

`Stage.Source.report_resident` optionally reports sorted/histogram ingress,
claim/status readback and device-blit byte counts. These are operation counts,
not verified receipts or timing claims. The stage has an explicit resident
byte cap; PCS retained buffers and FFT/Merkle workspace are included in its
checked envelopes. Canonical resident sessions now require the caller's actual
`SharedHostBudget`; heap growth and external reservations compete under its
single mutex/cap. Private buffers reserve before allocation, retain charges
through checked completion and actual destruction, and no-copy aligned host
aliases remain heap charged once. Local resident-source ownership must match
the session budget. This new source-only integration is described in
[shared-external-memory-budget-v1.md](../../performance/shared-external-memory-budget-v1.md).
It does not assert whole-process budget enforcement or completion/accounting
of every downstream GPU PCS/FRI operation.
Existing strict Metal host-work admission continues to reject unsupported
downstream host proving work.

Qualification sources are `src/block_v5_ram_lanes_resident_producer_test_root.zig`
(CPU metadata, streaming histogram, 23-total claim parity, allocation failures
and ownership moves) and `src/block_v5_ram_lanes_metal_producer_codegen.zig`
(retains actual collection/replay/requester/provider/prover bodies without
invocation). CPU fresh verification remains on the original typed AIR.

Qualification evidence is retained in `autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/ram-lanes-resident-producer-qualified-source-v1.json` and the linked logs/AOT receipt. The AOT metallib SHA-256 is `5019bb7beb4d562820c2b52d409a4a708108cd298806291620dc4b60004f568c`; actual resident producer body object SHA-256 is `8f0fe7a40012ee68d6be95cd2aff0f3a74c2531234cdfc6a01fe54c182922b7d`. These artifacts precede the next shared external-budget/preflight changes and remain historical qualified evidence.
