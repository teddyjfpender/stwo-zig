# BLAKE3 prover migration

## Current status — 2026-09-23

Scope correction: preserve existing Ethereum/CSP functionality; expanding
Ethereum block or canonical multi-segment aggregation capability is deferred.
The failed canonical two-segment aggregation gate is retained as evidence, not
a prerequisite for the current migration. Its queued mapped-storage rerun was
cancelled before launch, and the new parent-specific file-backed storage wiring
was removed. Core BLAKE3, native recursion, production routing and existing
CPU/Metal/CSP compatibility remain the priorities.

Explicit BLAKE3 core CPU and Metal proving paths and the full canonical CSP
matrix are qualified. Production-wide migration is **not complete**: ordinary
selection still defaults to BLAKE2s, and production memory/recursion retains
Poseidon. The dated entries below are chronological evidence, not a cumulative
claim that every earlier limitation still applies.

The latest full-suite ECDSA precompile samples at 70 queries/26 PoW bits are
1.096581208 s CPU and 0.907834583 s Metal, execution-inclusive. The separate Metal
AOT harness measured 0.881876417 s witness/proving plus 0.000743667 s execution.
See [CSP results](../../../vectors/riscv_csp/README.md).

The explicit full-width base-execution path now includes BLAKE3 program/memory
commitments, independently admitted keys/artifacts, and an end-to-end typed
execution-parent proof and a parent-of-parent proof independently verified after
their proving plans are released. This two-level unary qualification is diagnostic
q8/PoW0 on CPU.

The explicit base-execution parent now binds its Span and includes the
ordinary-to-continuation conversion rows. A real nonzero-output execution passes
two unary recursion levels with the Span identity preserved. Two adjacent
leaf-local runner segments now also produce a distinct-child aggregate and
an independently verified parent-of-aggregate, at diagnostic q8/PoW0 on CPU.
Four real segments now also qualify two binary aggregation levels through owning
verified tree nodes. General production multi-segment execution orchestration
remains unfinished.

The shared bounded pipeline now accepts verified tree-node pairs and overlaps
preparation with a persistent proving worker. A two-job root fixture qualifies
same-key plan reuse, allocation caps and verification after worker destruction;
this remains a local diagnostic pipeline, not production activation.

An explicit q70/PoW26 execution leaf and its recursive parent now independently
verify on CPU, with full-memory Span/custody and root coverage. The dedicated
gate now peaks at 23 GiB RSS after compacting persistent plan metadata and
transferring owned interaction columns into PCS;
canonical multi-segment aggregation, more recursion
levels and Metal qualification remain open.

The explicit full-width Ethereum path now proves and independently verifies
one signer recovery plus one Keccak call on CPU at canonical q70/PoW26. Its
bounded artifact round trip and successful-verification capture pass after
original witness/proof destruction and mutation of source public I/O. Persistent
verifier preparation derives wire limits from the admitted components. The gate
reports 10 minutes / 30 GiB with four workers; this is not a latency benchmark.
Ethereum recursive lowering now produces an independently verified parent at
diagnostic q8/PoW0. That gate retains 2,231,719,096 prepared bytes and peaks at
10,155,522,628 tracked worker bytes, with a 132,105-byte parent artifact.
Two real Ethereum segments now also qualify full-memory Span/custody and an
independently verified aggregate root at diagnostic q8/PoW0. Canonical CPU
Ethereum recursion is now qualified as detailed below; canonical aggregation,
production activation remain unfinished.

The remaining integration critical path is production multi-segment and
extension/precompile orchestration, then production-parameter CPU/Metal
qualification and production key admission. Only after those gates pass
should defaults switch and active prover-owned Poseidon paths be removed. No
end-to-end recursion speedup is yet established.

Canonical full-width Ethereum leaf-to-parent recursion now passes on CPU at
q70/PoW26. The independently verified parent artifact is 907,988 bytes; worker
peak is 32,530,488,858 bytes under the unchanged 36 GiB cap, with 10,150,562,296
prepared bytes outside that cap. Worker and rows are destroyed before parent
artifact verification. This qualification reused and independently verified a
cached canonical leaf, so its wrapper duration is not an end-to-end benchmark.
Omitting retained coefficient copies and using eight-column streaming batches
resolved the prior CPU worker-cap failure. Pool-backed key derivation is included.
See [CPU canonical result](../../../autoresearch/notes/2026-09-23-blake3-parent-commitment-residency/README.md).

Canonical full-width Ethereum leaf and parent now also pass on Metal at q70/PoW26,
with independent CPU verification. Parent proving performed 191 Metal dispatches
and 2 CPU fallbacks; worker peak was 27,708,198,754 bytes under the unchanged
36 GiB cap. The 907,988-byte artifact verifies after worker/row destruction.
Checked-allocator cleanup passed. The streaming PCS combined-buffer ownership
repair also passes 5/5 focused root/value and allocation-failure tests. See
[Metal canonical qualification](../../../autoresearch/notes/2026-09-23-blake3-streaming-backing-ownership/README.md).
An earlier stateless allocator context read was removed; its focused admission
regression passes, but a successful stateless-allocator parent run is still open.

Direct chunk projection now avoids scanning the complete destination trace for
every small witness chunk. Exhaustive offset/length parity in a small domain
passes; the successful canonical CPU run includes this path. No end-to-end speedup
has been measured. See [chunk projection](../../../autoresearch/notes/2026-09-23-blake3-chunk-projection/README.md).

Canonical aggregation, successful stateless-allocator parent
qualification, production orchestration/key admission/default routing and active
prover-owned Poseidon removal remain open. The base paired-admission regression
passes its four-leaf runtime gate; Ethereum paired-admission follow-up checks
also remain to be rerun.

Parent fixed rows are now compact from assembly through joining, rebasing and
key derivation. Projection parity, the diagnostic four-leaf/two-level tree, and
canonical q70/PoW26 Ethereum CPU recursion all pass. Canonical prepared retention
fell from 10,150,562,296 to 5,953,718,776 bytes (41.35% less), outside the worker
budget. Worker peak remains 32,530,488,858 bytes; the independently verified parent
artifact remains 907,988 bytes. The complete-run owned-I/O constructor is included.
The earlier Metal success predates compact rows; the Metal/SMP gate is queued.
Canonical Ethereum two-segment aggregation failed at its 48 GiB worker cap during interaction commitment. See
[compact fixed rows](../../../autoresearch/notes/2026-09-23-blake3-compact-parent-fixed/README.md)
and [owned complete-run I/O](../../../autoresearch/notes/2026-09-23-blake3-owned-complete-run/README.md).

Production routing must cover base, guest Poseidon2, guest Keccak and Ethereum
profiles. Existing explicit core-suite selection does not activate the full-width
memory/recursion path for those products. Guest Poseidon semantics remain distinct
from prover-owned hashing; production routing/removal is not complete.

Shared segment Span construction now derives continuation memory roots and
runner coordinates for base and Ethereum aggregation fixtures. Its focused
runtime check is queued; updated proof fixtures are not yet requalified. This
removes manually assembled leaf claims in preparation for production orchestration,
but does not activate the CLI or change verifier key admission. See
[segment construction](../../../autoresearch/notes/2026-09-23-blake3-segment-span-construction/README.md).

Segment-pair preparation now has an owning entry point that releases each
completed child's execution witness before proving the next child. Both children
are admitted first; prepared verifiers remain reusable. Base and Ethereum
aggregation regressions are queued, and no residency or timing improvement is
claimed before qualification. See
[owned pair preparation](../../../autoresearch/notes/2026-09-23-blake3-owned-segment-pair/README.md).

Canonical Ethereum aggregation prepared 11,906,171,864 bytes of rows but failed
at interaction commitment with a 51,522,018,090-byte tracked worker peak under
the 48 GiB cap. Expanded qualification and its proposed file-backed workaround
are deferred following the scope correction above. The experimental source
snapshot and failure evidence remain in
[aggregate storage notes](../../../autoresearch/notes/2026-09-23-blake3-aggregate-retained-storage/README.md).

Compact parent storage and segment/job constructor focused checks pass.
The Metal/SMP canonical single-parent run failed in FRI quotient batch-index
planning under the host cap. A source-fragmentation heuristic could select a flat
buffer beyond u32 descriptor addressing; mandatory segmentation for wide inputs
is implemented and pending qualification. See
[Metal wide-source fix](../../../autoresearch/notes/2026-09-23-blake3-metal-wide-fragmentation/README.md).

The shared statement codec now supports full-width BLAKE3 roots, with legacy
compatibility and real-proof round-trip checks queued. Commitment-plan admission
and production artifact routing remain unfinished. See
[statement metadata](../../../autoresearch/notes/2026-09-23-blake3-statement-wire/README.md).

A caller-pinned base execution manifest now binds full-width statement metadata,
commitment schedules, source digest labels, exact PCS policy and typed transcript
authority before verifier preparation. Runtime checks are queued; product-level
ELF/input validation and artifact routing are not yet connected. See
[execution manifest](../../../autoresearch/notes/2026-09-23-blake3-execution-manifest/README.md).

Independent base source validation now reconstructs the BLAKE3 program and
initial-memory commitments from the supplied ELF without running the guest. It
checks initial CPU state, ABI symbols, completion and byte-exact input; the input
binding is shared with the existing guest verifier. Runtime qualification and
product CLI wiring remain pending. See
[source admission](../../../autoresearch/notes/2026-09-23-blake3-execution-source/README.md).

## Earlier evidence and implementation log

Latest CPU CSP update: bounded pooled BLAKE3 PoW reduces the canonical ECDSA
qualification from 2.523295 s to 1.000019 s proving; PoW falls to 0.122675 s.
ReleaseFast protocol/CSP gates pass 8/8 tests and ReleaseSafe protocol 7/7.
These are single measured samples, not a statistical speedup verdict. Production
defaults and Metal remain pending. See [current pooled PoW evidence](../../../autoresearch/notes/2026-09-22-blake3-pooled-pow/README.md).

Status, 2026-09-22: the experimental CPU native-child-to-parent path now
includes canonical preparation, a persistent standalone prover, bounded artifact
transport and witness-independent verification. The diagnostic child uses
q1/PoW0 and parent q8/PoW0; this does not qualify production security parameters.
Production defaults remain unchanged. Production keys, binary aggregation,
parent-of-parent proofs and Metal qualification remain unfinished. No end-to-end
speedup or completed BLAKE3 production migration is claimed.

Canonical CSP ECDSA now passes with BLAKE3 on CPU at 70 queries/26 PoW bits.
The shared Ethereum artifact codec admits explicit v6 with an internally versioned
identity. One ReleaseFast/16-worker sample measured 2.489486 s proving and 0.188206 s
verification for 1,828 guest cycles; no speedup or full-suite claim is made.
Canonical ECDSA and artifact gates pass 1/1 and 13/13 tests. Production defaults
and Metal are still pending. See [CSP BLAKE3 evidence](../../../autoresearch/notes/2026-09-22-blake3-canonical-csp-ecdsa/README.md).

Core BLAKE3 integration now also proves a real guest precompile and independently
verifies its new v5 artifact using the shared guest prover/verifier and codec.
Canonical suite type bundles live in core; no BLAKE3-specific prover fork exists.
A genuine BLAKE2s proof relabeled as v5/BLAKE3 rejects during independent root
verification. Artifact gates pass 12/12 tests, real guest proof 2/2, and core
protocol/PCS 5/5. This uses diagnostic q3/PoW0, not canonical CSP parameters.
CLI/default routing, segmented artifact versions and Metal still need migration.
See [core/guest evidence](../../../autoresearch/notes/2026-09-22-core-blake3-guest-proof/README.md).

Core transcript receipts now bind suite, version and digest; BLAKE3 preserves
all 64 draw-counter bits. CSP compares proving and independent verification
receipts. Focused protocol and canonical ECDSA gates pass 8/8 tests across BLAKE3
and legacy BLAKE2s. The latest BLAKE3 qualification sample is 2.506949 s proving
and 0.191967 s verification; these single samples do not establish a speedup.
See [receipt evidence](../../../autoresearch/notes/2026-09-22-suite-transcript-receipts/README.md).

CSP product reports now use benchmark/verification schema v2 with an explicit
`transcript_receipt` (suite, version, hex digest). The benchmark reader checks
suite/version against the artifact header and requires the fresh verifier's
receipt to match. Retained rows identify the proof suite and artifact version.
Python CSP reader/wiring/provenance gates pass 101 tests. The ReleaseFast CPU
product builds and a real canonical ECDSA CLI proof plus separate verification
produce matching receipts (BLAKE2s, 0.798874 s proving). This reporting change does
not switch production defaults. See [report evidence](../../../autoresearch/notes/2026-09-22-csp-report-suite-admission/README.md).

The migration scope includes core commitments and transcripts for ordinary RISC-V,
guest-precompile/CSP proofs, recursion and CPU/Metal backends. Ordinary RISC-V
currently defaults to BLAKE2s (`prover/types.zig`); production recursion defaults
to Poseidon2. Guest-visible Poseidon operations remain supported. Completion
requires explicit new suite/key/artifact admission and end-to-end CSP measurements
at 70 queries/26 PoW bits, not only replacing recursive hashing.
The completion target is BLAKE3 for all prover-owned commitment and transcript
hashing, with Poseidon removed from active prover selection. Legacy artifact
verification must remain explicitly versioned, and guest-requested Poseidon
semantics must remain intact. CPU and Metal results must identify the actual
suite and device dispatch; measure total proving time rather than extrapolating
from hash throughput.

Frame, Merkle group, draw/query, complete transcript and aggregate STARK-path
adapters now support direct main-column destinations with separate witness
metadata. Plan identity and fixed metadata are checked independently; borrowed
storage survives receipt destruction and failed native emission retains planning
ownership. Draw/query gates pass 4/4 tests, transcript plan 2/2, transcript sequence
2/2 and native segment 3/3. The normal native parent now allocates combined hash columns before emission,
borrows transcript/path ranges, and adopts main-column ownership without the
final G/XOR projection. The shared row-emission mode is a diagnostic oracle.
The integrated plan/native gates pass 5/5 tests, including exact column parity,
failed-assembly retry, pointer-preserving transfer, second-transfer rejection,
State destruction, threaded handoff and independently verified parent proofs.
See [parent adoption evidence](../../../autoresearch/notes/2026-09-22-parent-column-adoption/README.md).
See [frame/group evidence](../../../autoresearch/notes/2026-09-22-frame-group-main-columns/README.md)
and [transcript/path evidence](../../../autoresearch/notes/2026-09-22-transcript-path-main-columns/README.md).
The current diagnostic preparation peak is 449,015,271 bytes (up from
382,427,287), retained handoff 130,557,704 and worker peak 982,008,191; key and
116,382-byte artifact are unchanged. Earlier column allocation overlaps metadata
still stored as full zero-main rows. The existing 512 MiB cap passes. No memory
improvement or latency speedup is inferred from eliminating the projection.
Core/CSP migration entrypoints are recorded in the
[local audit](../../../autoresearch/notes/20260922-core-blake3-migration-entrypoints.md).

Evidence: [canonical capture preparation](../../../autoresearch/notes/2026-09-22-native-blake3-parent-preparation/README.md),
[standalone producer](../../../autoresearch/notes/2026-09-22-native-blake3-parent-producer/README.md),
[artifact codec](../../../autoresearch/notes/2026-09-22-native-blake3-parent-codec/README.md),
and [independent verifier](../../../autoresearch/notes/2026-09-22-native-blake3-parent-verifier/README.md).

The persistent parent plan now retains its authenticated fixed commitment across
requests; two complete proofs from the same plan pass independent verification.
See [commitment reuse evidence](../../../autoresearch/notes/2026-09-22-native-blake3-commitment-reuse/README.md).
Reusable worker scratch is now qualified, including failure cleanup and proof
verification after workspace destruction; see [workspace evidence](../../../autoresearch/notes/2026-09-22-native-blake3-workspace/README.md).
A bounded prepared-row handoff now passes threaded ownership qualification;
see [handoff evidence](../../../autoresearch/notes/2026-09-22-native-blake3-handoff/README.md).
The diagnostic preparation retains 461,491,639 bytes of charged payload capacity.
Preparation now enforces a synchronized live-allocation cap that survives the
handoff. The diagnostic run peaked at 1,242,103,479 tracked bytes under a 2 GiB
cap; immediate and partial-construction denials clean up successfully. See
[preparation budget evidence](../../../autoresearch/notes/2026-09-22-native-blake3-preparation-budget/README.md).
A persistent worker now binds an explicit pool and shares one routed-allocation
budget across its plan, workspace and proof. Artifacts and captures retain budget
leases after worker destruction. See [worker evidence](../../../autoresearch/notes/2026-09-22-native-blake3-worker/README.md).
Canonical host Merkle layers now honor the explicit worker allocator budget;
peak tracked worker allocations were 1,632,926,982 bytes. See
[budgeted Merkle evidence](../../../autoresearch/notes/2026-09-22-budgeted-merkle-layers/README.md).
A bounded local pipeline now validates combined CPU/memory reservations against
the execution policy and overlaps preparation with proving: two same-key jobs
showed 1.34 s of stage overlap and both verified independently. See
[pipeline evidence](../../../autoresearch/notes/2026-09-22-native-blake3-pipeline/README.md).
This qualifies one pipeline node, not production execution-key forwarding,
statement-independent keys or aggregation of distinct children. Higher-level
scheduling and caller-declared external reservations remain obligations; neither
the allocation cap nor reservation arithmetic establishes a total process RSS
ceiling. No end-to-end speedup comparison has been measured.

Shared typed fusion now applies the census's 777 dot4 and 5,843 FMA matches
through one canonical materializer used by native and detached recursion.
Arithmetic rows fall from 29,488 to 18,206 (38.26%); the native proof, codec,
independent verification and two-job pipeline gate passes 3/3 tests. The detached
genuine-child preparation and snapshot regressions pass 2/2 with the independently
pinned saved fixtures. See [shared fusion evidence](../../../autoresearch/notes/2026-09-22-native-shared-fusion/README.md).
The native roster now has 19 AIRs, protocol version 3 and envelope version 2;
the artifact is 117,135 bytes, up from 111,428. These are structural savings,
not a measured end-to-end speedup. Preparation still peaks at 1,242,103,479
tracked bytes. Further fused PCS/DEEP components beyond existing dot4/FMA,
final-layout witness generation and separately reviewed parameter experiments
remain unfinished.

The follow-on native PCS census found 134 eligible four-query groups, but the
detached query-binding AIR cannot be selected unchanged: native scalar producers
also feed hash encoding and read-only authentication. Native fusion must retain
those two external emissions. The census and existing PCS component tests pass
6/6; see [native query-fusion boundary](../../../autoresearch/notes/2026-09-22-native-pcs-query-fusion/README.md).
The native base-query opening AIR is now implemented and passes exact lookup
closure, all fixed-coordinate mutations, main-coordinate mutations and padding
checks (7/7 focused tests including existing detached checks). It preserves both
external query emissions; subsequent roster integration is recorded below. See
[native PCS opening AIR evidence](../../../autoresearch/notes/2026-09-22-native-pcs-opening-air/README.md).

Native PCS query fusion is now integrated in preparation and the 20-AIR roster.
The actual parent removes 536 scalar rows across 134 groups; full native proof,
codec, independent verification and pipeline qualification passes 3/3. Protocol
version 4 / envelope version 3 bind the new geometry. Artifact size is 116,382
bytes; preparation peak is unchanged. See [integrated query fusion evidence](../../../autoresearch/notes/2026-09-22-native-query-fusion-integration/README.md).
No complete timing speedup or production qualification follows from this gate.

Query-fusion admission now has focused rejection coverage for all scalar/dot4
fields, missing/duplicate sources and preservation of unrelated rows (8/8 tests).
See [admission evidence](../../../autoresearch/notes/2026-09-22-native-query-admission/README.md).
A subsequent attempt to eliminate padded logical-row copies failed full-proof
constraints and was reverted to the qualified producer. Implicit interaction
padding must be checked against typed denominator constraints before replacing
explicit rows; see [rejected staging experiment](../../../autoresearch/notes/2026-09-22-native-row-staging/README.md).

The padding mismatch is now isolated: G padding has 56 live lookup events;
the other 19 native AIRs have inert padding. This supersedes the earlier
denominator hypothesis. Typed virtual padding now matches complete explicit
interaction columns and claims across all 20 AIRs; existing allocation/alias
checks also pass (11/11 tests). Producer integration still needs repeated-padding
table counter registration. See [virtual padding evidence](../../../autoresearch/notes/2026-09-22-native-virtual-padding/README.md).

Padded logical-row copies are now removed from the producer. Borrowed live rows,
typed virtual interactions and repeated-padding counter registration preserve
full-proof verification (3/3 native tests; 11/11 focused tests). Worker peak tracked
allocation falls from 1,626,590,262 to 1,567,077,617 bytes, a 59.5 MB / 3.66%
reduction. Preparation peak, key and artifact size remain unchanged. See
[copy-removal evidence](../../../autoresearch/notes/2026-09-22-native-padding-copy-removal/README.md).
This is one staging layer removed, not complete direct final-layout generation
or a measured timing speedup.

Separating preparation scratch from final-row ownership passed verification but
left retained bytes unchanged and increased peak allocation by 21.5 MB; it was
reverted. The next preparation change needs measured live row and buffer capacity
counts before pre-sizing or direct output. See [rejected scratch experiment](../../../autoresearch/notes/2026-09-22-native-preparation-scratch/README.md).

Exact pre-sizing of G, XOR and byte-route output buffers now reduces preparation
handoff retention from 461,491,951 to 254,205,405 tracked bytes (44.92%) and peak
preparation allocation from 1,242,103,479 to 1,044,442,891 bytes (15.91%). Live row
bytes, key and artifact size remain unchanged. Preparation-only measurement and
the full native gate (3/3 tests) pass. See [row pre-sizing evidence](../../../autoresearch/notes/2026-09-22-native-row-presizing/README.md).
This does not complete direct final-layout generation or establish a timing speedup.

Final row buffers now transfer individually into Prepared ownership; scratch is
released at return and abandoned buffer allocations can be freed during growth.
Handoff retention falls further from 254,205,405 to 118,185,496 bytes (53.51%),
matching the live payload plus bookkeeping. Preparation peak remains
1,044,442,891 bytes. The full native gate passes 3/3 with unchanged key and artifact
size. See [owned final-buffer evidence](../../../autoresearch/notes/2026-09-22-native-owned-final-buffers/README.md).
Adapter staging and direct committed-column generation remain unfinished.

Merkle-path adapter rows now use individually owned backing allocations, freeing
old row-growth storage rather than retaining it in the adapter arena. Preparation
peak drops from 1,044,442,891 to 799,302,496 tracked bytes (23.47%); handoff retention
remains 118,185,496 bytes. Full native qualification passes 3/3 with unchanged key
and artifact size. See [path adapter ownership evidence](../../../autoresearch/notes/2026-09-22-native-path-owned-rows/README.md).
Per-group copying and transcript staging remain before direct column generation.

Transcript witness rows now have individual backing-allocation ownership, reducing
preparation peak further from 799,302,496 to 612,480,383 tracked bytes (23.37%).
Handoff retention stays 118,185,496 bytes; key and artifact size are unchanged.
Transcript-plan plus full native qualification passes 4/4 tests. See
[transcript ownership evidence](../../../autoresearch/notes/2026-09-22-transcript-owned-rows/README.md).
Cumulative preparation peak reduction versus 1,242,103,479 bytes is 50.69%; this
is a memory result, not a measured end-to-end proving speedup.

Canonical full-hash generation now accepts caller-owned typed row destinations,
using the same evaluation loop as owning preparation. Live rows no longer receive
fixed G/XOR initialization that was immediately overwritten. Hash-vector, exact
row parity, closure and routed-frame checks pass 4/4; adapter reservations and
direct committed-column integration remain pending. See [destination kernel evidence](../../../autoresearch/notes/2026-09-22-hash-witness-destination/README.md).

Live routed frames now reserve exact hash-row destinations and release hash-plan
and wire scratch separately. Focused frame plus full native qualification passes
4/4 tests; preparation peak falls from 612,480,383 to 600,657,997 tracked bytes.
Key, artifact size and handoff retention stay unchanged. See [frame destination
integration evidence](../../../autoresearch/notes/2026-09-22-frame-hash-destination/README.md).
Outer adapter copying and direct committed-column generation remain unfinished.

Canonical hash evaluation now has a direct committed-column sink sharing the row
evaluator and typed constructors. Coordinate parity, nonzero offsets, untouched
padding and pre-mutation shape rejection are qualified; hash/frame checks pass
5/5, with strengthened hash rejection checks passing on rerun. No native producer
uses this sink yet. See [column sink evidence](../../../autoresearch/notes/2026-09-22-hash-column-sink/README.md).
Interaction row access and adapter destination integration remain required.

Interaction generation now accepts a bounded committed-column row view, reading
one logical row at a time through the same interaction kernel and typed padding.
Direct-hash column output matches owned-row interaction columns and claims;
hash/framework/PCS checks pass 15/15. Native producer integration is still pending.
See [column interaction evidence](../../../autoresearch/notes/2026-09-22-column-interaction-view/README.md).

The native producer now generates interactions from its committed-order main
columns plus authenticated fixed metadata. Full native and framework/PCS gates
pass 14/14 tests with unchanged key, artifact size and tracked memory peaks.
See [native column interaction evidence](../../../autoresearch/notes/2026-09-22-native-column-interaction/README.md).
Preparation still owns logical rows for projection/counters; replacing that
storage with directly generated main columns remains unfinished.

Native table registration now uses the same validated main-column/fixed-metadata
view as interactions. Full native/framework gates pass 14/14, and actual hash
counter-array parity passes in the 4/4 hash gate. Key, artifact size and tracked
memory remain unchanged. See [column table registration evidence](../../../autoresearch/notes/2026-09-22-column-table-registration/README.md).
Only admission and main projection still require the producer's prepared live rows.

Prepared now owns final main columns and fixed metadata for all 20 AIRs, releasing
live-row arrays before handoff; producer projection is removed. Full native tests
pass 3/3 with unchanged key/artifact. Handoff retention grows to 130,557,704 bytes
and tracked worker peak grows to 1,667,299,422 bytes, while preparation peak stays
600,657,997 bytes. This is not a memory/speed win: worker allocation ordering needs
investigation before performance promotion. See [prepared-column evidence](../../../autoresearch/notes/2026-09-22-prepared-main-columns/README.md).
Temporary row construction before projection and direct adapter emission remain.

The commitment-staging lifetime follow-up releases request arena memory before
core proving while preserving the worker lease. The full diagnostic native gate
passes 3/3, including new malformed prepared-column rejections. Arena capacity
entering core falls from 591/890 MB to 67 MB; tracked worker peak falls from
1,667,299,422 to 1,600,143,854 bytes (4.03%). This recovers only part of the latest
regression: the earlier row-handoff worker peak was 1,567,077,617 bytes. Further
commitment-stage allocation investigation remains; no timing claim follows.
Evidence: `autoresearch/notes/2026-09-22-native-commit-scratch-release/README.md`.

Reusing one bounded inversion scratch buffer across the 20 sequential native AIR
cohorts resolves the remaining prepared-column worker regression. The scratch
buffer is freed before interaction commitment; output columns still use the
canonical generation path and independent proof verification passes. Focused
hash/native gates pass 7/7. Tracked worker peak is now **982,008,191 bytes**, down
38.63% from 1,600,143,854, with unchanged 116,382-byte artifact and key. This is a
memory result, not a timing claim. Evidence:
`autoresearch/notes/2026-09-22-native-shared-inversion/README.md`.

Native assembly now also projects G, XOR and byte-route source chunks directly
into final columns without concatenating their live rows. Trusted metadata checks
and the shared committed-order writer are preserved. Hash/native gates pass 7/7
with unchanged key and codec. Preparation peak remains 600,657,997 bytes and worker
peak remains 982,008,191 bytes: this eliminates staging but does not reduce the
measured overall peak. Upstream adapters still emit logical rows. Evidence:
`autoresearch/notes/2026-09-22-native-direct-cohort-projection/README.md`.

Merkle frames now emit G/XOR witnesses into exact group-owned ranges, eliminating
frame buffers followed by group concatenation. Live and fixed destination APIs
share their original canonical writers. Frame receipts have explicit ownership
and error cleanup independent of final group storage. FRI-group, native parent,
frame parity and allocation-failure gates pass (5 tests across focused gates).
Key/codec and 982,008,191-byte worker peak remain unchanged. Preparation peak rises
from 600,657,997 to 622,506,697 bytes; this regression remains open and no memory
or timing improvement is claimed. Group destinations are still logical rows;
upstream-to-final-column integration remains incomplete. Evidence:
`autoresearch/notes/2026-09-22-merkle-group-frame-destination/README.md`.

STARK path G/XOR accumulators now lend exact ranges through Merkle groups to
frame writers, removing the group-to-path copies. Owning and borrowed APIs share
one builder, and sizing is independently revalidated before writes. Focused
frame/native gates pass 4/4 including group ownership allocation failures and both
independent parent proofs. Preparation peak remains 622,506,697 bytes; worker peak
remains 982,008,191. Restoring frame byte-allocation order was tested and rejected
because it increased peak to 623,859,426; the older preparation baseline regression
is still open. Path arrays remain logical rows, so full direct-column emission is
not complete. Evidence:
`autoresearch/notes/2026-09-22-stark-path-group-destination/README.md`.

Transcript mix and PoW frames now emit G/XOR rows directly into transcript
storage; frame plans/results and query/secure-draw temporaries have scoped backing
allocations. Preparation peak falls **622,506,697 -> 382,427,223 bytes (38.57%)**,
resolving the preceding preparation regression. Handoff remains 130,557,704 bytes
and worker peak 982,008,191. Successful threaded preparation now qualifies at a
512 MiB cap, while 1 byte/64 MiB reject. Native/plan and sequence gates pass 6 tests
including independent parent and transcript proofs, failure cleanup and unchanged
key/codec. No timing claim follows. Draw/query row copies and final column emission
remain unfinished. Evidence:
`autoresearch/notes/2026-09-22-transcript-frame-destinations/README.md`.

Raw query batches now borrow transcript G/XOR ranges and pass per-block ranges
to frame writers, removing both intervening hash-row copies. A single canonical
plan supplies equal-length draw geometry and local output wires across the batch.
Query/native gates pass 4/4, covering empty/partial/multiple blocks, owning/borrowed
parity and independent parent proofs. Preparation/worker peaks remain 382,427,223
and 982,008,191 bytes; no memory or timing gain is claimed for this stage. Direct
secure-draw and final committed-column emission remain unfinished. Evidence:
`autoresearch/notes/2026-09-22-query-transcript-destinations/README.md`.

Bounded secure draws now emit G/XOR rows directly through transcript-owned ranges.
They retain every configured attempt and the original retry/counter constraints.
A shared draw-layout helper removes duplicate query/bounded sizing logic. Focused
query/bounded/native gates pass 5/5 with owned/borrowed parity, failure cleanup and
independent parent proofs. Memory remains 382,427,223 bytes preparation and
982,008,191 worker; no peak or latency gain is claimed. Fixed-attempt staging and
final committed-column emission remain unfinished. Evidence:
`autoresearch/notes/2026-09-22-bounded-draw-destinations/README.md`.

Fixed-attempt and raw secure draws now share owning/borrowed direct G/XOR
destinations and the canonical draw layout. Public preprocessing still binds actual
input bytes; private state keeps routed authentication. All transcript operation
branches now avoid G/XOR append copies. Draw/sequence/native gates pass 7/7 with
public/private/raw parity, failure cleanup, rejection checks and independent proofs.
Memory/key/codec remain unchanged (382,427,223-byte preparation, 982,008,191 worker);
no timing claim follows. Logical rows still require final committed-column emission.
Evidence: `autoresearch/notes/2026-09-22-fixed-draw-destinations/README.md`.

The canonical hash emitter now has a native main-column destination with separate
zero-main witness metadata and logical boundary rows. Focused hash tests pass 5/5:
complete row reconstruction, offsets/padding, boundary and interaction parity,
shape rejection and existing vectors. This sink is not yet wired into parent
orchestration; parent-wide geometry, metadata admission and ownership transfer must
be integrated before native proof qualification. No new production memory/timing
claim. The concrete integration steps are recorded in
`autoresearch/notes/2026-09-22-hash-main-column-destination/README.md`.

Native transcript replay/planning is now separate from live emission, with explicit
success-only ownership transfer. State plans combined transcript/path hash domains
before emission and validates them afterward: G 46,648 +39,816 =86,464, XOR 24,704,
logs 17/15. Plan/native gates pass 5/5, including failed-emission retry, geometry
mutations and independent parent proofs. Preparation peak is 382,427,279 bytes
(+56); other measured ownership/key/codec values are unchanged. This supplies
geometry for the new column sink but adapters still emit logical rows. Evidence:
`autoresearch/notes/2026-09-22-native-hash-layout-planning/README.md`.

## Evidence and upstream scope

The inspected [ZisK alpha release](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha)
is commit `02d2ae7b711454ce4574d852f8bfbddbfcbb1d67`. Its release notes describe an
optional BLAKE3 recursive configuration and a seven-round compression precompile.
They also describe scheduling and witness-generation changes. This is evidence
for the architecture, not a controlled measurement of the hash change alone.
The earlier research checkout's tag resolved to
`5c5f81c96929abed88894473ec6060b1b545b5c5`; preserve both identities rather than
silently attributing earlier source inspection to the later release.

Release Cargo.lock uses `proofman-fields` 1.3.0-alpha, checksum
`eb8d460b2e0e01f448eb78bd5486877239130674572be8f5c334bc86948cd65b`.
Inspected reference implementation: Proofman
`d485fac207679076958b502554fb595568c2f954`,
`fields/src/blake3_core.rs` and `fields/src/blake3_transcript.rs`.
That commit is not asserted identical to the published crate. The transferable
idea is using the full BLAKE3 construction with a compression backend, rather
than replacing a Poseidon permutation inside its existing sponge. Goldilocks
transcript word reduction is not directly reusable over M31.

## Implemented reference protocol

`src/core/channel/blake3.zig` and
`src/core/vcs_lifted/blake3_merkle.zig` export an explicit experimental suite.
They reuse the existing std-backed `Blake3Hasher`; no new production dependency
or default-suite change. Protocol identifier: `stwo.blake3.experimental.v1`.
Every hash starts with that exact ASCII string and one operation byte:

| Tag | Encoding after protocol prefix and tag |
| --- | --- |
| 0, initial state | empty |
| 1, mix words | previous digest, u64 word count, u32 words |
| 2, mix QM31 | previous digest, u64 QM31 count, four u32 coordinates per value |
| 3, mix integer | previous digest, u64 value |
| 4, mix root | previous digest, full 32-byte root |
| 5, draw | current digest, u64 draw index |
| 6, PoW | current digest, u32 difficulty, u64 nonce |
| 7, leaf | concatenated canonical M31 values, each encoded as u32 |
| 8, node | full left digest, full right digest |

`src/core/channel/blake3_frame.zig` is now the sole protocol-byte author. Native
channel/Merkle hashing and recursive witness messages share its streaming writer;
materializing a frame is optional and is not done by the native hot path. The
original independent protocol-vector pins still pass. A complete CPU STARK also
verifies a canonically framed Merkle node against the native hasher, with public
child digests. See [framing evidence](../../../autoresearch/notes/2026-09-21-blake3-framing/README.md).

All integers are little endian. Absorption updates the digest and resets the
draw index. Draws increment a checked counter without updating the digest.
For base-field sampling, reject an eight-word draw if any word is >= 2p,
then reduce each accepted word modulo p = 2^31-1. Each output has exactly two
preimages. Single-QM31 draws consume one block and use its first four words;
bulk draws consume up to two QM31 per block, matching the existing PCS API's
consumption convention. PoW checks trailing zero bits in the first little-endian
u32 and rejects difficulty above 32. The initial state is pinned against an
independent oracle because Zig 0.15.2's BLAKE3 implementation fails to evaluate
this short input at comptime; runtime hashing is tested.

Digests remain `[32]u8`. There is no M31 digest reduction and no device-family ID
advertised by this new hasher. This protocol has not received cryptographic
review; the identifier deliberately says experimental. The primitive's digest
size alone does not establish 128-bit soundness for the entire M31/QM31 proof.

## Migration boundaries and implementation order

| Boundary | Existing implementation | Required migration |
| --- | --- | --- |
| Native commitments/channel | Core BLAKE2 paths; recursion `poseidon2_channel.zig` | BLAKE3 suite is now a CPU oracle; qualify generic proving and serialization before selecting it |
| Scheduled Fiat–Shamir | `native_scheduled_channel.zig`, transcript witness and verifier schedule | Constrain identical byte framing, draw indices, field rejection, roots and PoW |
| Recursive hash provider | Typed Poseidon components, `detached_parent_catalog_v1.zig` | Typed BLAKE3 compression plus framing/chaining constraints; exact lookup closure |
| Trace/FRI authentication | Merkle witness components and `fixed_wire_adapter.zig` | Lossless digest limbs, BLAKE3 path verification, all child roots authenticated |
| Program/memory statements | `air/memory_commitment`, segment statement wire | New commitment suite and statement version, recomputed roots and empty-tree hashes |
| Keys/proof identities | `engine_protocol.zig`, protocol identities, canonical proof identity, trusted artifacts | Bind family and full protocol definition into trusted key and wire admission; reject mismatches before interpretation |
| Metal | `hash_domain.zig`, runtime ABI, commitment/FRI kernels, typed AOT | New explicit family, BLAKE3 kernels and generated recursive evaluator, CPU parity and actual dispatch evidence |
| Product defaults | RISC-V leaf, parent, CSP scripts and docs | Switch together after end-to-end qualification; retire old prover selection and redundant code |

The shared seven-round compression schedule and typed degree-two G arithmetic
reference are now implemented; see
[compression evidence](../../../autoresearch/notes/2026-09-21-blake3-compression/README.md).
Four focused tests pass, including complete witness-coordinate mutation and
standard hash parity across chunk boundaries. This is not a qualified recursive
provider: the reference has 704 Boolean columns per G and no authenticated
inter-call relations. A compact typed G now uses 124 columns, 80 degree-two
equations and 56 requests to existing byte-pair/bitwise schemas. Its three
focused tests cover equivalence, mutation and table membership; see
[compact component evidence](../../../autoresearch/notes/2026-09-21-blake3-packed/README.md).
Typed G and feedforward XOR call components now compile through the canonical
relation binding, with a fixed 272-wire compression plan and a writer for all
72 rows. Exact signed multiset tests close both wires and canonical production
lookup-counter rows; see [wiring evidence](../../../autoresearch/notes/2026-09-21-blake3-wiring/README.md).
A standalone CPU compression STARK now commits the G, XOR and public-boundary
components together with the production bitwise and byte-pair tables. The core
verifier accepts it using independently reconstructed preprocessing and matching
BLAKE3 transcript draws. Substituted preprocessing roots and changed public
outputs fail root admission. The test uses eight queries and zero PoW solely to
keep integration checks short; it is not a production-security performance result.
See [committed proof evidence](../../../autoresearch/notes/2026-09-21-blake3-committed/README.md).

A canonical full-hash DAG now expands fixed public message lengths into the same
G/XOR wire circuit. It handles empty input, zero-padded partial blocks, chunk
counters, CHUNK_START/END, left-complete chunk trees, PARENT and ROOT. Chaining
values share wires across compression calls; they are private intermediates,
not additional public claims or values recomputed by the verifier. The first
eight words of the root output form the ordinary 32-byte digest. Keyed hashing
and XOF are outside the current unkeyed protocol suite.

`test-blake3-hash` checks standard-library parity across 18 lengths up to 8193
bytes, exact global wire closure, mutations and allocation failures.
`test-blake3-proof` now verifies full hash STARKs for 0, 65 and 2049 bytes, covering
empty/partial blocks and an unbalanced three-chunk tree. It rebuilds fixed
columns from public message/digest and length-owned topology without computing
the private rounds. See [full-hash evidence](../../../autoresearch/notes/2026-09-21-blake3-full-hash/README.md).

These are public-message hash proof gates. A typed private-input bridge now
copies complete caller word tuples into the hash graph and constrains unused
partial-word bytes to zero. Its trusted preprocessing receives length and caller
wire range, never message bytes. Compiler/export and exact global wire tests pass,
including rejection of missing caller emissions and changed endpoints. See
[private-input evidence](../../../autoresearch/notes/2026-09-21-blake3-private-input/README.md).
The bridge now also passes a complete CPU STARK for H(H(message)): the first
hash's digest is omitted from the public statement and its output wires feed the
second hash through the bridge. Trusted preprocessing uses only original message,
final digest and canonical schedules. This is witness-only composition, not a
zero-knowledge claim. See [private composition evidence](../../../autoresearch/notes/2026-09-21-blake3-private-proof/README.md).
Typed byte routing now also assembles canonical Merkle frames from authenticated
child digest words at unaligned offsets. Symbolic digest callbacks in the shared
frame writer derive the routing, and producer use counts reflect every consumer.
A complete CPU proof composes two native-framed leaf hashes with their parent;
the intermediate leaf digests are witness-only and its final root matches the
native commitment hasher. See [byte-routing evidence](../../../autoresearch/notes/2026-09-21-blake3-byte-routing/README.md).

Binary Merkle paths now also have a sibling-free preprocessing builder and a
typed bounded private-word source. Native four-leaf paths match at all positions;
complete CPU STARKs verify depth zero and depth two with private siblings. Their
index and depth are public statement coordinates in this gate. See
[path evidence](../../../autoresearch/notes/2026-09-22-blake3-merkle-path/README.md).
Production recursion must still bind query indices to constrained Fiat–Shamir
challenges and account for lifted PCS/FRI path geometry and batching.

Typed challenge extraction now proves the native eight-word rejection predicate
and reduction to M31, including rejection in an unused half-block. A complete
CPU STARK binds a canonical draw frame to all eight scalar outputs with real
range providers and trusted preprocessing. See
[challenge evidence](../../../autoresearch/notes/2026-09-22-blake3-challenge/README.md).
The frame's state and start index remain public. Ordered rejection retries now
have a reusable builder: consecutive counters, rejected intermediate attempts,
and one accepted final attempt. The complete draw proof uses this builder; a
skip past an accepted attempt fails its status constraints. See
[ordered-draw evidence](../../../autoresearch/notes/2026-09-22-blake3-ordered-draw/README.md).
Single-QM31 consumption is also supported: check all eight words, emit four,
discard the upper half and advance the draw counter. Consecutive single calls
match the native channel, and complete CPU proofs cover both consumption modes.
See [consumption evidence](../../../autoresearch/notes/2026-09-22-blake3-single-draw/README.md).
A shared digest-role router now supports state/root inputs for draw, integer
absorption, root absorption and PoW frames, using the native frame writer and
existing typed byte-selection AIR. Merkle routing delegates to this same path.
Missing, duplicate and unused digest bindings are rejected. See
[frame-routing evidence](../../../autoresearch/notes/2026-09-22-blake3-frame-routing/README.md).
A reusable routed-frame witness now replaces message-input boundaries with
authenticated routes. A complete CPU proof verifies two native integer
absorptions with a private intermediate state; independently reconstructed fixed
columns do not depend on that state's bytes. See
[private-transition evidence](../../../autoresearch/notes/2026-09-22-blake3-private-transition/README.md).
Ordered draws now accept authenticated private state and sum its routed consumer
counts across attempts. A complete CPU STARK proves native absorption followed
by a single secure challenge, without exposing the intermediate state. See
[private-draw evidence](../../../autoresearch/notes/2026-09-22-blake3-private-draw/README.md).
Integer absorption and secure draws now share a sequence builder that derives
state links and draw counters from operation order, including absorption resets.
A complete CPU proof covers absorb/draw/draw/absorb/draw with private states.
See [sequence evidence](../../../autoresearch/notes/2026-09-22-blake3-transcript-sequence/README.md).
The same builder now supports all native absorption variants: integer, words,
secure fields and roots. An eleven-operation CPU proof matches six native
challenges across those transitions; empty word/field arrays are also checked.
Payloads are public in this gate and intermediate states are private. See
[absorption evidence](../../../autoresearch/notes/2026-09-22-blake3-all-absorption/README.md).
Raw query masking now has a typed bytewise-AND component and a complete CPU
proof binding a canonical draw to eight query indices. Packed bytes preserve
31-bit index values without M31 aliasing; field rejection is not applied.
See [query evidence](../../../autoresearch/notes/2026-09-22-blake3-query-mask/README.md).
Private-state query batching now preserves native raw order, duplicates, partial
blocks and counter consumption. A complete CPU proof derives nine indices from
an absorption-produced private state; unit cases cover zero through three blocks.
See [batch evidence](../../../autoresearch/notes/2026-09-22-blake3-query-batch/README.md).
Raw query batches now participate in the same transcript sequence as secure
draws and all absorption types. A sixteen-operation CPU proof checks shared
counter advancement, partial batches, absorption reset and empty batches across
six AIR components. See
[mixed-sequence evidence](../../../autoresearch/notes/2026-09-22-blake3-mixed-query-sequence/README.md).
PoW verification is now part of the sequence: the native low-bit hash predicate
preserves state/counter, and nonce absorption remains explicit. A twenty-operation
CPU proof includes a native-generated 8-bit nonce, a subsequent draw, nonce
absorption and another draw. Boundary tests cover zero difficulty, invalid
nonces, full 32-bit masking and unsupported difficulty. See
[PoW evidence](../../../autoresearch/notes/2026-09-22-blake3-pow-sequence/README.md).
Canonical query-to-path admission now reuses native sorting/deduplication/folding
and checks exact path lists. A complete CPU proof constrains nine raw queries
and their two unique private-sibling paths together. Folded mapping has unit
coverage; the proof uses unfolded depth-one paths and public auxiliary query
coordinates. See
[path-admission evidence](../../../autoresearch/notes/2026-09-22-blake3-query-path/README.md).
Lifted leaf geometry now matches real native BLAKE3 commitments/decommitments:
parity-preserving column projection, ascending column size and stable equal-size
order. A complete typed depth-three path proof authenticates a native captured
opening to its real root. See
[lifted-path evidence](../../../autoresearch/notes/2026-09-22-blake3-lifted-path/README.md).
A typed canonical QM31-to-byte encoder now connects arithmetic wires to packed
hash words, excluding both the modulus encoding and high-bit aliases. A complete
CPU proof verifies source tuple → canonical bytes → BLAKE3 hash using the private
input bridge. See
[field-encoding evidence](../../../autoresearch/notes/2026-09-22-blake3-field-encoding/README.md).
Indexed word payload routing now shares native frame serialization for leaves,
secure fields and raw words. The canonical field proof now hashes a framed leaf
through authenticated payload wires, and trusted fixed columns are independent
of payload bytes. Native protocol vectors remain unchanged. See
[private-framing evidence](../../../autoresearch/notes/2026-09-22-blake3-private-payload-framing/README.md).
Lifted opening batches now have shape/range and repeated-projected-row
consistency checks, using one reusable map across columns. Real native
mixed-size openings pass; conflicting short-column values are rejected before
leaf construction in the integration fixture. See
[opening-admission evidence](../../../autoresearch/notes/2026-09-22-blake3-lifted-query-admission/README.md).
Actual successful CPU PCS captures now feed typed trace and FRI path preparation,
including mixed column sizes, raw duplicate queries and fold schedules 1, 2 and
4. FRI capture paths begin above the folding subtree; the adapter reconstructs
intra-subtree siblings with native leaf packing before passing an original leaf
path to the typed witness. One captured packed FRI path also verifies in a
complete CPU outer proof. This does not yet bind sibling-leaf values to recursive
FRI arithmetic. See
[PCS capture evidence](../../../autoresearch/notes/2026-09-22-blake3-pcs-capture/README.md).
The next gate closes that sibling-value gap for a complete folding group: every
QM31 tuple feeds a canonical field-byte encoder, every packed leaf is hashed in
typed constraints, and shared internal nodes feed the upper path. A real fold4
group (16 QM31 values, four packed leaves) verifies in one six-component CPU
proof; changing a source tuple in the last leaf invalidates the statement.
Native captures for fold1/2/4 and tail layers agree with the complete typed tree.
The source tuples are still public auxiliary fixture inputs; replacing those
sources with authenticated production FRI arithmetic/transcript wiring remains.
See [complete-group evidence](../../../autoresearch/notes/2026-09-22-blake3-fri-group/README.md).
A hash-independent owned arithmetic capture adapter now checks routing and
canonical field inputs against a supplied FRI profile. Actual BLAKE3 captures for
fold1/2/4 satisfy the existing canonical recursive FRI graph, and every arithmetic
input coordinate matches its captured hash value. Mutated DEEP answers and
misrouted positions are rejected. This is host evaluation of the full arithmetic
graph, not yet a combined outer proof with the hash components; the scalar
FRI-value relation must still be connected to the QM31 encoding source.
See [arithmetic capture evidence](../../../autoresearch/notes/2026-09-22-blake3-fri-arithmetic/README.md).
A typed scalar-to-QM31 repacking component now consumes the four scalar wires
identified by canonical FRI graph bindings and emits the tuple used by the hash
encoder. The complete group gate includes that connection in its seven-component
proof. Scalar source boundaries remain public fixture inputs; full arithmetic
operation rows and their additional producer counts are not yet part of this
outer proof. See [scalar-wire evidence](../../../autoresearch/notes/2026-09-22-fri-scalar-pack/README.md).
Canonical FRI hash wiring is now reusable: schedules and sorted extra reads are
derived from the authenticated graph bindings. The existing arithmetic lowering
accepts these exports, counts each extra read and generates operation invocations
for segment and binary modes. This removes the fixture-only node map, but those
arithmetic operation rows are still outside the complete hash-group proof.
See [wire-plan evidence](../../../autoresearch/notes/2026-09-22-fri-hash-wire-plan/README.md).
The arithmetic rows now pass a separate complete CPU STARK gate using the
existing multiply, inverse and linear AIRs with explicit proof-kind parameters.
It covers the canonical fold4 FRI circuit for all 17 queries of a real BLAKE3 PCS
capture, with graph-derived constants, inputs and zero-output anchors. This
advances beyond host-only evaluation. The arithmetic gate still has public
inputs; combining it with all authenticated hash paths and private shared
producers remains unfinished. See
[complete arithmetic proof](../../../autoresearch/notes/2026-09-22-fri-arithmetic-proof/README.md).
A combined ten-component proof now joins canonical FRI arithmetic and ALL captured
FRI paths: 17 queries across two layers, 34 folding groups and 1,224 shared
private scalar coordinates. The public FRI-value anchors are removed. Hash paths
and arithmetic consume the same producers with exact graph-plus-hash counts;
trusted fixed columns contain neither private value nor digest bytes. An exact
wire ledger also detects a changed private scalar emission. This closes the
separate-proof gap for the FRI subsystem. Transcript and PCS DEEP/trace admission
remain public-input boundaries, and production CPU/Metal migration is unfinished.
See [combined FRI proof](../../../autoresearch/notes/2026-09-22-blake3-combined-fri/README.md).
The combined proof now also constrains the actual standalone PCS transcript:
trace roots, sampled values, DEEP and FRI draws, terminal coefficients, PoW,
nonce absorption and raw queries. Twelve components share the same public
statement for transcript outputs/arithmetic/path indices; FRI opening values
remain private. The replay adapter preserves caller state on mismatches and
allocation failures and accepts an existing operation prefix. Full outer-STARK
prefix/composition/OODS admission and PCS DEEP/trace proof constraints remain.
See [PCS transcript evidence](../../../autoresearch/notes/2026-09-22-blake3-pcs-transcript/README.md).
The canonical PCS DEEP quotient circuit now participates in the same outer
proof, sharing public answer values with FRI and reusing existing arithmetic
components. The standalone fixture's OODS point/seed are now consistent, and an
altered sampled value is rejected. Trace queried values remain public inputs;
their authentication paths must still be joined. The fixture seed is explicitly
not a full STARK transcript draw. See
[combined DEEP evidence](../../../autoresearch/notes/2026-09-22-blake3-combined-deep/README.md).
The trace paths are now joined: all 17 paths for the mixed [6,4] columns reach
the public trace root and feed private base-field values into DEEP arithmetic.
Canonical scalar producers enforce literal zero extension coordinates, and
query-specific routes share producers for repeated projected column rows.
The thirteen-component proof and exact wire ledger pass, including changed
trace/FRI value audits. This closes the public trace-value boundary in the
standalone PCS fixture. Full outer-STARK transcript/composition/OODS admission
and production CPU/Metal/key qualification remain. See
[trace-join evidence](../../../autoresearch/notes/2026-09-22-blake3-trace-join/README.md).
A real full-STARK capture now qualifies the complete verifier transcript prefix:
composition randomness, composition commitment and OODS seed precede PCS opening
operations. The combined PCS proof supplies that capture after native verification;
a second typed proof verifies its entire transcript. Composition-root substitution
is rejected. This is full-STARK transcript qualification, not recursive proof of
its composition/OODS algebra or parent-of-parent qualification. See
[full-STARK prefix evidence](../../../autoresearch/notes/2026-09-22-blake3-stark-prefix/README.md).
The real capture now also qualifies its complete composition/OODS equation in a
separate typed arithmetic proof: all thirteen typed AIRs, both lookup tables,
claim balance, OODS circle mapping and split composition reconstruction. Existing
recorders and generic table equations remain the arithmetic authorities. The
combined gate verifies three complete proofs in 14 seconds on this host; this is
qualification runtime, not production recursion latency. Composition and transcript
still use separate public fixture statements. Joining them with the actual
full-STARK PCS into one parent remains required. See
[composition proof evidence](../../../autoresearch/notes/2026-09-22-blake3-composition-proof/README.md).
The actual four-tree STARK capture now supplies DEEP and FRI arithmetic alongside
composition in one typed arithmetic proof. Column degrees, ordered sample masks
and FRI schedule come from admitted components/configuration and are checked
against capture data. The owned DEEP adapter rejects shape, sample-order and
encoding mutations and preserves its data after source mutation. This removes the
standalone two-column restriction from arithmetic qualification. All three graphs
still use public fixture input boundaries; the full transcript and authentication
paths must join that same parent before recursive verification is complete. See
[full-STARK arithmetic evidence](../../../autoresearch/notes/2026-09-22-blake3-full-stark-arithmetic/README.md).
The full-STARK transcript now joins those three arithmetic graphs in the same
parent fixture. The transcript-only proof wrapper was removed; live and trusted
transcript rows feed the common typed roster with disjoint namespaces. The
combined gate now verifies two proofs and passes in 12 seconds / 1 GiB on this
host. This is test runtime, not qualified production recursion latency. Full
captured trace/FRI authentication paths are still absent from this parent, and
public fixture inputs have not become production private-input admission. See
[transcript/arithmetic join evidence](../../../autoresearch/notes/2026-09-22-blake3-transcript-arithmetic-join/README.md).
All four captured trace trees and every complete FRI folding group now join the
same parent fixture. Native query projection, lifted-column ordering and repeated
row consistency are checked; every prepared root matches its captured commitment.
The parent includes transcript, composition/OODS, DEEP, FRI and authentication
paths with public leaf values and private sibling words. Its combined gate passes
in 28 seconds / 6 GiB, reflecting the added hash work; these are fixture costs,
not production recursion performance. Fixed reusable keys, private child-proof
input admission, CPU/Metal and parent-of-parent qualification are still required.
See [full parent path evidence](../../../autoresearch/notes/2026-09-22-blake3-parent-paths/README.md).
A preprocessing audit identified the remaining child-dependent boundaries.
The transcript compiler now supports externally routed raw words and canonical
field encodings, with owned per-operation read multiplicities and namespace alias
rejection. Changed absorbed values retain identical fixed columns; a complete
proof with private input producers and a constrained native challenge passes.
The full parent still uses its public absorption operations pending shared-source
integration. Reusable keys additionally require dynamic query/path routing and
fixed-capacity rejection handling; this stage does not qualify a reusable key.
See [private absorption evidence and dependency inventory](../../../autoresearch/notes/2026-09-22-blake3-routed-transcript-inputs/README.md).
The parent now integrates routed claim and sample absorption. Canonical field
encoders read the same composition input wires, with exact additional consumer
counts. Claim producers are private and shared between composition and transcript;
sampled values retain public arithmetic anchors until DEEP's scalar inputs are
joined. The full eleven-AIR parent and the single-graph regression pass. Direct
claim anchors are removed, but other per-proof public outputs still prevent a
reusable production key. See
[shared parent input evidence](../../../autoresearch/notes/2026-09-22-blake3-parent-routed-inputs/README.md).
Sample values now share private sources across DEEP, composition and transcript.
The canonical DEEP input bindings select four scalar nodes per sample; weighted
instances of the existing packing AIR supply the sole secure tuple producer for
composition and the encoder. Both sets of public sample anchors are removed.
No AIR equations or semantic digest changed. Weighted tuple/mapping tests, the
full twelve-AIR parent and the shared arithmetic regression pass. Queried trace
and FRI opening values remain public; reusable-key and scheduling work remains.
See [private sample evidence](../../../autoresearch/notes/2026-09-22-blake3-private-parent-samples/README.md).
Queried trace and FRI opening values now share private sources with authentication.
Trace rows use canonical lifted-row producers and query-specific scalar routes;
FRI coordinates use existing packing and canonical field-byte encoding. Both the
leaf payload anchors and corresponding arithmetic anchors are removed. The full
thirteen-AIR parent and arithmetic regression pass. No AIR equations or identities
changed. Public challenge/query/root/terminal inputs and dynamic schedule handling
still prevent reusable production keys. See
[private opening evidence](../../../autoresearch/notes/2026-09-22-blake3-private-opening-inputs/README.md).
DEEP answers now feed FRI through private scalar routes, and FRI terminal
coefficients feed transcript absorption through private packing and encoding.
Their public arithmetic and absorption anchors are removed. Owned canonical input
mappings reject missing/duplicate coordinates, and the full parent, regression and
mapping/packing unit pass. No AIR identity changed. Public challenge, commitment,
query and nonce boundaries plus dynamic scheduling remain before key reuse. See
[private terminal-input evidence](../../../autoresearch/notes/2026-09-22-blake3-private-terminal-inputs/README.md).

Every secure challenge in the joined parent now comes directly from a constrained
BLAKE3 transcript output: universal relation draws, composition randomness, OODS
seed, DEEP randomness, and each FRI alpha. Protocol roles identify outputs;
canonical graph bindings identify consumers. Existing scalar routes and weighted
packing distribute each accepted coordinate, including the OODS seed shared by
composition and DEEP. Both transcript and arithmetic public challenge anchors
are removed, without changing AIR equations or semantic identities. The focused
mapping, routed/public transcript, and complete parent gates pass (six tests).
Commitments, query routing, nonces and per-capture rejection/schedule geometry
still block reusable production qualification. See
[private challenge evidence](../../../autoresearch/notes/2026-09-22-blake3-private-challenges/README.md).

Trace and FRI commitment roots now share canonical eight-word sources between
transcript absorption and all complete authentication paths. Existing byte-route
constraints bind computed root bytes to these sources using negative output
multiplicity. The preprocessed-tree root retains its public trusted-key anchor;
other roots use bounded private-word producers. Public root values are removed
from the non-key fixed columns without changing AIR equations or identities.
Seven focused tests pass, including public API regression proofs and the joined
parent proof. See
[shared root evidence](../../../autoresearch/notes/2026-09-22-blake3-private-roots/README.md).

Transcript query outputs now feed DEEP positions through constrained canonical
field encodings. DEEP query bits share scalar sources with FRI and the new typed
Merkle word selector. That selector authenticates the direction bit and orders
both child words without direction-dependent fixed columns. Trace projection
preserves raw bit zero; FRI consumes the appropriate consecutive folded bits.
FRI positions and offsets are private and checked by its arithmetic. The joined
parent now uses fourteen AIRs. Nine distinct focused tests pass, including the
new selector's typed identity/export/mutation checks, a native lifted-projection
oracle, and the complete parent proof. See
[private query evidence](../../../autoresearch/notes/2026-09-22-blake3-private-queries/README.md).

PoW and subsequent nonce absorption now share two bounded private-word sources.
Canonical framing exposes the u64 as two little-endian words without changing
serialized bytes or the protocol identity. The parent combines exact read counts
from both operations; nonce values are removed from fixed columns. No AIR changed.
Six focused tests pass, including a proof with nonzero PoW and nonzero upper
nonce bits, manual frame-byte parity, public transcript regressions, and the
complete parent. See
[private nonce evidence](../../../autoresearch/notes/2026-09-22-blake3-private-nonce/README.md).

The retry path now has a genuine native regression fixture: absorbing integer
418109725 produces a first raw word of 0xffffffff, rejecting the first block;
the second block accepts. Its state and three raw blocks are pinned. Both native
bulk extraction and a complete transcript proof exercise this retry and subsequent
counter/reset behavior. All four focused tests pass. See
[real rejection evidence](../../../autoresearch/notes/2026-09-22-blake3-real-rejection/README.md).

A typed first-acceptance controller now consumes all candidate statuses, emits
only the first accepted challenge, and authenticates the consumed attempt ordinal.
A complete hash/controller proof covers reject/accept/accept and discards the
third candidate; all short acceptance patterns and legacy draw behavior are tested.
The new raw-attempt export API shares existing draw/hash witness code. Its physical
batch counter is explicitly distinct from the selected native counter. Four
focused tests pass. See
[retry controller evidence](../../../autoresearch/notes/2026-09-22-blake3-retry-controller/README.md).

Checked private u64 advancement is now implemented and joined to bounded retries.
Byte carry/range constraints reject overflow and freeze the counter after the
first acceptance. Draw-index bytes feed hashing through authenticated payload
routes. Native comparisons cover real rejection, cross-word carries and padding
at u64-max; a complete bounded hash/controller/counter proof passes. Eight distinct
focused tests pass. See
[private counter evidence](../../../autoresearch/notes/2026-09-22-blake3-private-counters/README.md).
Bounded retries now feed the complete transcript and joined parent fixture.
The verifier supplies a capacity of three in this fixture; recorded attempt counts
have no fixed-column authority. Private counter ports chain between secure draws
and raw query batches. Absorption resets the counter to constrained zero; PoW and
empty queries preserve it. Raw query extraction never rejection-samples. The parent
roster includes retry-control and checked counter-step AIRs alongside its existing
hash, arithmetic, private inputs, query and Merkle path components.

Five distinct focused tests pass, including the joined parent. The strengthened
bounded-transcript test produces two complete CPU proofs: genuine rejection plus
consecutive single/bulk draws and resets, and independent raw 0xffffffff extraction
followed by a secure draw. Zeroed attempt metadata preserves live rows and trusted
preprocessing. Capacity errors and wrong public challenge preprocessing are tested.
See [bounded transcript evidence](../../../autoresearch/notes/2026-09-22-blake3-bounded-transcript/README.md).
These are qualification fixtures; their timings do not establish an end-to-end
BLAKE3 speedup. Fixed capacity adds recursive hash work that must be included in
subsequent comparisons.

A sparse read-only consistency replacement is now qualified as a separate proof
fragment. Sorted u32 index/value rows enforce integer order and equal values at
equal indices, using the existing multiset and byte-range providers. An input
adapter binds independent bounded index and scalar-value ports. Three focused
tests pass, including a complete joined input-adapter/table CPU proof with
unsorted duplicates and u32 boundary cases. See
[read-only consistency evidence](../../../autoresearch/notes/2026-09-22-readonly-consistency/README.md).
The read-only components are now joined to the complete parent fixture. Shared
projected index bytes come from authenticated DEEP bits through existing packing
and affine-routing constraints. Independent private opening-value producers feed
arithmetic, leaf encoding and read-only input adapters. Per-column sorted tables
use fixed row counts and ranks. The previous capture-dependent canonical scalar
map and its alias-derived IDs/multiplicities have been removed.

The projection regression proves fixed wiring invariance under changed queries
and duplicate patterns, including 31-bit projection boundaries. The complete
18-AIR parent gate passes with the new connections; its 32-second test runtime is
qualification evidence, not a matched performance result. See
[parent alias-join evidence](../../../autoresearch/notes/2026-09-22-parent-alias-join/README.md).

A reusable bounded transcript plan now retains trusted preprocessing and binds
capacity, protocol/AIR identities, fixed rows and semantic export/read mappings
into a structural fingerprint. It accepts changed private routed inputs and ignores
recorded attempt counts, while rejecting public shape/role changes and explicit
capacity exhaustion. Transcript proofs and the parent prefix consume this plan;
the parent fixture passes capacity explicitly and safely transfers preprocessing
ownership before adding its separate key-root boundaries. Three distinct focused
tests pass, including allocation-failure/arena-growth checks and complete proofs.
See [transcript-plan evidence](../../../autoresearch/notes/2026-09-22-transcript-plan/README.md).
The fingerprint is not a PCS root or full parent key. The parent fixture still
constructs a plan per invocation; production caching remains unfinished.

The normal native V2 RISC-V pipeline now produces and independently verifies
BLAKE3 nonfinal/final segment proofs through an explicit generic-engine selection.
The engine and recursive fixtures share coherent protocol aliases. The same
engine-parameterized test also verifies the default Blake2s path; a BLAKE3 proof
is rejected under the default suite's preprocessing root. Actual runner snapshot
identities replace stale placeholder memory digests in these tests, without
weakening statement admission. All three focused tests pass, including the
existing rebased leaf-local V3 default-suite proof.

See [native BLAKE3 segment evidence](../../../autoresearch/notes/2026-09-22-native-blake3-segment/README.md).
This one-query, zero-PoW diagnostic was slower with BLAKE3 than Blake2s and establishes
no speedup. It preserves existing V2 program/state/sparse-memory and guest Poseidon
semantics; only the proof suite is selected. The native V2 capture now has an owning transcript adapter that reuses canonical
physical-manifest encoders and matches the independently verified native channel
across 227 operations, all 12 relation pairs, and the final draw counter. Changed
interaction claims are rejected. Its native relation exports have a distinct role
and cannot silently enter fixture universal-relation links. See
[native transcript evidence](../../../autoresearch/notes/2026-09-22-native-blake3-transcript/README.md).
This qualifies transcript witness preparation, not a complete recursive parent.
The real BLAKE3 capture also satisfies the native composition recorder (13,929
nodes, 29 zero outputs), and 104 scalar challenge routes now connect transcript
roles to its authenticated input bindings. See
[native composition evidence](../../../autoresearch/notes/2026-09-22-native-blake3-composition-links/README.md).
These routes are prepared but not yet proved inside a complete native parent.
Native claim/sample encoding rows are now prepared for 28 canonical aggregates
and 705 samples (733 secure values, 2,932 scalar connections), with exact
transcript read multiplicities and mutation rejection. See
[native payload evidence](../../../autoresearch/notes/2026-09-22-native-blake3-payload-links/README.md).
Native PCS/DEEP preparation now evaluates the real capture with its authenticated
geometry (16,069 nodes, 34 zero outputs). All 705 samples have 2,820 explicit
shared scalar routes between composition, encoding and DEEP; the source rows
carry exact additional consumption counts. An arena ownership leak exposed by
the larger capture was fixed and covered by an allocation-growth regression. See
[native DEEP evidence](../../../autoresearch/notes/2026-09-22-native-blake3-deep-join/README.md).
Native FRI preparation also evaluates the real capture (3,684 nodes, 94 zero
outputs) and constructs explicit DEEP-answer scalar routes, rejecting changed
answers and terminal coefficients. See
[native FRI evidence](../../../autoresearch/notes/2026-09-22-native-blake3-fri-join/README.md).
Native transcript challenge routes now cover DEEP and FRI: 88 scalar connections
in this gate, including four shared OODS coordinates with exact additional
consumption counts. Missing FRI draws and altered DEEP randomness reject. See
[native PCS challenge evidence](../../../autoresearch/notes/2026-09-22-native-blake3-pcs-challenges/README.md).
Native terminal coefficients now have canonical transcript encoding rows, using
the same scalar/pack/byte constructor as claims and samples. Missing receipts
and changed coefficient payloads reject. See
[native terminal evidence](../../../autoresearch/notes/2026-09-22-native-blake3-terminal-encoding/README.md).
Native query preparation now connects transcript position bytes, all 31 shared
DEEP/FRI query bits, and FRI derived positions/offsets (104 scalar rows in the
one-query gate). Missing outputs and changed query values reject. See
[native query evidence](../../../autoresearch/notes/2026-09-22-native-blake3-query-join/README.md).
All native trace/FRI paths now use the canonical shared builder, with 39,816 G
rows, 2,352 selector rows and 781 opening sources in the gate. Query rows account
for path/projection reads; successful replanning replaces counts and failures
restore them. The existing joined FRI fixture proof also passes the shared code.
See [native path evidence](../../../autoresearch/notes/2026-09-22-native-blake3-paths/README.md).
All 781 native opening sources now have scalar producer rows with exact
arithmetic, encoding/packing and readonly-adapter use counts. The adapter derives
the required inventory from typed graph roles and rejects missing, duplicate or
changed sources. See
[native opening evidence](../../../autoresearch/notes/2026-09-22-native-blake3-opening-producers/README.md).
Native root/nonce source rows now cover all transcript/path reads: 188 private
words and eight fixed preprocessing-key boundary words. The key root is checked
with the native statement-derived verifier; each nonce requires both its PoW
and absorption receipts. Changed roots/nonces and missing receipts reject. See
[native root/nonce evidence](../../../autoresearch/notes/2026-09-22-native-blake3-root-nonce/README.md).
The native public-boundary graph now evaluates the verified BLAKE3 capture
through the existing canonical authority (4,351 nodes, 1,332 inputs, 21 zero
outputs). A changed published sum rejects. See
[native public-boundary evidence](../../../autoresearch/notes/2026-09-22-native-blake3-public-boundary/README.md).
Public-boundary challenge sharing now routes 32 coordinates from the native
composition sources. A 116-input arithmetic graph enforces component aggregate
plus public-total cancellation with four independent zero outputs. Mutated
aggregate values, role mappings and stored boundary evaluations reject. See
[native public-link evidence](../../../autoresearch/notes/2026-09-22-native-blake3-public-links/README.md).
Public wire/byte/selector source closure now emits 1,280 public coordinate rows
and sixteen private published-sum producers. Alongside the 32 challenge and four
total routes, these cover all 1,332 public-boundary inputs. The canonical native
statement encoder determines the exact transcript prefix positions and contents;
changed statement words reject. See
[native public-source evidence](../../../autoresearch/notes/2026-09-22-native-blake3-public-sources/README.md).
The complete experimental native-child parent now proves and independently
verifies all five graphs (VM composition, DEEP, FRI, public boundary, aggregate
cancellation) through the eighteen typed AIR components. Exact producer admission
covers 8,376 arithmetic inputs and rejects duplicate/missing opening producers;
all three activation selectors are fixed to one. The joined witness has 86,464
BLAKE3 G rows, 7,093 scalar rows and 29,488 arithmetic rows. See
[native parent evidence](../../../autoresearch/notes/2026-09-22-native-blake3-parent/README.md).
This gate uses an inner q1/PoW0 native proof and an outer q8/PoW0 parent proof.
Public statement operands still specialize preprocessing. The parent now has a distinct key-admission transcript binding its suite,
profile, child statement/configuration, five graphs, transcript plan, typed
roster/registry and fixed preprocessing root. A verifier-owned expected key
identity is mandatory. Wrong pins, versions, configurations, graph identities,
lifting presence and root substitutions reject; the full parent verifies under
this transcript. See
[native parent admission evidence](../../../autoresearch/notes/2026-09-22-native-blake3-parent-admission/README.md).
The canonical in-memory artifact owner and witness-independent verifier are now
implemented. The verifier rebuilds typed components and column geometry from
the pinned key, consumes proofs on all paths, and returns an owned verified
capture. Compensated claim tampering passes cancellation admission but rejects
in core verification. Parent-specific claim absorption explicitly advances the
protocol to version 2 and rejects version-1 keys. See
[native parent verifier evidence](../../../autoresearch/notes/2026-09-22-native-blake3-parent-verifier/README.md).
The bounded external codec now round-trips the real parent artifact
byte-for-byte (111,428 bytes) and feeds independent verification. Its fixed
372-byte header and body preflight enforce the verifier pin, canonical claims,
exact lengths, protocol configuration and allocation geometry before proof
decoding. Preflight and verification share one component owner. Malformed
headers, lengths, claims, configurations and commitment-count prefixes reject.
See [native parent codec evidence](../../../autoresearch/notes/2026-09-22-native-blake3-parent-codec/README.md).
The standalone backend-injected producer now retains authenticated definitions,
relation plans, compiled component templates and fixed columns in a stable
per-key plan. Request metadata is checked before proving; scratch and proof
ownership are separate. The real artifact verifies after plan destruction, with
no allocator leaks and no plan-arena growth during the request. Shared row
projection has one canonical implementation. See
[native parent producer evidence](../../../autoresearch/notes/2026-09-22-native-blake3-parent-producer/README.md).
Canonical capture preparation now coordinates every validated adapter and
returns only owned rows plus pointer-free key context, releasing intermediate
owners before return. The mutation fleet uses the same State implementation;
compact preparation produces identical rows/context and completes standalone
proving, transport and independent verification. See
[native parent preparation evidence](../../../autoresearch/notes/2026-09-22-native-blake3-parent-preparation/README.md).
Fixed host columns and their commitment tree are now reused; the bounded local
pipeline overlaps preparation and proving. Production scheduler integration
remains pending. Admission permits only the diagnostic profile. Production
security-profile qualification remains unfinished; this is not a production
migration or statement-independent key. Production defaults remain unchanged.

Remaining work: production capacity classes and overflow admission; production
child-proof source and reusable-key/artifact qualification; Metal support; and
CPU/Metal parent-of-parent qualification. Removing this specific source of
query-dependent preprocessing does not establish a complete reusable key.
Production recursion still uses Poseidon. New protocol/key/artifact identities must be admitted
explicitly; equal digest lengths do not authorize interpreting new proof bytes under
old keys.

The compact provider uses four bounded bytes per 32-bit word, preserving every
bit. Additions use bounded byte carries; XOR and rotations use canonical bitwise
and byte-pair tables. The shared typed arithmetic and relation compiler remain
the only constraint authors. Full construction reference:
[BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).

Retain guest-visible Poseidon precompile semantics when a program explicitly
requests Poseidon. Ethereum Keccak and structural SHA-256 artifact pins are
separate obligations. Migrating the prover's commitments does not authorize
changing the guest's program or making existing artifact identifiers ambiguous.

## Qualification and performance

The focused gate is `test-blake3-protocol` in the RISC-V CPU integration build.
It covers official primitive vectors across block/chunk boundaries, streaming,
independent protocol vectors, rejection boundaries, domain separation, a
nonconstant CPU PCS/FRI proof, tampered sampled-value rejection, every root byte's
high-bit mutation, wrong BLAKE2 family rejection, and matching final transcripts.
This target is PCS/FRI qualification. `test-blake3-framework` adds typed boundary,
export and padded interaction checks; `test-blake3-proof` produces and verifies a
compression and full-hash STARKs. None is a complete RISC-V or recursive parent proof.

Native diagnostic on M5 Max / 64 GiB, Zig 0.15.2 ReleaseSafe, six alternating
pairs, 2048 hashes per sample:

| Operation | Poseidon median ns/hash | BLAKE3 median ns/hash | Median paired speedup |
| --- | ---: | ---: | ---: |
| Leaf, 16 M31 words | 1786.45 | 204.56 | 8.76x |
| Leaf, 256 M31 words | 19687.54 | 1826.48 | 10.79x |
| Leaf, 4096 M31 words | 305724.42 | 27860.52 | 10.99x |
| Internal node | 595.38 | 160.38 | 3.70x |

These are single-message native API timings, not optimized batch/device paths,
not a profile-weighted workload, and not proof speedups. They include each
suite's own domain framing. Both use the same M31 leaf inputs; repeated nodes
use each suite's own digest chain. No build/proof work ran concurrently.
Samples and source pins are in
[`../../autoresearch/notes/2026-09-21-blake3-migration/README.md`](../../../autoresearch/notes/2026-09-21-blake3-migration/README.md).

The next performance acceptance measure is complete same-statement,
same-security-profile leaf/parent/tree wall time with independently verified
outputs, including recursive witness generation, interaction work, commitments,
PoW, admission and bounded scheduling. Native savings must exceed the added
recursive bitwise constraints and lookup traffic. Do not claim the earlier
5.54-second Poseidon parent timing is now a BLAKE3 result.

Security parameter changes remain a separate experiment. Keep original
q193/16+10 recursive measurements distinct from canonical CSP 70-query/26-bit
results. No query or PoW reduction accompanies this foundation.

### BLAKE3 slowdown attribution — 2026-09-22

Canonical ECDSA stage profiling measured BLAKE3 at 2.523295 s proving versus
BLAKE2s at 0.858627 s, with precompile enabled in both. PoW accounts for 1.640898 s
versus 0.125382 s, explaining 91% of the measured delta. BLAKE3 still uses a serial
reference grinder while BLAKE2s uses pooled batched search. Excluding PoW leaves
0.882397 s versus 0.733245 s; this subtraction is not a canonical total or a speedup.
Both proof/verification gates pass. Fix BLAKE3 PoW before promotion, then investigate
the remaining commitment costs. These are single stage-attribution samples.
[Stage profiles and source evidence](../../../autoresearch/notes/2026-09-22-csp-blake3-slowdown-profile/README.md).

### Pooled BLAKE3 PoW — 2026-09-22

BLAKE3 now uses the bounded prover pool for PoW, preserving the lowest valid
nonce and canonical predicate. The 70-query/26-bit ECDSA precompile qualification
measured 1.000019 s proving, 0.122675 s PoW and 0.197667 s verification, versus
the previous BLAKE3 2.523295 s proving/1.640898 s PoW. Eight focused tests pass,
including worker-count parity and independent full-proof verification. These are
single before/after samples; no statistical verdict, subsecond canonical total,
or improvement over the historical ~0.882 s result is claimed. Defaults and Metal
are unchanged. [Pooled search evidence](../../../autoresearch/notes/2026-09-22-blake3-pooled-pow/README.md).

### Bulk BLAKE3 leaf integration — 2026-09-22

BLAKE3 now uses bulk canonical leaf encoding and the existing tiled builder's
packed-byte interface. Eight ReleaseSafe protocol tests pass, including byte
and streaming equivalence. A canonical ECDSA proof plus independent verification
passed at 0.994176 s proving, 0.123395 s PoW, 0.188772 s verification and
0.001713 s execution (70 queries/26 bits, 1,828 cycles, 3,748,258 proof bytes).
This is neutral against the previous 1.000019 s sample; local leaf-probe gains
do not demonstrate a CSP end-to-end improvement. Defaults/Metal remain pending.
[Source, counters and qualification logs](../../../autoresearch/notes/2026-09-22-blake3-leaf-bulk/README.md).

### Segmented BLAKE3 v7 diagnostic qualification

Segment artifacts now share one suite-parameterized codec with immutable legacy
v3 and explicit BLAKE3 v7 admission. Outer version/hasher and inner identity domain
bind the suite. The artifact gate passes 14 tests; a new fixture-only gate passes
with actual snapshot-bound memory digests. Stale context/memory assumptions in
the old full-proof test were corrected. The corrected BLAKE3/legacy full segment
proof gates pass 2/2 tests (8/8 steps): proving, artifact serialization, independent
verification and capture validation. BLAKE3 gate runtime is 10 s, legacy 6 s;
these include mutation checks and are not proving benchmarks. This qualifies
q3/PoW0 only, not production parameters, larger jobs or product routing.
[Current evidence and remaining verification](../../../autoresearch/notes/2026-09-22-blake3-segment-v7/README.md).

### Remaining Poseidon in segment boundaries

The v7 STARK suite migration retains the existing SegmentV2/V3 statement.
Snapshot/job/lineage identities and continuation commitments still use the legacy
Poseidon owners. The span digest layout admits eight M31 words, so full BLAKE3
bytes require a new injective encoding and explicit statement/AIR/key admission;
masking digest bits is not an acceptable migration. This remains part of the
requested prover-wide replacement, beyond PCS/default/Metal routing.
[Boundary source audit](../../../autoresearch/notes/20260922-blake3-segment-boundary-audit.md).

### Canonical-parameter BLAKE3 segment qualification — 2026-09-22

The signer-containing non-final segment now passes v7 proof/artifact/independent
capture verification at SECURE_PCS_CONFIG (70 queries/26 PoW bits). Artifact size
is 3,524,992 bytes. Wrong artifact suite and hasher ID reject before allocation;
identity and sidecar mutations reject. Fixture plus full-proof gates pass 2/2
tests (8/8 steps). The 19 s full gate duration includes multiple verification and
negative checks and is not a CSP proving benchmark. This does not qualify product
routing, Metal, large jobs or replacement of the legacy boundary identity hashes.
[Canonical segment evidence](../../../autoresearch/notes/2026-09-22-blake3-segment-canonical/README.md).

### Metal BLAKE3 PoW device qualification — 2026-09-22

BLAKE3 now has distinct runtime/kernel/ABI dispatch for PoW. Core prepares the
exact first-block CV; Metal searches bounded ordered nonce intervals, and PCS
revalidates the result through the canonical channel. CPU/Metal minimum-nonce
parity passes at 8, 12, 21 and 26 bits, with device dispatch telemetry and zero
fallback. The 26-bit case spans 61 dispatches. Nine Metal/authority tests and eight
CPU protocol tests pass. The old PoW gate's lazy test discovery/runtime-linkage
gap is corrected. This qualifies PoW only, not AOT execution, Merkle/FRI/resident
transcripts, end-to-end Metal/CSP or production default routing.
[Device evidence and source pins](../../../autoresearch/notes/2026-09-22-metal-blake3-pow/README.md).

### Metal BLAKE3 resident parent reduction — 2026-09-22

BLAKE3 parent hashing now uses the existing resident parent-chain plan with
explicit family/ABI dispatch. A shared compression owner serves parents and PoW.
Every layer matches CPU hashing at depths 1, 5 and 11, with plan reuse, full-bit
inputs and intact arena guards; sparse-only dispatch also passes. Combined gates
passed 11 tests, and the final focused parent gate passed 2 tests after admission
hardening. Full commitment admission remains disabled until leaf/FRI support
exists. Plain-parent dispatch is compiled but not separately executed by these
chain tests; AOT execution and full Metal CSP remain unqualified.
[Parent-chain device evidence](../../../autoresearch/notes/2026-09-22-metal-blake3-parents/README.md).

### Metal direct BLAKE3 leaves: chunk-boundary qualification (2026-09-22)

The prepared direct leaf path now supports BLAKE3 with canonical framing,
heterogeneous column lifting and multi-chunk hashing. Across 14 widths, 32 rows
and two reused-plan inputs, all 896 full digests match CPU and arena guards
remain intact. Final ReleaseSafe leaf/inventory/shader gates pass 24/24 tests;
resident parent regression passes 2/2. Core AOT source/inventory assertions were
updated for the five added BLAKE3 kernels; stale recursive scan inventory
assertions were aligned with its existing six declared/dispatched scan stages.

This qualifies source-JIT direct leaf dispatch, not full Metal BLAKE3 proving.
Staged and wide-arena integration, FRI, resident transcript, statement identity
migration and production recursive qualification remain. No CSP timing or
speedup claim follows from these small-grid leaf tests.
Evidence: [Metal BLAKE3 leaves](../../../autoresearch/notes/2026-09-22-metal-blake3-leaves/README.md).

### Typed Metal FRI commitment trees (2026-09-22)

Prepared FRI trees now select leaf and parent pipelines by explicit family;
BLAKE3 packed leaves share canonical framing with direct leaves. All 18 device
trees match CPU (BLAKE3, plain and prefixed BLAKE2s; one/two/four QM31 rows per
leaf; reused plans and root-first arena storage). This also fixes the admitted
BLAKE2s two-row case previously hashing four rows. Arena checks now cover parent
layers, overlap and u32 addressing limits. See the final focused gate and source
snapshots in [FRI evidence](../../../autoresearch/notes/2026-09-22-metal-blake3-fri/README.md).

This does not qualify a full BLAKE3 FRI protocol, fold/cascade transcript or
end-to-end Metal proof. Staged/wide commitments and remaining Poseidon identities
are still migration work; production suite defaults remain unchanged.

### Width-bounded staged BLAKE3 state (2026-09-22)

Compact staged absorption now persists the CV, pending block and live chunk
stack, reconstructing counters from the sequential column cursor. It lifts
saved state across heterogeneous domains and writes canonical digests directly
on final stages. All 3,164 independently finished prefix digests match CPU across
415 stages; the focused gate passes 18/18 tests. Tested persistent state ranges
from 96 to 224 bytes per row, sized from width rather than a global maximum.

The stage primitive is ready; reusable resident-tree scheduling and batched
command integration still need implementation. Its disjoint buffers and variable
state stride must replace the existing Poseidon scheduler's fixed 16-word and
in-place assumptions. See [staged-state evidence](../../../autoresearch/notes/2026-09-22-metal-blake3-staged/README.md).
No full Metal proof or end-to-end speedup is claimed by this gate.

### Reusable staged BLAKE3 tree command batching (2026-09-22)

The retained resident-tree plan now runs width-bounded staged BLAKE3 leaves and
all parent layers in one command epoch. Eight complete trees match CPU, including
changed inputs under reused plans and root-first storage. Every command receipt
has one submission, one final wait and zero intermediate waits, including the
132-dispatch widest test. The stage primitive and plan share one encoder.
Focused gates pass 28/28 tests; see [tree batching evidence](../../../autoresearch/notes/2026-09-22-metal-blake3-staged-tree/README.md).

Completed-arena BLAKE3 adoption, production commitment selection/scratch planning,
wide arenas and transcript/cascade/decommit integration remain. No full Metal
proof or end-to-end performance improvement is inferred from this test.

### Completed staged BLAKE3 ownership handoff (2026-09-22)

The existing completed-arena tree handoff now admits explicit staged BLAKE3
plans. All eight tree cases verify root access after adoption and reject early,
wrong-plan, wrong-arena and repeated adoption. Focused validation passes 16/16
tests, preserving the single-command and full-tree parity checks. Evidence:
[completed BLAKE3 adoption](../../../autoresearch/notes/2026-09-22-metal-blake3-adoption/README.md).

Production heterogeneous commitment selection still rejects BLAKE3 and allocates
fixed Poseidon state. Its exact admission, width-sized scratch allocation and
staged-plan selection are the next integration boundary. This gate does not
qualify a full Metal proof or change production defaults.

### Production heterogeneous BLAKE3 commitment integration (2026-09-22)

The actual backed mixed-log `prepareAndCommitOwned` path now accepts the exact
canonical BLAKE3 hasher, sizes scratch from width and selects its staged plan.
CPU/Metal coefficients, extended columns, root and openings match; independent
Merkle verification passes. The shared BLAKE2s/BLAKE3 regression gate passes
3/3 tests, including cleanup/resource accounting and one-submit telemetry.
The small synthetic test uses the existing admission-threshold override.

See [heterogeneous BLAKE3 evidence](../../../autoresearch/notes/2026-09-22-metal-blake3-heterogeneous/README.md).
This qualifies that production commitment implementation, not every commitment
shape or a full STARK proof. Uniform/wide paths, transcript/cascade, full Metal
proofs, remaining Poseidon identities and production recursion remain unfinished.

### Ordinary BLAKE3 commitments and 64-bit offset dispatch (2026-09-22)

The ordinary resident Merkle route now admits exact canonical BLAKE3 through a
typed direct-domain helper shared with heterogeneous commitment selection.
Both offset-width kernels share one leaf implementation. Ten complete uniform/
mixed direct trees match CPU; direct/leaf/shader gates pass 26/26 tests. The
64-bit offset kernel ran on small arenas; >2^32-word arenas remain untested.
See [direct commitment evidence](../../../autoresearch/notes/2026-09-22-metal-blake3-direct-tree/README.md).

Combined uniform transform/commit selection and transcript/cascade still need
integration before full Metal proofs and canonical CSP timing. No default-suite
promotion or end-to-end performance gain is claimed here.

### Combined uniform BLAKE3 precommit (2026-09-22)

Both owned-evaluation and polynomial-form uniform precommit now accept canonical
BLAKE3 through the shared direct-domain owner. Eight-column base-log-16 cases
match CPU coefficients, extended columns and roots for BLAKE2s and BLAKE3, while
preserving existing work receipts. These use normal production shape admission.
Focused gates pass 3/3 tests, covering four combined commitments. Evidence:
[uniform BLAKE3 precommit](../../../autoresearch/notes/2026-09-22-metal-blake3-uniform/README.md).

Resident transcript/FRI cascade and full Metal proof qualification remain; this
is not a full STARK benchmark or default-suite promotion.

### Canonical resident BLAKE3 transcript operations (2026-09-22)

Resident words/felts/integer/root absorbs and secure-field draws now match the
canonical CPU channel, including full u64 counters, count framing and whole-block
rejection semantics. The focused transcript/leaf/shader gate passes 36/36 tests;
state and arena parity include counters crossing 2^32 and exhaustion rejection.
The rare sampling-rejection branch was inspected but not forced in device vectors.
Evidence: [resident BLAKE3 transcript](../../../autoresearch/notes/2026-09-22-metal-blake3-transcript/README.md).

The standalone operations use an 11-word state and shared/mapped arena. FRI
cascade/parent-tail integration, query draws and full Metal proofs remain; this
does not change defaults or establish end-to-end speedups.

### Native Metal BLAKE3 line FRI cascade (2026-09-22)

The versioned runtime cascade now selects BLAKE3 fused coordinate/leaf and
fold/leaf kernels, parents and root-to-challenge transcript handoff. Nine-level
cold/warm cascades match CPU roots, final transcript and final values for both
BLAKE3 and BLAKE2s, with one command/one wait. The initial combined gate passes
11/11; the final cascade plus ABI/AOT-profile gate passes 6/6. Evidence:
[BLAKE3 line cascade](../../../autoresearch/notes/2026-09-22-metal-blake3-cascade/README.md).

High-level resident FRI transaction admission and channel serialization still
select BLAKE2s; circle/prior-buffer handoff, query draws and full Metal proofs
remain. This runtime gate does not promote defaults or establish CSP speedups.

## Backend BLAKE3 FRI line cascade — 2026-09-22

The backend line-cascade API now admits BLAKE3 with full 64-bit transcript
counter serialization/restoration and a shared receipt/no-receipt invocation.
Seven focused tests pass, including CPU parity for all roots, final transcript
and terminal values at 1,024 and 8,192 values (host and device inverse paths).
Circle-to-line and combined quotient transactions remain separately gated;
this is not full-proof or CSP qualification.
[Source snapshots and logs](../../../autoresearch/notes/2026-09-22-metal-blake3-backend-cascade/README.md).

## BLAKE3 circle-to-line FRI prover — 2026-09-22

The resident circle transaction admits exact BLAKE3 suite pairs before drawing
its first challenge. A full FRI commit/decommit at 16,384 circle values matches
the generic CPU prover, including every root, intermediate column, terminal
polynomial, opening proof and transcript. The independent FRI verifier accepts
the Metal proof at transcript-derived queries. Eight focused tests pass.
Combined quotient/FRI and full STARK/CSP qualification remain outstanding; no
benchmark speedup or default promotion follows from this bounded FRI gate.
[Source snapshots and logs](../../../autoresearch/notes/2026-09-22-metal-blake3-circle-fri/README.md).

## Combined BLAKE3 quotient/FRI transaction — 2026-09-22

The lazy transaction now carries the exact BLAKE3 suite through quotient Merkle
commitment, initial root/challenge framing, and queued circle/line cascade.
Full transcript counters are transferred without changing scheduling. Tests
compare independently computed CPU quotients and complete CPU FRI proofs against
Metal commitLazy, then verify the Metal proofs with the independent verifier.
BLAKE3 and BLAKE2s pass; focused suite 10/10. Full STARK/CSP and captured receipt
qualification remain outstanding. No default promotion or speedup is claimed.
[Source snapshots and logs](../../../autoresearch/notes/2026-09-22-metal-blake3-quotient-fri/README.md).

### Canonical BLAKE3 ECDSA on Metal source JIT — 2026-09-22

The full precompile guest proof and independent verification pass at 70 queries,
26 PoW bits and 16 workers. One ReleaseFast sample: execution 0.000764458 s,
proving **0.902787958 s**, verification 0.087134666 s, 1,828 cycles and 3,748,258
proof bytes. The shared CPU/Metal harness also checks suite receipts and rejects
wrong inputs, wrong ELF and tampered proofs. Diagnostic source JIT is explicitly
selected; authenticated AOT remains pending. Whole-test telemetry reports 128
Metal dispatches and 5 CPU fallbacks (including negative-check activity).
This is a single qualification sample, not a demonstrated speedup over the
historical 0.882 s baseline or a controlled CPU/Metal comparison.
[Logs and source snapshots](../../../autoresearch/notes/2026-09-22-metal-blake3-csp-ecdsa/README.md).

### Canonical BLAKE3 ECDSA on authenticated Metal AOT — 2026-09-22

The freshly built current core AOT bundle passes the full precompile proof,
independent verification and negative checks at 70 queries / 26 PoW bits,
16 workers. One ReleaseFast sample: execution 0.000743667 s, proving
**0.881876417 s**, verification **0.085001875 s**, 1,828 cycles,
3,748,258 proof bytes. This is approximately the historical 0.882 s baseline;
no statistical speedup claim is made. Runtime setup is outside proof timing.
Whole-test telemetry has 128 Metal dispatches, 5 small circle LDE fallbacks,
and 25 CPU composition component placements (separate from fallback totals).
This is hybrid CPU/Metal execution. Full BLAKE3 CSP suite results remain pending.
[Authenticated manifest, logs and source snapshots](../../../autoresearch/notes/2026-09-22-metal-blake3-csp-aot/README.md).

## Full CSP publication boundary audit — 2026-09-22

The full software runner still reaches legacy engine bindings, JSON artifact v4,
a fixed-Hasher decoder and legacy transcript report fields. ECDSA's separate
BLAKE3 artifact path does not migrate those boundaries. Launching the runner now
would not qualify the full BLAKE3 suite. Next work is versioned suite admission,
engine-derived decoding and typed receipts, then explicit product/runner suite
selection and complete software proof qualification before the broader matrix.
[Source-pinned audit and required integration sequence](../../../autoresearch/notes/2026-09-22-blake3-full-csp-boundary-audit/README.md).

## Regular software artifact suite boundary — 2026-09-22

The regular envelope maps v4 to BLAKE2s and new v5 to BLAKE3; fixed-memory
routing and structural validation reject mixed tags. Twenty focused artifact
tests pass, including a complete structural v5 roundtrip. The adapter decoder
now checks the exact requested engine suite before reconstruction/allocation
and selects Engine.Hasher. That adapter change still requires product-level
instantiation and typed receipt migration; structural fixtures are not proof
qualification. Defaults remain v4, and full software BLAKE3 CSP is pending.
[Source snapshots and test evidence](../../../autoresearch/notes/2026-09-22-blake3-software-artifact-suite/README.md).

## Regular verifier typed transcript receipts — 2026-09-22

Software artifact v5 now has a riscv_verify_v2 encoder carrying the typed BLAKE3
transcript receipt. The independent verifier calls the canonical channel receipt
helper after verification; v4/BLAKE2s bytes remain pinned. Two focused encoder
tests pass, including allocation-free mismatch rejection. Complete BLAKE3
product verification remains unqualified until producer reports and product suite
selection migrate; no software CSP result is claimed by this encoding gate.
[Source snapshots and tests](../../../autoresearch/notes/2026-09-22-blake3-software-verifier-receipt/README.md).

## Regular producer and benchmark report integration — 2026-09-22

Producer serialization now selects Engine.Hasher, completed canonical receipts
and v5 for BLAKE3. Prove/benchmark schemas distinguish the BLAKE3 transcript
receipt from legacy fields; aggregation validates exactly one suite-appropriate
representation and canonical digest encoding. Nine focused adapter report tests
pass, including exact legacy field-set checks. Complete BLAKE3 product execution
and Python runner admission remain outstanding; no full software CSP result is
claimed. [Source snapshots, tests and archived failures](../../../autoresearch/notes/2026-09-22-blake3-software-producer-reports/README.md).

## Python software suite and transcript admission — 2026-09-22

Software validators now pin the requested suite across artifact, benchmark and
verifier schemas and validate canonical suite-specific receipts. The existing
runner also compares the retained-proof verifier transcript against the benchmark
transcript. Seventy-two focused Python tests pass. Product/runner suite selection
and full software BLAKE3 proof qualification remain pending; defaults are unchanged.
[Source and tests](../../../autoresearch/notes/2026-09-22-blake3-python-software-admission/README.md).

## Explicit product selection and regular CPU proof — 2026-09-22

Products accept `--proof-suite blake3` before the command; runner propagation
covers software and precompile/fallback paths. CPU product compilation, ordinary
SHA-256/128-byte CSP prove, independent verify, wrong-suite/tamper rejection and
one-sample benchmark aggregation pass with v5 artifacts and typed receipts.
Seventy-two Python tests pass. Metal product selection remains uncompiled, and
legacy guest-profile v1 commands now reject BLAKE3 instead of mixing suites.
Full clean-product CSP matrix and that profile's migration remain outstanding.
[Retained proof, reports, source and logs](../../../autoresearch/notes/2026-09-22-blake3-product-suite-selection/README.md).

### Ordinary SHA-256 BLAKE3 product qualification — 2026-09-22

The canonical 128-byte SHA-256 guest (14,056 cycles, 70 queries / 26 PoW bits)
passes authenticated-AOT Metal product proving, independent CPU and Metal CLI
verification, and benchmark aggregation. Its v5 proof bytes and typed transcript
match the CPU product exactly. Explicit wrong-suite verification is rejected.
One diagnostic prove command measured 0.366627334 s proving and 0.0976185 s
verification; these dirty-development products are not a clean full-suite cohort
or repeated speedup study. Full BLAKE3 suite results remain pending.
[Retained proof, receipts and build evidence](../../../autoresearch/notes/2026-09-22-blake3-metal-product-proof/README.md).

## Full BLAKE3 CSP matrix — 2026-09-22

Completed all 16 cases on CPU and authenticated-AOT Metal from clean local source
snapshot `348b9a02c2bfc33487a1f653aef7152ce83ae2b0` (not published).
Every retained proof independently verified; both backends also proved and verified
the bad-signature rejection case. All rows use 70 queries and 26 PoW bits, with
recursion disabled. ECDSA uses the typed recovery precompile; other targets execute
software guests, including the intentionally preserved Poseidon guest workload.

Apple M5 Max, 16 workers, ReleaseFast, one sample, no warmups, battery power.
These are local qualification measurements, not a controlled performance comparison.
Prove includes execution, witness and proof generation; verification is separate.

| Workload | Size | CPU prove (s) | CPU verify (s) | Metal prove (s) | Metal verify (s) |
|---|---:|---:|---:|---:|---:|
| sha256 | 128 | 2.074658 | 0.192373 | 0.421341 | 0.094871 |
| sha256 | 256 | 2.206294 | 0.191040 | 0.452077 | 0.096447 |
| sha256 | 512 | 2.295138 | 0.193408 | 0.423100 | 0.093192 |
| sha256 | 1024 | 3.894334 | 0.192097 | 0.508788 | 0.093122 |
| sha256 | 2048 | 2.719380 | 0.196893 | 0.458731 | 0.093496 |
| keccak | 128 | 2.585501 | 0.194410 | 0.413153 | 0.099302 |
| keccak | 256 | 1.805518 | 0.198111 | 0.408048 | 0.095944 |
| keccak | 512 | 3.879529 | 0.257437 | 0.443229 | 0.092867 |
| keccak | 1024 | 3.596645 | 0.225637 | 0.472704 | 0.094817 |
| keccak | 2048 | 3.811401 | 0.267551 | 0.471172 | 0.106059 |
| poseidon2_m31 | 2 | 2.457577 | 0.224616 | 0.479333 | 0.098394 |
| poseidon2_m31 | 4 | 2.285950 | 0.223041 | 0.519534 | 0.098360 |
| poseidon2_m31 | 8 | 1.712028 | 0.217501 | 0.514272 | 0.107732 |
| poseidon2_m31 | 12 | 2.197131 | 0.232287 | 0.551292 | 0.099131 |
| poseidon2_m31 | 16 | 3.596061 | 0.245193 | 0.606420 | 0.098611 |
| ecdsa_secp256k1 | 32 | 1.096581 | 0.166682 | 0.907835 | 0.091660 |

The earlier 2.523295 s BLAKE3 ECDSA CPU result included 1.640898 s of serial
PoW search; profiling attributed 91% of its difference from the paired BLAKE2s
measurement to PoW. Bounded pooled search fixed that regression. Current full-suite
ECDSA measures 1.096581208 s CPU and 0.907834583 s Metal, versus the historical
approximately 0.882 s reference. The separate Metal AOT harness measured
0.881876417 s witness/proving plus 0.000743667 s execution. Do not interchange
harness witness/proving, suite execution-inclusive proving, verification, or process
wall time. Single samples cannot establish a residual regression or its cause.

This qualifies explicit BLAKE3 suite selection; it does not promote defaults or
complete the remaining Poseidon statement-identity and recursion migration.

[Raw reports and evidence](../../../autoresearch/notes/2026-09-22-blake3-full-csp-matrix/README.md).

### Remaining statement identity boundary — 2026-09-22

Current-source inspection confirms that selecting the BLAKE3 STARK suite does
not replace `segment_statement_v2_contract.IdentityHasher`: it still wraps
`poseidon2_channel.CanonicalWordHasher`. V2 fixed layout uses eight field words
per identity and pins 652 fixed words / 412 base projection words. The Span
reader and writer also assume eight M31-canonical words per digest. In addition,
V2 continuation roots remain scalar M31 sparse-Merkle roots. Those are a separate
memory-commitment contract, not interchangeable with a 256-bit identity.

Added `src/frontends/riscv/recursion/blake3_identity_digest.zig` as the lossless
encoding primitive for the replacement statement format: a distinct 32-byte
Digest struct, encoded into sixteen little-endian 16-bit public words. Decoding
rejects values above 65535 before narrowing, including otherwise canonical M31
values. Three ReleaseSafe standalone tests passed: pinned byte order/high bits,
invalid aliases at every limb, and preservation of every one of the 256 bits.
Command: `zig test src/frontends/riscv/recursion/blake3_identity_digest.zig -O ReleaseSafe`.
This primitive is not yet wired into a production statement or AIR and changes
no existing proof identities.

The next implementation must migrate the connected contract: versioned Span and
segment layout; shared identity preimages and native BLAKE3 hashing; recursive
BLAKE3 hash bindings and 16-bit limb constraints; source/capture projection and
geometry; artifact admission and authenticated keys. Negative qualification must
reject old-format substitution and modified high digest bits. Scalar continuation
roots and the legacy guest-profile product envelope require their own connected
migration. Only after these paths qualify can defaults and legacy prover-owned
Poseidon implementations be retired. Guest-requested Poseidon semantics remain.

### BLAKE3 Span statement implementation — 2026-09-22

The lossless digest encoding is now connected to `span_statement_blake3`: a
525-word statement with a distinct B3SP tag and explicit format version 1.
Fourteen digests each occupy sixteen 16-bit limbs. Legacy and BLAKE3 statements
share one canonical encoding, semantic validation and folding implementation;
the legacy 412-word ABI remains pinned. Native distinct-child folding, high-bit
boundary mutations, all digest-limb aliases and padding pass the focused
`test-riscv-statement-codecs` ReleaseSafe gate alongside legacy statement tests.
The new format is exported but not yet admitted by production proof artifacts.
Arithmetic constraints, identity hash bindings, source/capture geometry and
key admission still require migration. No recursion performance claim follows
from this native codec qualification.
[Source snapshot and qualification](../../../autoresearch/notes/2026-09-22-blake3-span-statement/README.md).

### BLAKE3 Span input AIR schedule — 2026-09-22

The format-specific row-11 witness profile now admits all 525 words and enforces
sixteen-bit classification at all 224 digest positions per scope, reusing the
existing typed byte-range AIR. Legacy and BLAKE3 direct column writers share an
implementation; binding and preprocessing identities remain format-separated.
Five new focused checks cover all digest coordinates, authority substitution,
forged arithmetic decomposition, padded final-column emission and fail-before-write
admission. The combined legacy/BLAKE3 codec and input AIR gate passes ReleaseSafe.
The full statement-semantics graph remains on legacy geometry; migration of that
graph and its providers is the next dependency. This is not full recursive-proof
qualification.
[Evidence and source snapshot](../../../autoresearch/notes/2026-09-22-blake3-statement-input-air/README.md).

### BLAKE3 statement semantics graph — 2026-09-22

The arithmetic graph now supports the 525-word BLAKE3 Span through the same
contract/builder/equations as legacy statements. The new sealed graph has 2,416
inputs, 10,912 nodes and 2,916 constraints, with sixteen-limb edge bindings and
an explicit leaf-version equation. Legacy graph geometry and seal still pass.
The focused ReleaseSafe gate also covers distinct-child arithmetic folding,
all sixteen continuation/edge limb mutations, padding and empty subtrees, and
the combined graph/input-AIR range admission. This is arithmetic qualification,
not a complete recursive proof. The row-10 provider, identity hash bindings and
artifact/key integration remain pending.
[Source and evidence](../../../autoresearch/notes/2026-09-22-blake3-statement-semantics-graph/README.md).

### BLAKE3 statement provider — 2026-09-22

The row-10 provider now has a format-separated 2,100-row BLAKE3 schedule over
four 525-word lanes and shares its direct column writer with legacy statements.
The focused ReleaseSafe gate passes, including all 1,050 segment/parent emitted
tuples checked against the authenticated graph input plan, binary full-word
emission, padding and fail-before-write schedule mutation rejection.
This does not close the full global relation ledger: binary child routing still
has two consumers, and composition input schedules retain legacy word bounds.
Source/public-claim projection, BLAKE3 identity bindings and artifact/key admission
remain pending.
[Evidence and source snapshot](../../../autoresearch/notes/2026-09-22-blake3-statement-provider/README.md).

### BLAKE3 composition schedule compiler — 2026-09-22

The composition compiler now has a format-separated BLAKE3 instantiation with
525 statement words and coherently shifted later input coordinates (537 inputs
in the minimal recursion profile). Graph, reference and schedule domains are
separated while legacy seals remain unchanged. Shared compiler validation rejects
legacy scalar-root/field-public extensions until migrated. The ReleaseSafe gate
passes legacy checks and new full-coordinate, authenticated synthetic compilation,
anchor, bounds, mapping-mutation and cross-format seal checks.
The composition witness writer still needs the new compiler instantiation; no
production composition proof or complete recursion qualification is claimed.
[Evidence and source snapshot](../../../autoresearch/notes/2026-09-22-blake3-composition-schedule-compiler/README.md).

### BLAKE3 composition witness and child-word routing — 2026-09-22

The row-18 witness profile now selects the BLAKE3 composition compiler and shares
its direct column writer with legacy mode. Source admission delegates to compiler
validation. The focused ReleaseSafe gate passes compiled-reference writer/padding/
fail-before-write checks and exact tuple/multiplicity matching across both consumers
of all 1,050 binary child words. The tuple test uses explicit composition-coordinate
fixtures alongside the sealed statement graph schedule; it is not full production
composition or global relation closure. Production source projections, identity
hash constraints and artifact/key integration remain pending.
[Evidence and source snapshot](../../../autoresearch/notes/2026-09-22-blake3-composition-witness/README.md).

### Native BLAKE3 Span/job identities — 2026-09-22

Added one versioned preimage/source mapping for full-digest statement and job
identities. The focused ReleaseSafe gate passes framing, high-bit sensitivity,
fail-before-write checks and agreement with recursive full-hash witnesses;
claimed digest substitution fails exact hash-wire closure. Production source-wire
binding, remaining snapshot/lineage/memory commitments and artifact/key migration
are still pending. Defaults are unchanged.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-span-identities/README.md).

### BLAKE3 Span identity input routing — 2026-09-22

A value-independent compiler now routes native identity headers and statement
word bytes through the existing typed byte-route AIR, preserving hash fanout and
tracking statement source use counts. Both preimages pass exhaustive byte and
coordinate comparisons in the focused ReleaseSafe gate. Canonical field-byte
producer binding and production assembly remain pending; this does not yet
qualify complete recursive identities.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-span-identity-routing/README.md).

### Canonical Span identity input preparation — 2026-09-22

The input plan now connects scalar packing, canonical field-byte encoding and
identity routing, with explicit source multiplicities and final-group padding.
The focused ReleaseSafe gate passes internal lookup closure and byte-substitution
rejection for the connected preparation. Authenticated statement-node assignment,
producer fanout integration, private hash assembly and digest output binding remain
pending; this is not production recursion qualification.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-span-input-chain/README.md).

### Parent identity source authority — 2026-09-22

The identity builder derives source nodes from the validated, sealed BLAKE3
statement graph and augments the existing row-11 fanout for packing consumers.
Focused checks pass for all parent assignments, preserved unrelated bindings,
changed preprocessing authority and rejection of tampered graph metadata.
Production prover assembly, joint identity fanout and digest output binding
remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-parent-identity-binding/README.md).

### Private Span identity hash assembly — 2026-09-22

Live and message-free trusted constructors now replace public hash message
boundaries with identity byte routes. Both purposes pass native digest agreement,
fixed metadata comparison and full hash-wire closure with explicit fixture source
producers; changing a digest sink breaks closure. Production statement/identity
claim integration and complete STARK qualification remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-span-private-hash/README.md).

### Joined parent statement-to-identity preparation — 2026-09-22

One parent-plan entry point now prepares canonical input and private hash rows.
A differential lookup check joins additional actual row-11 fanout through packing,
encoding and the full hash, for both identity purposes on a distinct-child parent.
Packed-coordinate substitution and wrong digest claims fail closure. The focused
ReleaseSafe gate passes; this remains component integration evidence rather than
complete production STARK qualification.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-span-joined-identity/README.md).

### Shared job and statement identity preparation — 2026-09-22

Joint preparation now shares statement inputs, scalar packing and canonical byte
encoding across both hashes. The focused ReleaseSafe gate passes combined
lookup closure and rejects missing job consumers and aliased circuit namespaces.
Production proof/claim assembly and remaining commitment migration are pending;
no end-to-end timing improvement has been measured.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-span-identity-pair/README.md).

### Message-free paired identity preprocessing — 2026-09-22

Trusted constructors now generate fixed rows for the complete paired identity
preparation without statement values. Every fixed column matches live generation
for two distinct statements in the focused ReleaseSafe gate. Production key and
claim admission and complete STARK qualification remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-pair-trusted-preprocessing/README.md).

### Paired identity arithmetic and table qualification — 2026-09-22

Every direct constraint and active byte-range/bitwise table request in the paired
identity witness now passes a focused exhaustive row check. Forged encoding and
XOR witnesses fail. Together with prior wire and metadata checks this strengthens
component qualification, but production STARK proof assembly and remaining
commitment migration are still pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-identity-constraints/README.md).

### Paired identity CPU STARK proof — 2026-09-22

The dedicated `test-riscv-blake3-identities` gate now proves and verifies both
identities with shared canonical encoding and independently generated trusted
preprocessing, rejecting a changed job digest. It passed in ReleaseSafe using the
fixture's diagnostic 8-query/0-PoW parameters. Scalar statement inputs are public
fixture boundaries; production statement ingress/folding and recursive child
verification are not included. This is not canonical CSP or production recursion
qualification, and no prover speedup is claimed.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-paired-identity-proof/README.md).

### Full-digest byte-memory commitment primitive — 2026-09-22

Added a full-256-bit BLAKE3 byte tree with domain/kind-separated leaf and node
framing, reusing the legacy continuation traversal without changing its semantics.
Native sparse-root checks pass. Production scalar roots remain legacy: typed
memory AIR, full-width public/continuation claims and retained-snapshot integration
are still required before replacement.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-byte-memory-tree/README.md).

### Typed BLAKE3 memory-node routing — 2026-09-22

The canonical memory-node frame now routes authenticated left/right digest roles
through the existing typed byte router and full hash witness. Native agreement,
placeholder-based routing metadata, wire closure and substituted child rejection
pass alongside existing transcript-frame regression checks. Tree aggregation,
private leaf bytes and production memory/continuation claims remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-memory-node-routing/README.md).

### Private byte-memory leaf witness — 2026-09-22

Memory leaves now consume a private byte through the existing typed bridge while
keeping frame headers fixed. Native agreement, fixed metadata, hash-wire closure,
source substitution and unused-coordinate rejection pass in the focused gate.
Tree/path aggregation and production memory/continuation source and claim
admission remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-private-memory-leaf/README.md).

### Full-depth memory path and qualification correction — 2026-09-22

The 30-level BLAKE3 memory path now connects private leaf and sibling inputs to a
full root claim, with native root agreement, witness-free fixed metadata and
complete wire closure; substituted siblings fail. The corrected focused gate
passes. Earlier memory qualification claims were premature: those tests were
missing from the focused root. They and the intended frame regressions are now
explicitly imported and passed; earlier evidence notes record the correction.
Production memory admission and a full path STARK proof remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-memory-path/README.md).

### Full-depth byte-memory opening STARK proof — 2026-09-22

The dedicated memory-path gate proves and verifies the full 30-level BLAKE3
opening with private siblings and trusted preprocessing, rejecting a changed root.
ReleaseSafe qualification passed at diagnostic 8-query/0-PoW settings. The byte
source is a public fixture; memory transitions and production memory/continuation
admission remain pending. This is not an end-to-end speed measurement.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-memory-path-proof/README.md).

### Snapshot-derived memory openings — 2026-09-22

A single shared traversal now derives a sparse snapshot root and requested
opening, including absent and explicit-zero bytes. Native reconstruction and
adversarial checks pass, and the full path STARK gate passes using siblings from
a multi-branch snapshot. Runner-owned snapshot admission, transitions and
production continuation claims remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-snapshot-openings/README.md).

### Shared-sibling byte-update witness — 2026-09-22

Before/after path assembly now shares one sibling producer and one address, with
separate byte sources and root claims. Native snapshot-root agreement, retained
producer fanout and trusted metadata checks pass. A combined update STARK proof
and production memory/continuation admission remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-byte-update-witness/README.md).

### Combined byte-update STARK proof — 2026-09-22

Both root paths now pass one CPU STARK proof with shared private siblings and
trusted preprocessing, rejecting a changed after-root. The dedicated gate passed
at diagnostic 8-query/0-PoW parameters with public byte-source fixtures. Production
memory/clock admission, continuation claims and artifact/key integration remain
pending; this is not yet a proved RISC-V store.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-memory-update-proof/README.md).

### Memory-access boundary adapter: integration in progress — 2026-09-22

Added a typed four-byte boundary adapter preserving the existing memory-access
word/address/clock tuple and initial/final signs, with byte-range requests and
four scalar byte outputs. Its typed identity is
`33f5035f2ca070d0895d9d8ad08f208c1b985308c59cc92339015d08daacb0df`.
The new focused test currently fails with `InvalidInputGeometry`: the exact
memory-access schema requires `.address`, while the universal relation runtime
admits only field-scalar inputs. This is an unresolved lowering integration,
not a qualified adapter. The existing type restriction remains intact.

Next: add explicit verifier-bound 30-bit address lowering, preserving exact
memory relation geometry and avoiding unrestricted 32-bit-to-M31 aliasing; then
qualify tuple/sign parity and joined memory proofs. Current focused gate result:
110/111 tests pass, one new adapter test fails. Logs:
`/tmp/blake3-memory-boundary-final.log`, `/tmp/blake3-boundary-detail.log`.

### Fixed-address boundary lowering qualified — 2026-09-22

The previous `InvalidInputGeometry` failure is resolved by explicit runtime-type
admission of verifier-owned address columns. Default address rejection remains;
the memory boundary schedule bounds addresses to aligned 30-bit values. The
focused gate passes exact memory tuple/sign parity, byte-wire outputs and policy
revalidation checks. Production path/root/key admission and joined proofs remain
pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-memory-boundary-lowering/README.md).

### Bound four-byte memory opening — 2026-09-22

One statement now derives the typed memory boundary and four byte paths with
exact address/source coordinates and a shared full root. Snapshot-derived byte
values, native roots, trusted boundary metadata and complete internal wire
closure pass; changed bytes, root mismatch and namespace collisions are rejected.
A full joined word proof and production memory/clock provenance remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-memory-word-binding/README.md).

### Runner-snapshot memory projection — 2026-09-22

An owned adapter now derives BLAKE3 roots, byte openings and boundary clocks from
the runner Snapshot representation, preserving ordinary public-memory custody
and separating whole-memory continuation projection. Ownership, custody and
byte/clock preparation checks pass. Tests use constructed snapshots; actual
RunResult and production proof/source admission remain pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-retained-memory-source/README.md).

### Execution-produced memory source qualification — 2026-09-22

Two real adjacent runner segments now feed the BLAKE3 snapshot adapter in a
focused test. Continuation roots agree across the boundary; the final store
changes the root, and prepared boundary bytes/clocks match retained execution
state. The gate passes. This does not switch production memory proofs or qualify
the joined RISC-V STARK; continuation/key admission remains pending.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-runner-memory-source/README.md).

### Full-width ordinary public statement roots — 2026-09-22

The shared execution statement now offers an explicitly versioned BLAKE3 root
contract without duplicating validation. Full 256-bit roots use sixteen u16
limbs; presence flags distinguish absent and zero roots. The focused gate
passes every-bit binding checks and legacy transcript-layout regressions.
Production assembly and artifact/key admission have not switched.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-public-root-contract/README.md).

### Combined ordinary commitment preparation — 2026-09-22

Program admission is shared between suites: decoded field tuples, declared
padding policy, fetch membership and multiplicities are prepared before hash
selection. The BLAKE3 program tree uses tag-3 canonical u32 field leaves under
program kind; memory retains tag-1 byte leaves. This preserves decoded values
larger than 255 without truncation. Shared node framing and traversal are reused.

`prover/blake3_commitment_witness.zig` now assembles the program and ordinary
entry/exit memory roots with custody-aware, disjoint boundary schedules. It
binds roots into `Blake3PublicData` only after all supplied-root comparisons and
statement validation pass. Word witnesses can be prepared one work item at a
time. `public_logup.blake3RelationSums` reuses execution/public-I/O compensation;
full-width root sinks must be bound by admitted hash components, not scalar
Merkle compensation.

The focused ReleaseSafe gate passes combined preparation, field-valued program
openings, custody and namespace checks, fail-atomic root binding, and shared
legacy program-admission/public-LogUp regressions (39 s, 1 GiB).
Production component placement, program-access-to-hash wiring, artifact/key
admission and complete RISC-V/recursive proofs remain unfinished. These APIs
are not yet selected by the production orchestration.

The full-depth STARK gate also passes both byte and canonical program-field
openings with changed-root rejection (33 s, 1 GiB; diagnostic q8/PoW0). Sources
are public fixtures, not yet the production program-access relation.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-ordinary-commitment-assembly/README.md).

### Program-access hashing and admitted commitment schedules — 2026-09-22

The typed program boundary now connects decoded fields through canonical byte
encoding and BLAKE3 paths. A shared component emitter handles complete program
and memory schedules with bounded per-word workspace; independent preprocessing
requires a versioned verifier-pinned plan. The focused gate passes exact provider
sign, wire closure, trusted-column agreement and mutation rejection. Fixed PC
lowering is explicit; default witness-PC rejection remains. Full production proof
orchestration, PCS keys/artifacts and recursion admission are still unfinished.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-program-component-admission/README.md).

### Persistent commitment PCS columns — 2026-09-22

Admitted memory/program components now emit into final PCS column buffers with
independent fixed columns, retained typed plans, reusable interaction scratch,
lookup registration and prover/verifier component binding. The focused gate
passes full row/column parity, zero padding, interaction-reference parity and
failed-update invalidation followed by buffer reuse (45 s, 2 GiB). This is engine
interface integration; joined execution/table proofs and complete key/artifact
admission remain unfinished.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-commitment-pcs-columns/README.md).

### Shared native execution component assembly — 2026-09-22

A full-width execution statement now reuses the native component assembly walk
while rejecting legacy commitment providers. Native and BLAKE3 components share
one universal relation draw, and checked manifest origins place commitment
columns after execution. The dedicated integration gate passes; it was split
from the codec gate to keep ordinary iteration lighter. A complete joined STARK
and PCS key/artifact admission remain pending; this is assembly qualification.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-native-execution-assembly/README.md).

### Real native execution proof and explicit API — 2026-09-22

The full-width path now proves and independently verifies a real base RISC-V
program, joining shared native opcode/clock/lookup generators with BLAKE3
program and memory commitments. The reusable backend-injected API is exported
through the frontend and CPU integration. It binds all protocol parameters,
public roots, admitted schedules and detailed claims; the verifier reconstructs
preprocessing and geometry independently of witness buffers. Geometry mutation
and preprocessing-root substitution checks pass.

Integration found and fixed missing lookup counts from zero-padded BLAKE3 G/XOR
rows. The full-domain census now agrees with the interaction generator. The
execution gate passes (1 min, 4 GiB), and shared statement/codec regressions pass
(35 s, 1 GiB), in ReleaseSafe. These are build/test timings, not proving benchmarks.
The real proof uses diagnostic q8/PoW0 and covers base instructions, not CSP
precompile extensions or multi-level recursion. Production defaults, complete
key/artifact admission, extension/continuation orchestration and recursive
qualification remain unfinished. No performance gain is claimed.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-real-execution-proof/README.md).

### Prepared execution keys, bounded artifacts and recursive capture — 2026-09-22

The explicit BLAKE3 execution API now has independently derived, caller-pinned
execution keys and a prepared verifier that retains typed plans and geometry.
It owns public I/O and schedules, allocates no main witness columns, and releases
fixed columns after deriving their commitment. Its B3EXART1 codec bounds nested
proof allocation from admitted component geometry and never lets a received key
ID select a key. The execution transcript is now version 2, binding native typed
authorities and explicit lifting-parameter presence.

Successful verification can publish an owned, sealed PCS/FRI capture. Full-width
execution transcript planning feeds the shared native BLAKE3 PCS replay suffix
and reproduces the verified final transcript without scalar-root conversion.
The gate passes real proof encode/decode after original-proof destruction,
tamper rejection, repeated verification with one prepared owner, source-copy
isolation, capture-mutation rejection and transcript-plan construction (1 min,
4 GiB, ReleaseSafe). Shared recorder/plan regressions pass all 3 named tests.

This is diagnostic q8/PoW0. Keys remain specialized to admitted statements and
schedules. Native parent composition/public-boundary integration, continuation,
multi-level recursion, extension/CSP orchestration and production default/key
selection remain incomplete. No canonical benchmark or speedup is claimed.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-execution-admission-capture/README.md).

### Full-width execution recursion arithmetic and transcript routes — 2026-09-22

A joined arithmetic graph now replays the native execution evaluators and typed
BLAKE3 commitment programs, including public LogUp closure and split composition
reconstruction. Public compensation shares its generic implementation with the
ordinary verifier. Public values remain specialized to the admitted execution key.

DEEP geometry is derived from the admitted component roster, preserving native
current/previous and typed previous/current masks. The existing DEEP and FRI
graphs consume the real execution capture. Explicit routes connect all 47
universal challenge pairs, composition/OODS/DEEP/FRI draws, detailed claims and
sampled values. Secure packing and scalar fanout share samples between DEEP,
composition and canonical transcript byte encoding without duplicate producers.

The real-proof execution gate and shared statement/codec checks pass in
ReleaseSafe (1 minute / 4 GiB and 37 seconds / 1 GiB respectively). Tampered
composition samples, claims, shared samples and transcript draws are rejected.
These remain diagnostic q8/PoW0 tests, not canonical benchmarks or a new parent
STARK. Merkle openings, query/terminal bindings, complete parent roster/key and
end-to-end parent proving remain to integrate. Continuation, multilevel recursion,
extension/CSP orchestration and production defaults also remain unfinished.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-execution-composition/README.md).

### Full-width execution opening, query and terminal bindings — 2026-09-22

The real execution capture now passes the shared STARK opening witness path:
4 trace trees, 20 FRI layers, 8 queries and 7,800 checked scalar opening sources.
The path witness emits 324,352 G rows and 92,672 XOR rows. Query and terminal
routing reuse the retained transcript plan; emitted-transcript callers retain
fixed/live receipt checks. A new execution root adapter pins the preprocessing
root to the independently admitted execution key and binds the single PCS nonce.
All roots retain their complete 32-byte representation.

The execution gate passes root/query substitution rejection and idempotent
Merkle-direction/projection fanout, alongside the earlier arithmetic and payload
checks (ReleaseSafe, 1 minute build/test time, 4 GiB peak RSS). This is diagnostic
q8/PoW0 evidence. Full parent row assembly, parent key/proof qualification,
multilevel recursion and default promotion remain unfinished; no speedup claimed.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-execution-openings/README.md).

### Full-width execution parent proof and shared preparation — 2026-09-22

The new owning preparation joins the three execution verifier graphs and all
transcript/opening input routes into the shared parent assembler. It writes hash
witnesses directly into final columns and transfers those columns only after
successful assembly. A removed secure claim producer rejects without losing
column ownership. Shared storage and input-inventory modules reduce the assembler
to 283 lines while preserving the earlier native adapter.

The real execution parent passes proving, bounded artifact encode/decode and
independent verification after its proving plan is destroyed. Its BLAKE3 key
identity binds the full child key, parameters, graph and transcript identities,
AIR geometry and preprocessing root. The artifact is 124,866 bytes; preparation
retains 526,596,548 bytes and accounts for 13,738 graph inputs. The gate passes in
ReleaseSafe (2 minutes build/test time, 5 GiB peak RSS). The earlier native census
also passes (1 test, 11 seconds runtime; 1 minute compile), preserving its
missing/duplicate input rejection checks and shared fusion path.

Both child and parent use diagnostic q8/PoW0. This completes the explicit
single-level base execution-parent path, not multilevel recursion, production
parameter qualification, continuation/extensions, default promotion or the
original speed goal. The frontend and CPU integration expose the explicit API.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-execution-parent/README.md).

### Distinct-key unary parent-of-parent proof — 2026-09-22

A verified typed parent can now feed the same owning preparation used by base
execution leaves. Its transport receipt retains challenges and seals proof
capture/claims/transcript state against the admitted key. Its recursive
composition reuses authenticated typed programs and shared table equations;
DEEP geometry comes from the admitted roster. Protocol-specific transcript
framing is replayed through the shared bounded BLAKE3 witness planner.

The real execution-parent proof and its parent both independently verify after
artifact roundtrip and proving-plan destruction. Their keys are distinct, and
the second key binds the first. Artifacts are 124,866 and 121,966 bytes; the
second preparation has 18,565 inputs and retains 523,271,232 bytes. Capture
mutation and key/graph/transcript substitution checks reject. The ReleaseSafe
gate passes in 2 minutes build/test time with 5 GiB peak RSS.

This qualifies two unary recursion levels at q8/PoW0, not distinct-child
aggregation, continuation/extensions, production security parameters, Metal
parity or default promotion. No speedup claim is made.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-parent-of-parent/README.md).

### Continuation memory conversion and public custody — 2026-09-22

A canonical multi-byte transition chains the existing shared-sibling update AIR,
with full-width intermediate roots, disjoint namespaces, caller-pinned identity,
independent fixed-column reconstruction and transactional preparation cleanup.
Public-I/O custody derives allowed edits from admitted execution data and memory
schedules; snapshot roles cannot authorize edits. Every byte of an excluded word
is checked, including zero bytes. The ordinary commitment witness now prepares
this conversion against a caller-supplied full-memory endpoint.

The focused memory-update gate passes in ReleaseSafe (36 seconds build/test,
1 GiB peak RSS), requiring five named tests. The chained diagnostic q8/PoW0 STARK
proves insertion/deletion and rejects substituted intermediate-root preprocessing.
Admission and witness mutation checks pass. A real runner with declared nonzero
input produces entry/exit conversions matching independently built full snapshot
roots, and substituted full roots reject. This runner check is not a new joined
execution/continuation proof.

Span endpoint authentication and inclusion of conversion rows in an aggregation
proof remain unfinished, as do distinct-child aggregation, extension/CSP wiring,
production qualification/default promotion and the performance goal.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-continuation-custody/README.md).

### Execution Span and converted endpoints in the parent proof — 2026-09-22

The execution parent now admits the leaf Span against the verified child's
public data, commitment schedules and full-memory conversion endpoints. A
versioned BLAKE3 input/output identity preserves all u32 bits and excludes
proof-only output access clocks. Final Span admission rejects mere segment-boundary
fetch completion. The profile reserves the separate machine I/O-state digest as
zero; full memory and edge claims carry the I/O state.

Conversion paths enter the actual parent proof using its existing typed AIRs.
Public byte constants directly supply hash inputs, eliminating redundant private
copy bridges for this public-custody path. A transactional appender extends final
columns and remaps their committed row layout only when domains grow. Namespace
isolation reads actual circuit identifiers from typed relation effects, including
witness-column identifiers. Parent key version 2 binds the Span and conversion
identities; parent-of-parent preparation preserves those identities through the
admitted child key.

The real six-instruction fixture publishes a nonzero output byte and proves eight
updates between distinct ordinary/full final-memory roots. Both recursive parents
round-trip and independently verify after proving-plan release (artifacts 126,640
and 124,256 bytes). The ReleaseSafe execution gate passes in 2 minutes with 5 GiB
peak RSS. Focused custody/admission and namespace/column-growth gates pass in
32 seconds / 1 GiB and 6 seconds / 564 MiB. Tampered registers, roots, output
identities, fixed schedules and key metadata reject.

This remains diagnostic q8/PoW0 CPU evidence with specialized admitted keys.
Distinct-child aggregation, multi-segment orchestration, extensions/CSP integration,
production parameter/key qualification, Metal parity, default promotion and the
performance goal remain incomplete.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-execution-span-parent/README.md).

### Child namespace isolation and direct parent-column join — 2026-09-22

An authenticated relocation plan now derives circuit fields from typed relation
effects, includes the older arithmetic AIRs' selector-controlled circuit
schedules, and assigns a dense injective range. Full preflight precedes in-place
identifier updates. The real nonzero-output execution parent relocates 10,520
identifiers into [1, 10521) while retaining its main buffers. Both parent and
parent-of-parent artifacts independently verify (125,652 / 124,381 bytes;
ReleaseSafe execution gate: 2 minutes, 5 GiB peak RSS, diagnostic q8/PoW0).

The new two-source column join validates exact source geometry and disjoint
identifier ranges, then copies directly into final columns with the necessary
row-permutation remapping. Focused append/join checks pass (10 seconds, 826 MiB),
including overlap, out-of-range identifiers, malformed geometry, padding and
source preservation. No combined two-child STARK has yet qualified this join.

This prepares aggregation but does not complete it. Adjacent segment proving,
a key binding both child contexts and the folded Span, the aggregate proof and
later-level verification remain to integrate, alongside production qualification
and the original performance goal.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-parent-namespace-join/README.md).

### Adjacent execution segments aggregate through another recursion level — 2026-09-22

The leaf-local segment adapter owns public I/O and canonical execution witnesses.
Boundary program-fetch compensation now matches the commitment witness in both
native and recursive BLAKE3 verification; execution transcript framing advances
to version 3 while legacy compensation behavior stays unchanged.

The aggregate admits both child Spans, checks their continuity, relocates each
child into disjoint namespaces and joins directly into final columns. Parent key
version 3 binds both child contexts, their statement/custody identities and both
namespace plans. A later recursive verifier carries the aggregate statement and
custody identity through its admitted child key.

The focused ReleaseSafe aggregation gate passed in 3 minutes with 7 GiB peak RSS.
Two real runner segments cover six retired instructions and a nonzero output.
The aggregate and its parent independently verify after artifact roundtrip and
proving-plan destruction. Artifacts are 132,947 and 122,984 bytes; aggregate
preparation retains 1,082,774,500 bytes, and the next level 538,770,400 bytes.
Substituted child-key/context metadata and reversed segment order reject.
This is diagnostic q8/PoW0 CPU evidence, not canonical security qualification
or a measurement of end-to-end proving speed. General production orchestration,
extensions, canonical recursion parameters, Metal parity and default promotion
remain open.

Segment-to-parent preparation is exposed as
`prover.blake3_segment_parent.ForBackend(Backend).prepare`. It borrows a
caller-pinned reusable verifier and preflights the owner's statement, Span and
memory custody before consuming the execution interaction phase. The real
aggregation fixture now exercises this API rather than duplicating preparation
inside its test. Evidence and source snapshots are recorded in
[the aggregation note](../../../autoresearch/notes/2026-09-22-blake3-adjacent-aggregation/README.md).

### Four-segment binary tree with owning verified nodes — 2026-09-22

`blake3_execution_parent.tree.Node` authenticates the supplied Span against an
independently admitted key, consumes the artifact on every path and owns its
verified capture. `preparePair` rejects aliases, mismatched jobs/levels and
nonadjacent spans before allocating witnesses. It reconstructs each child's
verifier columns from verified captures and joins them with the existing
namespace-isolated fold. Returned witness ownership is independent of both nodes;
earlier execution/aggregate witnesses are not required.

A real runner executes four segments of 1, 1, 1 and 3 retired instructions,
including nonzero output. The two intermediate aggregate artifacts (130,994 and
132,374 bytes) and their aggregate root (131,497 bytes) independently verify
after proving-plan destruction and artifact roundtrip. Root coverage admission
succeeds, both child-key bindings match, alias/reversed-order and wrong-key cases
reject, and the borrowed child nodes remain valid. The focused ReleaseSafe
four-leaf gate passed in 5 minutes with 6 GiB peak RSS; root preparation retains
1,077,529,688 bytes. This remains diagnostic q8/PoW0 CPU qualification.

The existing bounded overlap scheduler is still coupled to older native-child
preparation/worker types. Adapting it to these inputs, padding/general scheduling,
production key admission, extension/precompile migration, canonical recursion
parameters, Metal parity and default replacement remain unfinished. The original
performance objective stays active; this is not an end-to-end speedup claim.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-four-leaf-tree/README.md).

### Shared bounded scheduler accepts BLAKE3 tree pairs — 2026-09-22

The native-child pipeline now delegates to one adapter-driven implementation of
resource admission, a single-slot ownership queue, cancellation, interval timing
and preparation/proving overlap. The tree adapter prepares verified-node pairs
under a live host-allocation cap, checks their context against the caller's
admitted key, and transfers allocator custody with the prepared columns.

The worker is protocol-parametric and retains its CPU pool and scratch workspace.
Same-key jobs reuse the immutable plan and fixed commitment. Different admitted
keys can construct a replacement within the same budget; failure preserves the
old plan, with replacement and proving covered by one worker lease. Successful
different-key replacement is not yet qualified by this fixture.

The real four-segment tree gate now submits two copies of its root job. Both
outputs and a codec copy independently verify after worker destruction, with
allocator leases retained by the captures. CPU/RSS overcommit, one-byte
preparation admission, duplicate worker leasing and a wrong-root replacement
reject. The same plan/fixed columns remain allocated across both jobs.

The ReleaseSafe focused gate passed in 6 minutes with 9 GiB peak RSS. Preparation
and proving overlap by 11,142,619,042 ns. Worker peak routed allocations are
6,036,200,199 bytes under an 8,589,934,592-byte cap. Combined admission reserves
25,794,988,912 bytes and three CPU tokens. Root artifacts remain 131,497 bytes.
These are same-workload resource/overlap measurements at diagnostic q8/PoW0;
there is no comparative end-to-end speedup or production activation claim.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-tree-pipeline/README.md).

The native adapter regression also passes 3/3 tests after extraction (1 minute
compile, 50 seconds execution; 6 GiB compile / 1 GiB run peak). Its existing real
two-job parent pipeline records 2,403,698,791 ns overlap and 982,008,191 routed
worker peak bytes under a 4 GiB cap, with plan/workspace and post-destruction
verification checks intact. The same evidence note retains both terminal logs.

### Explicit q70/PoW26 parent profile and successful worker rekey — 2026-09-22

Execution-parent key derivation now accepts an explicit profile. The new
`csp_q70_pow26` tag pins 70 queries, 26 PoW bits, log blowup 1, last-layer bound 0,
fold step 1 and absent lifting override. The existing diagnostic default and
version-3 encoding remain in place. Profile/config mismatches and a diagnostic
key substituted for the new artifact reject.

The real execution parent proves under the new profile and independently verifies
both directly and after artifact roundtrip. The persistent worker successfully
replaces its diagnostic plan with the new admitted plan while retaining its pool,
and both outputs verify after worker destruction. The recursive bounded transcript
planner emits 39,704 G rows and reproduces the verified digest/draw counter.

The focused ReleaseSafe gate passes in 3 minutes with 5 GiB peak RSS. The 70/26
artifact is 738,033 bytes. The child is explicitly q8/PoW0: stronger outer PCS
parameters do not upgrade child soundness. A full 70/26 chain, a STARK verifying
this 70-query parent, production key admission, Metal qualification and default
promotion remain unfinished. This is not the separately reviewed larger-domain/
fewer-query performance experiment or an end-to-end speedup result.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-parent-csp-profile/README.md).

### Execution leaf through recursive parent at q70/PoW26 — 2026-09-22

A dedicated `test-riscv-blake3-canonical-chain` target now proves the real
nonzero-output execution leaf with 70 queries and 26 PoW bits, prepares its
full-memory Span/custody through the shared segment pipeline, and proves the
parent at the same profile. The parent's admitted child configuration is checked
against the exact 70/26 profile; this closes the mixed-profile limitation of the
preceding parent-only fixture for one leaf-to-parent chain.

The parent artifact and an independently decoded copy verify and pass complete
root coverage after destruction of the runner/leaf owners, parent columns and
persistent worker. The original verified capture retains allocator custody.
The focused ReleaseSafe gate passes in 4 minutes with 25 GiB peak RSS. Parent
preparation contains 81,132 inputs and retains 4,214,454,616 bytes. The artifact
is 860,503 bytes. Worker routed peak is 23,106,927,066 bytes under its 24 GiB
(25,769,803,776-byte) cap with four proof workers.

This qualifies a CPU execution leaf plus one recursive parent at 70/26. It does
not qualify a canonical multi-segment tree, another recursive level, Metal,
production key authority, precompile migration or default promotion. The memory
cost is now measured and constrains parallel scheduling; no end-to-end speedup
is claimed. The separate target keeps this expensive qualification out of the
ordinary diagnostic iteration loop.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-canonical-chain/README.md).

### Compact persistent parent metadata reduces routed peak — 2026-09-22

The immutable parent plan now stores only fixed preprocessing fields and selector
parameters. It no longer duplicates and zeroes main-column placeholders in every
metadata row. The interaction runtime reconstructs logical rows from existing
main columns plus compact fixed tails, with strict geometry, representation and
source/destination alias checks. Preprocessing projection and all AIR/lookup,
transcript, key and PCS semantics remain unchanged.

The focused full-row/compact interaction parity and rejection gate passes in
9 seconds / 832 MiB. The same q70/PoW26 leaf-to-parent proof passes in 4 minutes /
24 GiB RSS after worker and witness destruction. Prepared columns remain
4,214,454,616 bytes and the verified artifact remains 860,503 bytes. Compact plan
metadata is 376,119,932 bytes. Routed worker peak drops from 23,106,927,066 to
21,518,565,568 bytes, saving 1,588,361,498 bytes (6.87%) with the same 24 GiB cap.

This reduces one redundant persistent copy. Prepared metadata and large PCS
commitments remain substantial, and no latency speedup, production migration
completion or parameter/security change is claimed.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-compact-plan-metadata/README.md).

The native regression gate also passes 3/3 tests (1 minute compile / 6 GiB,
50 seconds run / 1 GiB), preserving fixed-row mutation rejection, persistent-plan
reuse, bounded pipeline behavior and post-worker verification. Its routed worker
peak is 930,536,163 bytes, down from 982,008,191 under the same 4 GiB cap.

### Owned interaction columns eliminate PCS source duplication — 2026-09-22

Parent AIR and lookup interaction outputs now transfer ownership directly into
PCS through its existing bounded streaming dispatch. Column/claim parity and
allocation-failure cleanup pass. The canonical q70/PoW26 leaf-to-parent gate
passes in 4 minutes / 23 GiB RSS, with unchanged 860,503-byte artifact and
independent verification after witness/worker destruction. Routed worker peak
falls from 21,518,565,568 to 19,514,934,660 bytes (9.31%); combined with compact
metadata this saves 15.54% against the original 23,106,927,066-byte baseline.
The native regression also passes 3/3 tests. No latency speedup or completed
production migration is claimed.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-owned-interactions/README.md).

### Shared execution-segment pairing API — 2026-09-22

Adjacent execution leaf pairing now lives in the public segment-parent API. It
validates both caller-pinned child keys, Spans and memory custody before either
interaction phase is consumed, then shares the existing proof/capture and
namespace-safe aggregation implementation. The four-leaf fixture uses this API
and qualifies second-child key rejection without consuming either owner, alias
rejection, two distinct intermediate aggregates, and the independently verified
root through the bounded pipeline. The diagnostic CPU gate passes in 5 minutes /
9 GiB RSS. This does not activate production routing or extension support.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-segment-pair-api/README.md).

### Ethereum witnesses join full-width BLAKE3 providers — 2026-09-22

A shared preparation owner now accounts for Ethereum external retirements,
validates runner public I/O and completion, includes all external program fetches,
and builds native plus BLAKE3 commitment columns without legacy commitment
witnesses. Existing Ethereum caller lookup registration runs before shared
lookup tables are emitted. Base-only proof admission still rejects external
retirements. The existing extension interaction generator is extracted into
an owning API used by both paths, preserving the legacy challenge schedule.

A real signer-recovery + Keccak fixture passes full interaction generation and
global relation closure in the focused gate (4 minutes / 12 GiB build/test peak).
Dropping extension claims fails closure; omitting an output-length word now
fails public-I/O preflight before witness generation. The existing canonical
BLAKE3 CSP ECDSA proof also passes 1/1 regression tests at q70/PoW26. Neither
result qualifies a full-width extension STARK or production activation.
[Evidence](../../../autoresearch/notes/2026-09-22-blake3-ethereum-witness/README.md).

### Full-width Ethereum proof independently verifies — 2026-09-23

The explicit B3EH/1 proof and B3HK/1 caller-pinned key now join native execution,
full-width BLAKE3 program/memory providers and the existing Ethereum AIRs.
Persistent verifier preparation owns public I/O and schedules and independently
derives the fixed root and PCS geometry. The coefficient certificate includes
BLAKE3 provider domains and complete public memory terms. Native, hash and
extension claims share one closed relation system and transcript.

One signer recovery plus one Keccak call proves and independently verifies on
CPU at diagnostic q8/PoW0 after witness destruction and caller-I/O mutation.
Wrong-key proving rejects before interactions; modified coefficient admission
rejects. The gate reports 10 minutes / 30 GiB peak RSS with four proof workers.
This material memory cost must be included in future scheduling admission; no
latency speedup or canonical-security qualification is claimed.

The separate witness regression passes (4 minutes / 12 GiB), and the existing
canonical BLAKE3 CSP ECDSA path passes 1/1 tests after the shared main-column,
selector and AIR-construction refactors. Extension artifact transport, recursive
capture, canonical CPU/Metal qualification and production activation remain open.
[Evidence](../../../autoresearch/notes/2026-09-23-blake3-ethereum-proof/README.md).

### Canonical full-width Ethereum artifact and capture — 2026-09-23

B3EHART1 validates its caller-pinned key, fixed claim geometry, canonical field
limbs, byte lengths and nested proof bounds before allocating payload data.
Shared extension claim encoding preserves the existing Ethereum envelope format.
Successful verification retains the proof, claims, 26 extension draws, fourteen
component placements and final channel, protected by a mutation seal.

The canonical CPU q70/PoW26 gate passes serialization/re-encoding, captured and
ordinary verification after original proof/witness destruction, and malformed
artifact/capture mutation checks. The gate takes 10 minutes / 30 GiB with four
workers. Recursive Ethereum equations, canonical multi-segment qualification,
Metal and production switching remain open.
[Evidence](../../../autoresearch/notes/2026-09-23-blake3-ethereum-artifact/README.md).

The shared canonical CSP ECDSA regression also passes 1/1 tests after extension
wire/challenge extraction (ReleaseSafe, q70/PoW26; 3,748,258-byte proof). Existing
ReleaseFast CSP benchmark results remain unchanged.

### Full-width Ethereum recursive parent — 2026-09-23

The shared Ethereum equation recorder now supports both the legacy symbolic
scalar and BLAKE3 composition graphs. Full-width extension geometry comes from
production mask vtables. Detailed claims and their separately mixed aggregates
are connected by constraints; all 60 challenge pairs are exported and routed.
DEEP uses the complete admitted component assembly, while FRI, PCS paths and
final-layout hash emission reuse the existing parent machinery.

A real signer-recovery + Keccak leaf and its parent independently verify at
diagnostic q8/PoW0, including parent artifact decoding after worker/prepared-row
destruction. The 14-minute build/test gate peaks at 30 GiB. Parent retained
preparation is 2,231,719,096 bytes; worker peak is 10,155,522,628 bytes; artifact
is 132,105 bytes. This does not qualify canonical Ethereum recursion, Ethereum
segment Span/custody, Metal or production activation.
[Evidence](../../../autoresearch/notes/2026-09-23-blake3-ethereum-recursion/README.md).

Both shared regressions pass: the original Ethereum equation/mask/cold-program
gate passes 6/6 tests, and the canonical q70/PoW26 base leaf-to-parent gate passes
with its prior 860,503-byte artifact and 19,514,934,660-byte worker peak unchanged.
All builds for this batch are terminal; see the linked evidence bundle for logs.

### Ethereum segment Span/custody and aggregate root — 2026-09-23

The real leaf-local Ethereum segment runner now feeds the full-width witness
owner. Base and Ethereum share public-I/O ownership, segment boundary validation
and completion handling. The shared segment-parent path admits both caller-pinned
keys and custody plans before consuming either leaf's interactions, then uses
the existing recursive Span binding and namespace-safe aggregation.

A signer-recovery first segment resumes into Keccak and completion in a second
segment. Both leaves and the aggregate root independently verify at diagnostic
q8/PoW0 with full-memory continuity and custody conversions. The decoded root
verifies after witness/worker/prepared-row release. The gate reports 25 minutes /
37 GiB, 4,476,857,164 retained preparation bytes, a 20,271,200,200-byte tracked
worker peak and 144,055-byte root artifact. Canonical Ethereum recursion, Metal
and production activation remain open.
[Evidence](../../../autoresearch/notes/2026-09-23-blake3-ethereum-segments/README.md).

The one-shot Ethereum witness regression also passes (4 minutes / 12 GiB),
and the canonical base leaf-to-parent regression passes (4 minutes / 23 GiB)
with its artifact and tracked worker peak unchanged. All three gates in this
segment integration batch are terminal and passing.


### Release artifact qualification update (2026-09-23)

The updated owned-pair diagnostic aggregation gate passed, including two recursion
levels. The legacy statement-wire target passed, and the Metal quotient planner
regression target passed 9/9 tests. Full Metal recursion qualification remains
pending; the planner result alone does not prove that integration.

The full-width base artifact and CLI verification route are implemented but not
fully qualified. The base artifact gate exposed a diagnostic ELF missing release
ABI symbols. The fixture now supplies the complete ABI without weakening source
validation, and checks rejection of incomplete ABI and substituted program bytes.
The corrected real-proof gate is queued. Production proof-generation routing and
default switching remain outstanding. Evidence and source snapshots:
`autoresearch/notes/2026-09-23-blake3-release-artifact/`.


### Explicit base product route (2026-09-23, qualification pending)

Explicit `--proof-suite blake3` base `prove` and `bench` requests now enter the
full-width execution owner and B3RVART1 artifact transaction. The request releases
runner and witness owners, then reconstructs admission and independently verifies
the serialized artifact before publication. The outer CLI retains atomic output
publication. Benchmark samples enforce stable statement/transcript identities.
Metal requests require dispatches during the proof itself and report fallbacks.

The new `riscv_full_width_execution_v1` report identifies phase timings in
nanoseconds: execution, witness, proving, artifact encoding (including admission
key construction), and fresh verification. Its total/median includes all five;
it is not the old CSP witness/prove-only timing or an exact-work task profile.
Defaults remain unchanged. Extension-profile routing and existing CSP measurement
integration still require migration. Product compilation and runtime qualification
are pending in `/tmp/blake3-artifact-cpu-product-build.log`; syntax checks passed.


### Canonical compact Metal parent qualified (2026-09-23)

The wide-source quotient fix passed the full SMP Metal parent gate: 8/8 tests,
q70/26, independent CPU verification, 191 parent dispatches and two CPU fallbacks.
Prepared storage was 5,953,718,776 bytes and worker peak 27,708,198,754 bytes.
The 907,988-byte parent artifact verified after worker/row destruction. This
supersedes the earlier pending Metal retry; it does not qualify the new product
artifact path or constitute a production latency result. Log and source evidence:
`autoresearch/notes/2026-09-23-blake3-metal-wide-fragmentation/`.

Product request review also restored the shared run-admission gate and corrected
the public execution API reference. New full-width product and verification
receipts explicitly use `experimental_full_width` release status.


### Base full-width artifact gate passed (2026-09-23)

The release-ABI fixture rerun passed. It qualifies the typed statement/plan wire,
authenticated manifest, actual ELF/input source binding, and B3RVART1 fresh
verification after proof destruction, plus the existing recursive subcases.
The canonical-parent subcase still has a diagnostic child (q8/0), so it is not
reported as a fully canonical tree. Product compilation and separate CLI
prove/verify remain pending. Evidence:
`autoresearch/notes/2026-09-23-blake3-release-artifact/base-artifact-pass.log`.


### Base CPU product and CLI qualification passed (2026-09-23)

The CPU product build and separate-process CLI prove/verify passed for both smoke
and canonical q70/26. The canonical B3RVART1 artifact is 609,851 bytes and its
transcript agrees between prover and fresh verifier. Six adversarial CLI cases
rejected wrong statement/source/policy/suite, truncation and altered proof bytes.
The new benchmark path passed one warmup plus two measured samples, exact additive
phase timing checks, and fresh verification of the retained final artifact.

Evidence, receipts, fixture and canonical artifact are retained in
`autoresearch/notes/2026-09-23-blake3-release-artifact/`. This qualifies the explicit
base CPU path; extension/CSP routing, Metal product qualification, default
promotion, and obsolete prover-owned Poseidon removal remain unfinished.


### Device-independent product verifier wiring (qualification pending)

Full-width product verification now reconstructs its admitted key on CPU for
both CPU and Metal products. This preserves the Metal verify-only command's
contract of requiring no proving runtime and makes Metal publication verification
independent of device computation. The shared adapter reuses an existing CPU
backend module to avoid duplicate Zig module ownership. Metal closure policy
explicitly includes the CPU verifier implementation. Both product rebuilds are
pending; earlier CLI results predate this graph change. Evidence and next checks:
`autoresearch/notes/2026-09-23-blake3-independent-product-verifier/`.


### CPU/Metal base product cross-verification qualified (2026-09-23)

Both corrected product builds passed. The Metal canonical q70/26 proof recorded
67 device dispatches and six CPU fallbacks; its statement and transcript match the
CPU artifact exactly. Fresh CPU and Metal executable processes each verified both
artifacts. Metal verify-only checks used an invalid AOT environment path, proving
they do not enter device runtime admission. Evidence and receipts:
`autoresearch/notes/2026-09-23-blake3-independent-product-verifier/`.

This supersedes the pending verifier graph qualification. It covers the tiny base
fixture, not extension/CSP full-width routing or the default switch, which remain
outstanding. Expanded Ethereum block support remains deferred.


### Ethereum admission metadata integration (qualification pending)

B3EHADM1 now authenticates the Ethereum extension and shared typed native/plan
metadata together. The base codec's framing is reused through explicit profile
contexts; its default/base wrappers retain their original checks and bytes.
Ethereum source validation binds the actual profile ELF and full-width initial
roots. Hash geometry derivation avoids allocating witness columns just to validate
metadata. The canonical signer/Keccak fixture now constructs admission from the
received manifest and releases decoded metadata before proving.

Canonical Ethereum metadata/proof and base regression gates are running/queued.
Sources, commands and scope are recorded in
`autoresearch/notes/2026-09-23-blake3-ethereum-manifest/`. Full product artifact
routing for extensions and CSP, default promotion, and obsolete hashing removal
remain outstanding; expanded block proving remains deferred.


### Ethereum manifest qualified; full artifact/product route pending

The canonical q70/26 Ethereum manifest/source gate passed, including independently
reconstructed admission and released witness verification. The subsequent batch
adds B3EVART1 through shared base/Ethereum artifact framing and connects explicit
BLAKE3 Ethereum prove/bench/verify to the shared product transaction. The v2
execution report separately measures admission/key construction; Ethereum
benchmark requests share a bounded scoped worker pool. Syntax checks passed;
base regression, CPU product build and full Ethereum artifact gate are queued.
Evidence: `autoresearch/notes/2026-09-23-blake3-ethereum-product-artifact/`.
No extension product qualification, default switch or expanded block support is
claimed yet.


### Product receipt and CSP integration review

The shared base artifact regression passed. The first Ethereum product build
caught a missing required worker-count option; the product now explicitly caps
its retained pool at 16 workers, and the corrected build is queued. Full Ethereum
artifact proof qualification remains live.

Product reports/fresh-verifier receipts now project output/source hashes and
execution steps from successfully verified public data, and include PCS policy;
benchmark reports include process resource telemetry. These additions await the
corrected product build and CLI checks. The CSP software harness still expects
legacy JSON artifacts/reports, while its separate ECDSA command retains the older
commitment path. Both need integration before any full-width CSP suite claim.


### Full Ethereum artifact and CSP reader update

The canonical full Ethereum artifact gate and corrected CPU product build passed.
A separate canonical CLI proof is active; it is not yet qualified. The CSP software
reader now admits the new binary artifacts/reports with source/output/transcript
cross-checks against a separate verifier receipt, exact canonical parameters and
additive timing validation. It preserves STARK-only proof size and distinguishes
full-width commitment rows. 34 focused Python tests passed. Evidence:
`autoresearch/notes/2026-09-23-blake3-csp-full-width-reader/`.

The dedicated ECDSA command still uses the older commitment path. No full-width
CSP matrix or speed comparison is claimed until that route and actual suite runs
are completed.


### Canonical CPU Ethereum product CLI qualified

The explicit BLAKE3 Ethereum CLI produced and freshly verified a q70/26 B3EVART1
artifact. Verified output/source hashes, steps and transcript match the report.
The artifact is 5,599,503 bytes, including 5,566,284 serialized STARK bytes. The
new verifier also accepts the retained canonical base artifact and reports its
correct nonempty output hash. Receipts and full artifact are retained in
`autoresearch/notes/2026-09-23-blake3-ethereum-product-artifact/`.

The one-signer/one-Keccak ReleaseSafe CLI run took 154.286922125 seconds, dominated
by 125.707944791 seconds of proving. This is qualification evidence, not a speedup
claim or a comparison with ReleaseFast CSP ECDSA timing. Metal Ethereum product,
dedicated full-width CSP ECDSA, actual CSP suite runs, remaining standalone
profiles and default/legacy-path cleanup remain unfinished.


### Dedicated ECDSA command migration (2026-09-23, qualification in progress)

The BLAKE3 `ecdsa-csp-bench` command now delegates to the shared full-width
Ethereum artifact transaction, retaining a single backend runtime and worker
pool. It publishes only after fresh CPU verification and checking the verified
public summary: one signer call, zero Keccak calls, halt completion, and the
32-byte success output matching the canonical input. `ecdsa-csp-verify` now
requires `--expect-statement-digest` for BLAKE3; it never trusts an identity
extracted from the received artifact as its own admission authority.

The CSP reader accepts the full-width report, validates phase accounting and
artifact payload size, and requires a matching independent CSP verifier receipt.
Precompile cycle counts are bound by that receipt, not borrowed from the software
guest baseline. No software-trace evidence is fabricated. Dirty-build publication
rejection remains in force. Profiling this route emits the disjoint phase report.

CPU product compilation passed; 29 focused Python tests and the Zig public-summary
contract test passed. A canonical ECDSA CPU ReleaseSafe qualification is running;
no full-width ECDSA performance result is established yet. Metal build/runtime
qualification of this dedicated command and default promotion remain outstanding.
Expanded Ethereum block functionality remains deferred by user direction.


Qualification update: both dedicated command products compile, but the canonical
CPU ECDSA ReleaseSafe run was stopped at a measured 81.2 GiB footprint; it did
not publish a verified artifact or timing result. A follow-up removes retained
coefficient duplicates and bounds borrowed-column preparation to eight columns.
Complete PCS proof parity and failure-ownership checks pass; ECDSA memory/runtime
qualification remains outstanding. See `autoresearch/notes/2026-09-23-blake3-csp-shared-route`.


Bounded leaf preparation follow-up: final CPU/Metal builds passed, and canonical
base proofs remain byte-identical across both backends and to the retained
pre-change artifact. Cross-verification passed with no Metal runtime required.
Metal telemetry changed to 131 dispatches / 36 fallbacks, so no speedup is claimed.
The ECDSA resource failure remains an open qualification issue despite passing
base regression and PCS ownership/proof parity tests.


### Bounded ECDSA geometry (2026-09-23)

The 36 GiB host-allocation run failed cleanly without publishing output. Its 1,828
steps require 303 memory-word and 404 program-word schedules. Four independent
paths per word generate 172,508 compression blocks / 9,660,448 G rows (padded to
2^24), explaining why storage policy changes alone cannot finish qualification.
Census no longer materializes every trusted path solely to count rows; emission
parity and admission-tamper checks pass. A tested sparse shared-path topology is
implemented, but its authenticated AIR/hash emission is still pending. This is
the next structural change, not a claim that full-width ECDSA is now qualified.
Evidence: `autoresearch/notes/2026-09-23-blake3-csp-memory-geometry/README.md`.


### Shared-path AIR integration and canonical ECDSA (2026-09-23)

Shared topology now drives actual witness and verifier preprocessing, with exact
parent fanout, private frontier digests and public root sinks. Plan identity and
codec version 2 prevent reinterpretation of independent-path plans. Canonical
ECDSA completes and independently verifies on CPU and Metal with identical
artifacts: 489,328 G rows versus 9,660,448 previously, and tracked host peaks near
3 GiB. Dirty ReleaseSafe complete transactions were 18.414 s CPU / 18.742 s Metal;
these are qualifications, not clean performance comparisons. Full canonical
Ethereum recursion requalification is running. Evidence and source snapshots:
`autoresearch/notes/2026-09-23-blake3-shared-path-ecdsa/README.md`.


Canonical shared-path Ethereum recursion requalification passed on CPU: leaf and
parent both 70/26, fresh verification after worker/row destruction, artifact
907,299 bytes and tracked worker peak 32,402,522,298 bytes within 36 GiB. This
qualifies the circuit change, not an order-of-magnitude parent speedup. A live
sample identified barycentric weight construction during parent opening as a
profiling lead. Canonical Metal-parent requalification remains pending.


### 2026-09-23: guest Poseidon full-width witness and admission

The guest Poseidon adapter now has a full-width BLAKE3 witness owner, native/hash
coefficient admission, shared lookup registration and guest interaction generation.
The existing guest permutation/caller constraints and row preflight are reused.
A release-ABI Poseidon guest closes the combined native + BLAKE3 + guest lookup
claims, independently binds its ELF/input roots, and contains no legacy commitment
components. Focused guest compatibility and the Ethereum external witness census
both pass in ReleaseSafe after extracting their common BLAKE3 admission bounds.

This milestone does **not** qualify a complete Poseidon-profile proof or product
route. Next: shared proof assembly/transcript, pinned artifact admission, product
routing, recursive capture and CPU/Metal proof qualification. Default promotion,
obsolete commitment-route removal and clean ReleaseFast CSP results remain pending.
See [retained evidence](../../../autoresearch/notes/2026-09-23-blake3-guest-poseidon-witness/README.md).


### 2026-09-23: shared extension proofs and guest Poseidon CPU/Metal product

Ethereum and guest Poseidon now use one typed extension pipeline for proof
orchestration, prepared keys, verified captures, bounded proof decoding and
source-bound admission manifests. The Poseidon profile has distinct transcript,
key, proof and published-artifact identities. Its main-column adapter borrows
final-layout witness values. The existing guest permutation AIR is preserved;
its execution commitments use BLAKE3.

Both full CPU proof tests pass at q70/PoW26, including fresh artifact verification
and negative pin/source/capture checks. The real Rust precompile guest runs
through the shared CPU and Metal CLI transactions: 84 steps, 64 output bytes,
byte-identical 1,091,213-byte artifacts and successful cross-verification. Metal
records 348 dispatches / 41 CPU fallbacks. A separate Metal CLI verification works
with a nonexistent AOT bundle path. The refactored CPU verifier also accepts the
retained canonical full-width ECDSA artifact without regenerating it.

These are dirty ReleaseSafe qualifications, not new performance claims. Guest
Poseidon recursive circuit integration, default-suite promotion and obsolete
commitment-route removal are still pending. Canonical Metal-parent qualification
for the shared-path layout and clean ReleaseFast CSP results also remain pending.
See [source-pinned evidence](../../../autoresearch/notes/2026-09-23-blake3-shared-extension-pipeline/README.md).


### 2026-09-23: both extension profiles qualify through canonical recursion

Guest Poseidon now shares the typed BLAKE3 recursive verifier stack with Ethereum:
composition, DEEP, transcript, admitted roots and parent preparation. Guest AIR
semantics are preserved, with explicit detailed-claim totals, request/supply
cancellation and provider structural-zero constraints. CPU canonical parent and
both Metal extension parent gates pass at q70/PoW26, including fresh CPU
verification after worker and rows are released. Focused replay checks cover both
profiles and reject an altered claim. The combined Metal command passes 16 tests.

Parent artifacts are 867,999 bytes (guest Poseidon) and 907,299 bytes (Ethereum).
Metal tracked worker peaks are 12,979,996,846 and 27,580,232,194 bytes respectively;
both fit the 36 GiB worker allocation limit. These are qualification receipts,
not clean latency comparisons or evidence of a 10x speedup. This supersedes the
pending extension-recursion and Metal-parent items above. Default promotion,
obsolete prover-owned commitment-route removal, clean CSP measurements and the
original performance work remain open. See [retained evidence](../../../autoresearch/notes/2026-09-23-blake3-extension-recursion/README.md).


### 2026-09-23: BLAKE3 becomes the RISC-V and CSP default

The shared CPU/Metal CLI and CSP runner now select BLAKE3 by default. Benchmarks
always pass an explicit suite to proving and verification subprocesses. Both
ReleaseSafe products build successfully. The suite-selection test and 87 CSP
reader/precompile/wiring tests pass, including propagation of default BLAKE3 and
explicit historical BLAKE2s through report publication. Metal default-route
proving produces the exact retained explicit-suite artifact, with canonical
q70/PoW26, and standalone CPU verification requires no Metal runtime bundle.

Explicit BLAKE2s and its legacy proving implementations still exist; this is a
default promotion, not completion of route removal. Source and runtime receipts
are retained in [default-promotion evidence](../../../autoresearch/notes/2026-09-23-blake3-default-promotion/README.md).
No clean benchmark or additional performance claim is implied.


### Canonical product orchestration cleanup (in qualification)

Removed the legacy base and guest-profile proving transactions, the historical
CSP ECDSA proving loop and Metal-only guest Poseidon proving implementation.
The shared router dispatches the three supported typed profiles to full-width
BLAKE3. Legacy generation is refused while historical artifact verification stays
available. Product build and runtime qualification is recorded in
[canonical-route evidence](../../../autoresearch/notes/2026-09-23-blake3-canonical-product-route/README.md).
This does not yet remove all historical library or diagnostic recursion APIs.


The canonical-product cleanup qualifies on both rebuilt products. Legacy generation
refusals pass; fresh canonical CPU proving matches the retained artifact, and Metal
verifies that artifact. The final Metal help/registry refresh also passes. Historical
library/diagnostic recursion entry points remain under audit.

### Opening setup optimization (canonical parent requalification running)

Barycentric context construction now walks the circle-domain iterator and computes
its base-field constants in M31 before embedding them into QM31. Eight focused
ReleaseSafe tests pass, including exact comparison with the prior indexed QM31
algorithm. A paired ReleaseFast setup microbenchmark at log 16 measures a 1.626x
median improvement; this is not an end-to-end parent speedup. See
[raw timings and source](../../../autoresearch/notes/2026-09-23-barycentric-base-context/README.md).


The opening-context optimization passed canonical guest-Poseidon recursion:
leaf and parent q70/PoW26, parent artifact 867,999 bytes, fresh verification after
worker and rows are released. The qualification is not a latency comparison.

### Compatible parent-plan re-admission (qualification running)

The bounded BLAKE3 pipeline already overlaps preparation with a persistent worker.
The next change reuses authenticated fixed structure across compatible admitted
keys instead of always reconstructing it. It compares geometry, fixed root and
all fixed rows, while the next proof still mixes the new key and full parameters.
The diagnostic-to-canonical profile test now asserts plan-pointer reuse, distinct
key admission, independent proof verification and transcript replay. See
[implementation and gate](../../../autoresearch/notes/2026-09-23-blake3-parent-plan-reuse/README.md).


Compatible parent-plan re-admission passed the focused proof gate: the exact plan
allocation survives diagnostic-to-canonical rekeying, the parent independently
verifies at q70/PoW26, decoding with the old key is rejected, and the transcript
replays. The fixture child is diagnostic q8/PoW0. The same run verifies two levels
of diagnostic recursion. No latency claim follows from this reuse qualification.


### Canonical parent row census changes the next performance target

A focused authenticated q70/PoW26 guest-Poseidon parent preparation census passes
without proving another parent. BLAKE3 G contributes 86.3% of counted padded trace
words; byte routing 5.2%, XOR 2.7%, and arithmetic/opening components about 1.4%.
These are geometry shares, not measured time. Existing graph-fusion candidates
must not be counted again as new savings. Next: separate transcript, leaf-payload
and ancestor hashing costs before selecting hash-sharing changes. Retained
[raw census and analysis](../../../autoresearch/notes/2026-09-23-blake3-canonical-parent-census/README.md).


The detailed hash census passed: 62,328 transcript G rows, 807,520 leaf/subtree
rows and 2,304,960 ancestor rows (3,174,808 total). Per-root shared openings and
ancestors estimate 2,124,248 rows, a 33.1% live-row reduction, but still 27,096 rows
above the 2^21 boundary. The padded G domain would remain 2^22. This rules out
claiming that sharing alone halves the dominant domain in this fixture. See
[raw breakdown and bound](../../../autoresearch/notes/2026-09-23-blake3-hash-work-breakdown/README.md).
