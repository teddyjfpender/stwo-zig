# Block proving architecture redesign

Status: implementation in progress. The 218-segment candidate roster is a
qualification of the **old** per-segment-key path only. Stop that path after
recording its result; do not mistake a candidate roster, first-round geometry,
or a source replay for a complete block proof.

Current priority is the proof architecture, not standalone throughput tuning:
the v5 global program table and source seal, independently authenticated
initial-source families, reusable native proof template, and genuine multi-child
recursive verifier. Larger memory-instance performance sweeps are deferred
until those authority boundaries are implemented and freshly verified.

The first v5 ROM table proof has passed a focused q8 fresh-verification and
sum/count closure fixture, including changed ROM, multiplicity, and seal
rejection. The real-native same-root bridge now passes q8: one freshly verified
Ethereum-SHA native proof, a same-fixed/main-root request proof, and a global
ROM proof close an exact seven-fetch census (six retired opcode requests plus
one authenticated unretired terminal fetch) under one source seal. A serialized,
independently pinned program receiver passed 12 focused ReleaseFast checks,
including fresh proof verification, canonical IDs, B5SS challenge parity,
and malformed-preflight rejection. SHA/Keccak/signer caller fetches require
a sparse separate same-root request family before old per-leaf program custody
can be removed. A separate versioned block-v5 first-round seal now binds the exact program, execution,
memory, execution-sidecar, and program-request rosters; a complete receiver
must reconstruct it from independent pins. All v5 families must draw the frozen
47 universal challenges from one B5SS SourceSeal prefix; a program-specific
PCS proof domain may add transcript framing only after that common relation
draw. This resolves an integration mismatch found when the program table and
sorted memory were first brought together. The q8 local four-child recursive
proof passed fresh verification and child-order rejection. A five-real-leaf
mixed stage then proved one quartet and two exact roots, and its outer proof
freshly verified. A SHA-pinned detached manifest and independent mixed/outer
receivers passed kind, edge, file-hash, forest-digest, and outer-key tamper
gates. The bounded parallel mixed producer passed the same five-real-leaf q8
detached forest/outer gate (7/7), and its 218-leaf queue passed bounded
dependency and failure gates (2/2).

The mixed-radix planner now selects 70 four-child and three binary parents for
218 leaves, preserving the five exact roots and avoiding padding. That is 73
planned parent proofs instead of 213. Four-edge staged transport, a canonical
binary-tail encoding, a SHA-pinned v5 forest manifest, and a detached receiver
are implemented. Both file-backed serial and parallel q8 proof gates passed;
the complete block receiver is still required before production.

A standalone opcode program-request sidecar has passed a q8 PCS proof and
freshly verified closure against the ROM table, followed by the real-native
joint q8 gate. It still needs SHA/Keccak/signer fetch adapters. Separately, two differently
sized v5 sorted-memory instances, one shared range shard, and independently
pinned register/input/RW source files have freshly verified and closed at q8.
A re-pinned, re-sealed, and re-proved omitted first touch fails the global
initial relation; log-size, predecessor, root, and seal mutations also reject.
The old v2 q70/PoW26 memory transcript passed its focused regression.
An exact 59-instance planner fixture creates two M31-safe range shards. A
two-pass v5 memory artifact producer now passed a q8 fixture: roots-only
collection and shard counters precede the seal, then one trace at a time is
replayed, root-checked, proved, yielded to a sink, and freshly received. An
actual sorted Replay has now fed that producer and fresh receiver in a focused
ReleaseFast gate. An exact streaming ROM
census now merges validated full and sparse per-leaf fetch schedules into one
block-global table, checking complete image/root equality and choosing a ROM
AIR size independently of execution and memory. Its focused ReleaseFast test
passes alongside the source-seal test.

A versioned native-only proof passed two distinct same-geometry execution
states with one fixed root/template ID and different instance IDs. Its native
relation receipt is deliberately open. Catalog mode seals ordered per-leaf
template records so varied row geometries can coexist without a false
single-key claim. Two real different-geometry native leaves fresh-verified
under the catalog, with missing/changed-record negatives (7/7 ReleaseFast).
Cross-geometry key reuse
requires moving `isActive` from fixed to main columns and constraining its
Boolean prefix/count against the public statement. The opcode sidecar's
universal-memory recurrence passed a narrow three-case gate. A combined
same-root q8 sidecar proof then bound native opcode columns to transition,
byte-range, and opposite universal-memory claims (8/8 ReleaseFast); the native
and sidecar memory sums canceled in that fixture. Final RW and precompile
memory endpoints, plus the new recursive native-leaf verifier, remain in
progress. Until all receipts close, v5 cannot replace old per-leaf
custody or claim a complete block proof.

The independent family11 precompile STARK now fresh-verifies at q8 using real
SHA/Keccak/signer runner tapes. Its dedicated witness builds arithmetic only:
no native columns, per-leaf memory Merkle plan, or custody hash columns. The
program family12 bridge separately passed a three-caller q8 quotient/ROM
closure gate (3/3). Joint fresh family11/family12/complete-ROM verification
also passed (6/6), including changed count and swapped execution negatives.
The joint fresh family11/family13 memory bridge passed (4/4), count103, with
substituted caller-root rejection and exact consume clocks. The bounded
precompile producer/receiver passed roots-only census, witness replay, changed
key/claim rejection and fresh verification at q8. These sparse rosters use the actual execution ordinal,
and complete policy requires all three caller families to have equal counts.
Final-memory endpoint bytes (including clocks) must be committed before B5SS
challenges through `rw_endpoint_plan_digest`; complete policy requires this
digest and an independently expected final sparse state root. Existing sparse
root semantics include input words and are preserved.
Two differently sized sorted-memory instances and their same-root endpoint
proofs passed fresh verification (4/4), including cross-instance predecessor,
global last endpoint, untouched-word retention and independently pinned final
full-image root. A wrong endpoint clock was re-pinned, re-sealed, re-proved and
rejected by the final endpoint relation. This public endpoint receiver is
linear in touched words; a succinct final-root AIR is a separate requirement
for an eventual standalone succinct block verifier.

The actual native-v5 recursive verifier passed its focused ReleaseFast gate
(7/7): one freshly verified parent proof, 51,865 fixed rows, 128,024 proof
bytes, native verifier equation, linear B5SS transcript v2, and algebraic
exported-open-claim binding. A changed exported claim rejects even after its
capture mutation seal is recomputed. This first circuit still specializes
changing instance data into its key; reusable recursive setup requires moving
the full tuple (seal, instance IDs, roots, public endpoints and claims) into a
constrained public-input binding. It is not yet a complete block proof.

The reusable recursive public bus subsequently passed two real native states
and two fresh recursive proofs with the same geometry key and setup (7/7,
q8/PoW0). The constrained tuple has 45 public wires, 51,644 fixed rows, and
129,580/127,054 proof bytes. Changing seals, main roots, public values and open
claims no longer specializes the recursive key. Lightweight native-v3 removes
the old per-leaf commitment Plan entirely; its actual proof and reusable
recursive receiver gate passed (8/8, q8; 128,792/126,041 parent proof bytes).
Its open claim compensates PC/clock state only. A complete receiver must bind
register first/final values and exact clocks with global memory providers;
intermediate PC/clock spans cannot attest intermediate register snapshots.

The v5-only compact memory layout passed fresh sorted, range, initial-source
and final-endpoint verification (4/4, q8). Reusing 17 ordering predecessor
fields reduces main columns from 83 to 66, saving 20.5% of main cells without
dropping clock/value constraints or changing v2 proofs. This is a committed
cell saving, not a measured timing or process-memory improvement. A separate
packed36 layout and range16 provider subsequently passed fresh q8 proof gates:
two independently sized instances, separate log16 range AIR, exact 64-bit
clocks including bit48, global register endpoints and complete final sparse
RW image. A re-pinned/re-sealed bit32 register-clock change was rejected after
fresh proof regeneration. Compared with the old 83-column layout this removes
47 main columns (56.6%); the new interaction geometry changes too, so this is
not a peak-memory or timing measurement.

The packed same-root execution adapters passed 8/8 ReleaseFast checks: a real
native-v3 ADDI leaf and separately fresh family11 SHA/Keccak caller proof with
103 accesses. Their packed transition claims equal the byte-to-word oracle;
their opposite universal claims cancel the corresponding native/caller
tuples. Byte requests retain their existing universal range8 AIR and must
join independently field-safe family14 provider groups. Sorted memory's
range16 proof is separate. The old-v2 q70/PoW26 memory regression also passed
(3/3). These are individual and joint family gates, not a complete block proof.

The native/program shared first round passed 12/12 q8 checks: the request
proof leases immutable fixed/main trees, consumes its own proof storage, and
the surviving native proof then fresh-verifies. Both protocols retain the
original native roots. Request quotient extension reconstructs coefficients
from the selected LDE columns when native retention is disabled; it does not
rebuild native commitments.

All six standalone native lookup provider AIRs passed q8 fresh verification,
including positive and negative multiplicities, canonical bounded artifact
decoding, independent group identity, changed-counter rejection and exact
host denominator oracles. Groups partition execution indices contiguously,
with independent shape-derived absolute request bounds below M31. The
receiver delivers each group separately rather than treating one block-wide
scalar as closure. A same-native-root table-only consumer projection is still
required before these open provider receipts can close. Fixed table basis
reuse across groups passed its focused recheck: identical fixed roots and
shared storage survive independently committed main trees and proof release.

Complete B5SS policy now also requires an independently admitted
`register_endpoint_plan_digest`; it commits global register endpoints and
exact clocks before challenges. A complete block proof has not been produced.

## Measured starting point

The exact mainnet replay has 139,214,856 VM cycles, 356,303,914 memory
events, and 218 nonempty execution leaves. Its exact dyadic forest needs 213
parent proofs and five roots; no padding proofs are present. A measured q70
parent fold took 41.7 seconds on this CPU, so 213 **sequential** folds alone
extrapolate to about 2.47 hours. The existing default sorted-memory capacity
is 2^20 events, implying at least 340 separately proved memory instances for
this replay. These are estimates from one fold and a row count, not measured
mainnet proof timings.

The completed old-path candidate roster took 4,592.79 s, peaked at
10,212,395,984 tracked bytes / 10,053,238,784 process bytes, and published
manifest SHA-256 `a8ba6144b6897afa1724e611af7c1ccd7c133ce24fe067855d819794bb1fb749`.
All 218 native key IDs are distinct; caching the existing key identity has
zero cross-leaf hits on this block. The roster is proposal-only and made no
proof or geometry authority claim.

One real log20 memory instance has separately passed q70/PoW26 at 22.645 s
and 6.46 GB tracked peak (see the delivery README). A log22 cap would reduce
the mathematical instance count to 85, but its peak cannot be inferred safely
by multiplying log20 memory by four: PCS and trace lifetimes must be measured
under the intended host cap. The current 2^20 count has no smaller-tail
variant for this particular event count.

The current sorted-memory AIR commits 22 fixed, 83 main, and 84 interaction
columns per row: 189 base-field columns before quotient, LDE, and Merkle
storage. The 84 interaction columns include 72 for 35 paired byte-range
requests. This width explains why increasing row height can trade proof count
for a sharp live-memory increase. A larger-instance benchmark must measure
both the roots-only first pass and the retained-coefficient proving pass;
choosing log22 solely from the 85-instance count would be unjustified.

## Port the architecture, not the proof format

ZisK v1.3.0-alpha has an instance planner that minimizes instance count first
and memory second (`common/src/component/air_selection.rs`), lane-packed main
and memory AIRs, separately planned memory, and proof scheduling that overlaps
recursion with basic proofs. Its proving key is setup-level rather than a key
derived afresh from every block leaf. We retain our Stwo/M31/BLAKE3 proof
format and security parameters; foreign proofs or setup bytes do not become
authority by entering a manifest.

1. **Versioned reusable native template.** Current `B3SK/B3CK` IDs include
   plan-specific public state and a Tree0 root whose rows contain ROM
   multiplicities, memory boundary schedules, and paired Merkle topology. A
   cache keyed by the current ID is safe but will rarely hit across blocks.
   The new protocol must move mutable custody rows from fixed Tree0 into
   constrained dynamic commitments or an independently verified global bus.
   Its template ID binds semantics, PCS security, exact column geometry, and
   only truly invariant fixed columns. Every instance still binds its full
   plan, public I/O, roots, counters, and source seal into the transcript.
   This is a new key/proof version; old proofs cannot be reinterpreted.
   The existing typed execution sidecar already extracts memory transitions
   from the same committed opcode rows and the block sorted-memory AIR closes
   those transitions. This is the bridge for removing per-leaf RW Merkle
   custody. Program fetches still need a separately proved, block-global ROM
   table tied to the ELF/program root; a program-root descriptor alone is not
   such a proof. The new receiver must accept the global closures before it
   treats a lightweight native leaf as complete.
2. **Separate memory, size each family.** Execution, sorted memory, range
   tables, and hash/precompile work keep independent row budgets. A planner
   chooses the largest memory-safe AIR variant to reduce proof count, then
   minimizes committed area at the same count. It must budget peak witness,
   coefficients, LDE, and Merkle storage, not just trace rows. The complete
   memory permutation and initial/final state closures remain mandatory.
3. **Pipeline and parallelize the exact forest.** Publish a core leaf only
   after fresh verification against independent pins. Give every parent its
   canonical span, dependencies, proof index, and artifact name. A bounded
   ready queue may prove independent parents in parallel and overlap them
   with later base proofs. Completion order must not change manifest order or
   transcript authority. Enforce a shared host-memory budget and release each
   parent transport after its hash-pinned file is durable.
   The producer can also overlap independently sealed memory/table proofs
   with execution proofs under one shared host budget; this schedule requires
   the small real-I/O fixture to pass before it is enabled by the CLI.
4. **Reduce recursive work per leaf.** The 213-parent binary forest is a major
   latency cost even with parallelism. Measure the recursive verifier's row
   inventory and then batch multiple adjacent, verified children into one
   capacity-bounded aggregate with a versioned statement. A batch must prove
   each child verifier equation and exact span continuity; a hash-only digest
   of proof files is not recursive verification. Benchmark fan-in against
   q70/PoW26 security and actual peak memory before adopting it.
5. **Streaming precompile buses.** SHA-256, Keccak, and elliptic-curve hints
   can be computed outside the VM and proved by dedicated AIRs, with ordered
   calls linked to execution. Existing guest precompiles are retained as the
   semantic baseline. The bridge must reject missing, duplicated, reordered,
   or changed calls, and the proof statement must bind exact counts.

## Qualification gates

First prove template-key reuse for two different block states, and reject a
swapped state, program, count, and missing closure. Next demonstrate identical
statement and proof acceptance between serial and parallel scheduling on a
small fixture, plus deterministic 218-leaf task planning without a full proof.
Then measure per-family proof count, host RSS, and timings at q70/PoW26.
Finally produce and freshly verify a complete, independently pinned mainnet
bundle. The CPU result is the baseline for later multi-GPU work; the quoted
ZisK 4×/8×5090 numbers are not CPU or security-matched comparisons.

Source references: [ZisK v1.3.0-alpha release](https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha),
[ZisK AIR selection](https://github.com/0xPolygonHermez/zisk/blob/v1.3.0-alpha/common/src/component/air_selection.rs),
[ZisK main planner](https://github.com/0xPolygonHermez/zisk/blob/v1.3.0-alpha/state-machines/main/src/main_planner.rs),
and [ZisK memory planner](https://github.com/0xPolygonHermez/zisk/blob/v1.3.0-alpha/state-machines/mem/src/mem_planner.rs).

## Fresh global join qualification (2026-09-26)

The packed-memory join qualified with real native-v3 execution, a sorted36
proof, range16, complete initial/final RW sources, and global register
endpoints. A separately pinned and re-sealed high clock bit mutation is
rejected at the actual packed transition closure, even though its individual
proof families freshly verify. The canonical native-v3 producer now selects
this packed36/range16 family rather than the historical byte-memory producer.

The independent B5PS caller state quotient also qualified for real SHA-256,
Keccak and signer recovery. It leases the existing family11 fixed/main
commitments, draws the common universal relations followed by its own linear
transcript domain, and matches the PC/clock retirement sums calculated from
runner call records. Changed claims and root bindings fail. The old program
quotient shares the implementation through an explicit mode while retaining
its existing protocol; a program proof is not a state proof.

`block_v5_global_receiver_v1` reconstructs complete source/endpoint pins and
streams fresh base proofs through both private joins in one program receive
loop. It checks individual PC spans, six-table groups, packed transitions,
register endpoints and final accounting. `verifyGlobals` leaves exact
recursive compression pending. `verifyComplete` rebuilds every native verifier
policy from independent pins and the base receipts freshly created inside the
same call, then verifies the exact recursive forest. The genuine ordinary
fixture passed both receive modes: one ADDI execution, ROM, a grouped
six-table provider, two packed memory events, 28 byte requests, full RW/register
endpoints, a reusable native recursive leaf and a genuine one-child exact outer.
Wrong seal and provider demand are rejected. This is a complete proof bundle
for that ordinary fixture, with separately verified global proofs; it is not a
single compressed Ethereum proof. The subsequent frozen-tree gate also passed
the actual complete detached-file path through the same private fresh receive
loop, plus early wrong leaf/parent/outer security, child-verifier security and
key rejection before any base proofs are consumed. `writeWire` and
`verifyDetachedPinned` are exercised by this path, including independent outer
file pins.

The independent five-native-leaf recursive gate also passed a genuine quartet
and an exact outer over the 4+1 roots without padding. The quartet has
2,821,160 fixed rows, 495 public wires and a 151,500-byte proof; the outer has
1,471,279 fixed rows, 1,140 public wires and a 141,474-byte proof. These are
artifact/row inventories, not block proving latency or peak-memory measurements.
The genuine detached five-leaf ready-queue stage qualified file publication,
manifest reception, independent policy and transport tamper rejection. Its
accounted stage-owned peak was 3,182,242,484 bytes under a 12 GiB allocator cap.
This excludes borrowed native policies, initial fixture setup and the receiver;
it is not whole-block RSS, and the one ready quartet does not qualify concurrent
parent overlap.

Caller six-table projections and the bounded production warm-hook pipeline
qualified for real SHA/Keccak (103 accesses) and signer/Keccak (94 accesses),
including two witness loads per instance, immutable same-root leases and
independent shipped counter checks. The authoritative SHA admission undercount
is fixed. Native and caller producers now expose explicit warm first-round and
borrowed-proof callbacks, keeping side stages within one execution lifetime.
Their staged proofs remain provisional until the complete receiver closes all
families. The native warm lookup and recursive-leaf stage also qualified: one original
native proof supplies both stages, the recursive leaf survives file publication
and fresh reopening, and profile mismatch rejects before the clone. No borrowed
trace or verifier capture escapes the callback; strict allocator teardown passes.

The real 103-access sorted-memory and range proofs now pass. The new packed
interaction generator let Zig infer an 11-bit batch count, so 256 × 33 wrapped
to 256 and left most inverses unwritten. Explicit `usize` sizes and checked
multiplication fix this; proof equations and field arithmetic are unchanged.
The older memory path already uses a typed size and needed no mutation. Packed
inverse regressions at 8,448 terms also pass under ReleaseFast/native.

The complete caller-only gate now passes with a genuine versioned physical
frame for the zero-opcode native roster. Two SHA calls and one Keccak call
close 103 memory events, 1,442 byte requests, four ROM fetches including the
terminal fetch, all six lookup tables and PC/clock state, followed by fresh
verification of a genuine native recursive leaf and one-child exact outer.
The combined gate passed 13/13 with clean allocator teardown. SHA, Keccak and
signer AIRs all emit byte addresses on the universal memory bus; the shared
bridges previously used word indices. Authentic-event regressions qualify all
three corrections and prove that sorted transitions are preserved. No closure
equation has been relaxed. See `block-v5-complete-caller-q8.json` for the exact
workload, command and exclusions. End-to-end block production wiring remains
pending. Neither a complete Ethereum block nor canonical q70/PoW26 performance
is qualified by these diagnostic q8/PoW0 gates.

The warm program-extension stage qualified together with the caller lookup
and state stages: both real SHA/Keccak and signer/Keccak fixtures reuse the
original fixed/main commitments, freshly verify family11 and family12, and
reject changed claims, swapped roots and changed record keys. The focused
gate passed 10/10 with clean allocator teardown; see
`block-v5-warm-program-extension-q8.json`. The bounded native recursive cache
also qualified two real instances with one cold setup and one cache hit,
including fresh verification of both leaves after public admission changed;
see `block-v5-native-recursive-stage-cache-q8.json`.

The separate canonical ordinary detached gate also passed at 70 FRI queries
and 26 PoW bits. It exercises the same real ordinary bundle, fresh global
closures and genuine recursive leaf/outer under matching security configs.
The recorded 4-minute/6G build observation includes compilation and is not a
proving benchmark. Complete caller and Ethereum block measurements remain
pending; see `block-v5-complete-ordinary-q70.json`.
