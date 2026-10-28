# Block-v6: remove proof work, then accelerate what remains

Implementation update: the [direct-native batch experiment](direct-native-batch-m5-20261028.md)
now measures 17.0x faster recursion on a two-segment q70/PoW26 fixture.
Global closure and multi-level batch consumption remain open; the complete
block architecture below is not yet implemented.

Status: design and experiment contract, not a qualified proof protocol. The
archived block-v5 run stopped before a root. All speedups below are hypotheses
unless explicitly marked measured.

The follow-up [direct-native aggregation analysis](next-generation-riscv-20261028.md)
changes the first recursion experiment: eliminate compulsory individual wrappers
before tuning their verifier. A new canonical capture census attributes 431,144
G rows to the three native verifiers and 10,069,360 additional G rows to verifying
their wrappers and intermediate parent. This is a 24.35x work-amplification
finding on the small fixture, not a runtime or block-scale speedup. The report
also separates FRI schedule, path sharing and vertical batching counterfactuals.

## The workload that must change

The retained block 24,628,607 run had 139,214,856 guest cycles, 67 execution
segments, 356,303,914 memory events, 85 memory instances and 622 base proof
files. Its first collection/admission pass took 1,650.976 seconds. Registers
accounted for 298,427,187 (83.76%) of the events. These numbers are from
`autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-performance-roadmap-v1.md`;
the run did not finish, so they do not constitute a block-to-root baseline.
The separate bare guest preflight took 42.238 seconds on that host. Once proof
work is removed, that execution floor becomes important. A six-second
first-input-to-root target on the same CPU would also need faster guest
execution or safe overlap; moving execution before the measured clock would
change the product timing boundary, not reduce end-to-end work.

The block work model projects that existing register-local custody plus RAM2
would cut padded memory commitment area from 50.625 to 4.991 billion M31
cells and 85 to 7 memory proofs. This is a 10.14x *memory-area* reduction,
not a 10.14x proving-time result. The measured RAM2 component advantage on
large inputs was only 1.15–1.62x against word-v4. The missing gain is mainly
from eliminating register events, not packing RAM alone. See
`ethereum-block-fast-path.md` for source and component measurements.

The first complete small bundle exposed three protocol implementation defects
that are now fixed in the lab: a Keccak output opening used the component
domain instead of the shared composition domain, caller program/state
interaction columns were committed in a different order from the verifier,
and five-tree caller preflight used the larger fixed/main Merkle log as its
FRI degree bound. The q8 and canonical fixtures now publish real base files,
an exact forest and a fresh detached receiver result. This establishes a
usable small positive test for further architecture work, not block-scale
soundness or speed.

The measured forest covers native execution and exports open global
obligations. `block_v5_global_receiver_impl_v1.verifyWithTransportSelected`
first verifies the global base proofs, then checks that forest against the
fresh native residual. Thus complete-bundle verification is stronger than
native-only verification, but the outer forest file alone is not a closed
block proof. Block-v6 must recursively include global memory, caller, lookup,
source authentication and final relation closure before claiming a single
block root. The separate capacity completion path remains to be qualified.

## Four proof-architecture changes

### Measured recursion cost that sets the priority

The canonical three-segment fixture was profiled with fresh detached
verification again; all 13 selected tests passed. Its local two-child parent
spent 14.317 s preparing verifier rows, 3.057 s deriving its key, 4.790 s
constructing setup, 38.268 s proving and 0.195 s encoding/verifying. Its
two-child exact outer spent 14.728, 3.308, 5.184, 43.871 and 0.198 s in
the corresponding stages. Both were cache misses. Raw counters are in
`block-v5-parent-profile-m5-20261028.json`.

The producer already uses radix-four planning and authenticated setup caches.
On a miss, `blake3_parent_fixed_key_v1.derive` commits fixed columns and drops
the tree; `blake3_native_parent_producer.Plan.init` projects and commits them
again. An owned fixed-commitment handoff can remove that duplication, subject
to exact independent root admission and lifetime checks. It cannot supply the
main gain: preparation plus key/setup is about 35% of these parent jobs. Even
removing all of it bounds their summed elapsed-time improvement at roughly
1.56x. Actual STARK proving accounts for 82.139 s across the two jobs, so
reducing the verifier's proved work is essential. These are per-job sums;
local parent work overlaps base publication, and must not be added to the
122.962 s forest wall timer as separate work.

This prioritizes joint base proofs and specialized verifier operations over
further setup-cache tuning. The next comparison must count committed verifier
cells, hash calls, openings and quotient work for the same child statements,
then prove and independently verify the reduced circuit at q70/26.

The follow-up q70/26 census passed all 13 selected tests and complete detached
verification. `block-v5-parent-census-m5-20261028.json` records the 23 physical
AIR cohorts per parent; `parent-work-census.py` reproduces the grouping from
`STWO_BLOCK_V5_PROVE_PROFILE=1` logs. The local parent commits 1.178 billion AIR
cells and the exact outer 1.293 billion, excluding lookup provider tables,
composition and PCS expansion. G arithmetic accounts for 71.82%/73.97%, byte
routing 11.58%/10.54%, XOR 6.06%/5.51%, and hash boundary rows 2.85%/2.59%.
Padding accounts for 10.71%/9.32%. These are work counts, not peak RAM or
timing shares. The measured forest remained 123.354 s.

This narrows the specialization target to recursive BLAKE3 commitment and
transcript verification. A G row currently commits 16 fixed, 82 main and 80
interaction cells. Its ten generic wire events account for 20 interaction
cells: deleting just those events would save at most 11.2% of G-row area,
before replacing their linkage obligations. A full-compression AIR must
remove more routing/range overhead to justify itself. Likewise, perfect
padding elimination cannot produce an order-of-magnitude improvement.
The next experiment must inventory the hash calls by PCS leaf, authentication
path, FRI and transcript, then compare shared authenticated hash DAGs and joint
proof layouts on the identical child statements. Query deduplication must
prove equal query coordinates and exact hash inputs; host digest equality
cannot authorize reused nodes. The existing shared-root plan already removes
some repeated root work, so count only additional reductions.

### 1. Prove registers within execution; use sorted RAM only for mutable words

Complete and qualify mode1 with the already implemented RAM2 relation. Every
read must be linked to the preceding register write or the segment's admitted
incoming value. Every write must update the outgoing value. Adjacent execution
segments must share exact endpoint values and clocks. Caller-side register
accesses and x0 are in the same custody theorem. Only mutable RAM tuples enter
the global sorter. The two-segment detached receiver and adversarial endpoint,
count, tuple and x0 tests are the immediate admission gate. A full-security
block measurement is the performance gate.

This is the only candidate with a quantified order-of-magnitude reduction in
the block's committed memory area. Its end-to-end upside is bounded by the
fraction of time actually spent on that area, which the stopped block did not
measure.

### 2. Prove each execution segment once; bridge only its narrow event stream

The current collector commits wide native and sidecar traces and discards PCS
state. The proof pass rebuilds and recommits those traces. Replace this with a
versioned local theorem and a late block relation:

```text
segment i:  transition(state_i, state_i+1)
            exact ordered event columns E_i committed at event_root_i
            native/caller/sidecar constraints bind E_i to active instructions
block:      all admitted event_root_i and counts
            + sorted writable-RAM proof R
            + independent ROM/input/precompile providers
            -> multiset and boundary closure for every bus
root:       verifies every local theorem and every block relation theorem
```

The event commitment is a separate narrow PCS tree so its columns and Merkle
opening data can be retained or reconstructed from a bounded event spool. The
local proof commits that tree and constrains every emitted tuple; it can finish
before other segments. The block challenge is sampled only after the ordered
event roots and provider roots are sealed. A later relation proof opens the
*same event roots* under a domain-separated transcript and proves exact
multiset equality, including counts. Rebuilding the narrow event tree must
reproduce its root exactly; a host-supplied digest is not a proof. The root
receiver checks local proofs, relation proofs, ordering and boundary state.

Each local proof statement must include the block public-policy digest,
segment index, exact clock span, incoming/outgoing machine-state commitments,
event layout digest, event count and event root. The block seal absorbs these
statements in segment order before drawing global relation challenges. The
bounded spool may carry witness bytes and a transport hash, but the receiver
derives authority only from the admitted local STARK and the later opening of
its committed event root. Reusing a PCS root under two transcripts requires
explicit domain separation and an audit of the opening protocol's binding;
if that cannot be established, the bridge must use a second event commitment
and prove equality of the two vectors.

This protocol changes the Fiat–Shamir schedule, proof type and receiver. It
must be versioned, not activated by a performance flag. Its first experiment
is two real adjacent segments with a changed event value, dropped event,
reordered event, changed count and substituted event-root rejection. The
performance comparison measures first-input-to-final-proof wall time and peak
memory, including spool I/O. A fast collector alone is insufficient if the
new bridge adds more proof work than it removes.

### 3. Reduce proved state hashes, after measuring the existing batch fold

After register removal, the stopped block still contains 57,876,727 writable
RAM events and 3,142,932 recorded first-touch keys. The key count is not yet
an RW-only count. A high-cardinality diagnostic in the encoding research
showed BLAKE3 state commitments dominate a distinct-address fixture; the
absolute cost does not transfer to this block.

Block-v5 already has a bounded postorder sparse-tree fold in
`block_v5_memory_source_batch_fold_v1.zig`. It proves initial and final state
together and shares siblings. Calling for a generic "batched multiproof" would
repeat that work. First measure its actual branch/empty/compression census,
the BLAKE3 proof rows and the source page/fold time on 1, 256, 4k and
block-scale distinct-key streams at identical access counts.

If hash proving still dominates, the new design should reduce *proved hash
operations*: authenticate immutable page roots once, prove only changed-page
transitions, and reuse identical internal-node digests across the before and
after trees through a dedicated batched hash relation. Each reused digest
must be tied to its exact coordinate, height and children. The RAM proof
still produces exactly one first and one last value per distinct mutable key;
the state transition must bind a canonical, strictly ordered key list to
those endpoints and independently pinned initial/final roots. Omissions,
duplicate keys, changed children and path aliases must fail. This is a
conditional experiment; if the existing shared-sibling fold has already
removed nearly all duplicate work, prioritize the other changes instead.
An alternative memory argument is worth prototyping only after this cost is
isolated.

The [Twist/Shout paper](https://eprint.iacr.org/2025/105.pdf) is evidence that
different memory protocols can substantially change prover cost. Its
multilinear sum-check construction is not a drop-in replacement for Stwo's
circle-domain STARK; adapting it would require a new commitment, verifier and
recursion analysis. ZisK's [separate main, memory, ROM and input AIRs](https://github.com/0xPolygonHermez/zisk/blob/main/pil/zisk.pil)
support independent component sizing, but do not establish our speedup.

### 4. Replace hundreds of independently verified STARKs with joint proofs

The 622-file roster makes recursion verify many independent transcripts,
commitments, Merkle openings and FRI proofs. Group compatible components by
segment and transcript phase into one multi-component STARK. Keep separate
AIRs and independently sized domains inside the joint PCS, but share its
channel, quotient/FRI and opening paths where the Stwo protocol permits. A
segment joint proof should cover native execution and its same-root caller,
ordinary-memory and lookup projections. Block-global RAM, ROM and provider
proofs can form separate joint groups after all required roots are sealed.

Every old bus equation must remain in the joint AIR. A joint proof with one
omitted family must fail even if all its other components verify. The first
measure is actual roster and recursive-verifier work: proof count, verified
component count, opening hashes, verifier rows, leaf/forest wall time and
peak. A target of at most 150 base proof files for the 67-segment block is a
falsifiable engineering goal, not a forecast of runtime. Higher recursive
fan-in is useful only after this work reduction; it cannot erase child
verification cost by itself.

## Decision sequence and qualification

1. Make the current mode1/RAM2 bundle pass a fresh detached receiver at q8
   and canonical 70-query/26-PoW security, then run hostile probes. The small
   real-ELF q8 two-segment and canonical three-segment cases now pass complete
   detached verification. Their measured phases are retained in
   `block-v5-bundle-m5-20261028.json`. This clears the small positive gate,
   not the hostile or full-block qualification gate.
2. Run matched complete proof profiles with mode0 and mode1 on the same guest
   workload. Record family time, committed cells, proof count, wall time and
   process/device peak. No 10x time claim is permitted from the geometry model.
3. Prototype the event-root bridge with two segments. It must prove every
   tuple and preserve the same public statement. Measure wide witness
   construction/commitment eliminated against narrow bridge work added.
4. Profile the existing batched sparse fold on high-cardinality inputs. Only
   then prototype changed-page authentication or hash-relation deduplication;
   require exact root equality and adversarial key/path negatives.
5. Jointly prove one segment's compatible components and independently verify
   it, then scale the same proof grouping to the full block roster. Measure
   recursive verifier work rather than only the number of proof files.
6. Only after these changes, port the chosen proof families and joint PCS to
   resident CUDA and schedule independent segments/forest nodes across GPUs.

Guest execution and trace generation need their own stage profile in every
comparison. A native/JIT witness producer, per-segment streaming and bounded
lookahead can make the local-proof pipeline useful, but the AIR must still
derive execution validity from its committed columns. A witness supplied by
another process is not execution authority. Report both upstream preparation
and first-input-to-root latency so overlap is visible rather than hidden.

For a claimed 10x end-to-end gain, measure the same admitted block, security
configuration and independently expected state roots on both implementations.
Include guest execution, collection, all base proofs, recursion, detached
verification and peak memory. The first completed baseline and the first
completed block-v6 proof must both be retained; neither a projection nor a
partial root is enough.

The stop/go thresholds are intentionally stronger than a collection-only win:
the register/RAM change must preserve complete fresh verification while
cutting the measured memory-family wall time materially; the event bridge
must reduce wide trace construction/commitment work *net of* its relation
proof and spool cost; joint proving must reduce recursive verifier rows and
forest time as well as file count; state-hash changes must lower proved
compressions without increasing memory peak beyond the selected device.
If one experiment misses its own threshold, measure the remaining critical
path before combining it with the others. Cell reductions and isolated kernel
ratios do not multiply into an end-to-end speedup by themselves.
