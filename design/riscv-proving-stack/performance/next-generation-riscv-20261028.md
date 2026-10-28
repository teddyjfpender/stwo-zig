# RISC-V architecture: remove wrapper amplification and global register traffic

Status: a [direct-native batch experiment](direct-native-batch-m5-20261028.md)
now passes fresh proofs at q70/PoW26 and measures **17.0x faster recursion**
on two tiny adjacent native segments (three eight-worker M5 runs). This is
**not a measured block speedup or a complete replacement block protocol**.
The earlier canonical complete-bundle fixture still exports global obligations
from its forest; its detached receiver closes them with separate base proofs.

The earlier hash-work census implementation is pinned at lab commit
[`7f77b5e87`](https://github.com/teddyjfpender/stwo-zig/commit/7f77b5e87).
The archived block implementation and new experiment remain on
`codex/ethereum-block-fast-lab`. The linked direct-batch report pins its newer
implementation and measurement receipts separately.

## Two distinct order-of-magnitude opportunities

| Change | Evidence | What the ratio does and does not mean |
| --- | --- | --- |
| Directly aggregate native proofs; omit compulsory individual recursive wrappers | Three native verifier captures require 431,144 G rows. The current complete native forest requires 10,500,504 G rows across its verifier captures. | 24.35x recursive G-work amplification in this small fixture, before the replacement batch's public binding. Not a runtime result or a full-block projection. |
| Remove register events from global sorted RAM and use RAM2 for mutable words | Retained block: 298,427,187 of 356,303,914 events are registers. Mode1/RAM2 model: 50.625 billion to 4.991 billion committed memory cells, 85 to 7 instances. | 10.14x modeled memory commitment area. Local register constraints remain necessary; this is not a 10.14x reduction of all proving work. |

These attack different work. Do not multiply their ratios. A complete block
profile must also include source authentication, global buses, precompiles and
the final recursive closure. The native forest alone is insufficient.

The direct-native batch now demonstrates that wrapper verification can be
removed: 32.425 to 1.910 seconds for the focused recursive phase, with 37.88x
fewer G rows and 32.97x fewer AIR cells. The
[nine-segment follow-up](native-batch-scaling-m5-20261028.md) now verifies
heterogeneous batches of 1/3/4/8 children and an upper parent consuming 8+1.
Its canonical phase sum is 58.219 s; experimental wider FRI schedules reduce
that to 39.493 s. Global recursive closure remains open. These larger results
show why removing individual wrappers is necessary but insufficient.
The large-tree counterfactual limits an eight-child-only change to roughly
7.3x G-work reduction; cheaper upper proofs and memory redesign are still
needed. Do not transfer the tiny-fixture runtime ratio to Ethereum blocks.

The [same-execution tiling follow-up](native-tiling-m5-20261028.md) tests
formation of fewer native proofs before recursion. At 851,968 cycles,
one/three/nine native proofs all commit 45,580,288 native cells, but the
one-proof route reduces the measured phase sum from 196.377 to 15.927 s
and recursive cells by 11.05x versus nine. This still uses only ADDI/JAL and
leaves global obligations open. It establishes why native-cell minimization
alone is an inadequate sizing objective, not that the full block can fit a
larger monolithic segment. Native, memory and caller capacities must be
decoupled, and the total tree cost must determine the proof grouping.

## New measurement: where recursive hash work comes from

Reproduction, from the lab branch:

```sh
STWO_BLOCK_V5_PROVE_PROFILE=1 STWO_RISCV_HASH_WORK_CENSUS=1 \
  python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v5_cpu_profile_test_root.zig -OReleaseFast \
  --test-filter 'block-v5 CPU assembled mixed multi-segment complete bundle canonical' \
  > hash-work.log 2>&1
python3 design/riscv-proving-stack/performance/hash-work-model.py \
  hash-work.log --native-prefix 3
```

The M5 CPU run passed all 13 selected tests, including complete detached bundle
verification at 70 queries / 26 PoW bits. It reported collection 1.006 s,
base/leaf publication 30.342 s, forest 123.426 s, and detached verification
2.052 s. Local parent work can overlap base publication; these phase counters
are not additive independent jobs. Local and outer parent proof calls took
38.260 s and 44.018 s. This run instrumented work; it was not an A/B speed test.

`block-v5-hash-work-m5-20261028.json` retains all seven capture censuses, query
and leaf geometry, exact totals, model alternatives and the source-log SHA256.
`blake3_native_hash_layout.zig` invokes the opt-in census. The counter checks
its leaf/subtree/path sum against the actual planner's G allocation. The Python
model independently reproduces all seven baseline path totals, and rejects
changed totals and truncated captures.

| Capture | Transcript G | Leaf G | Subtree G | Upper-path G | Total G |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native segment 0 | 17,528 | 62,720 | 23,520 | 72,688 | 176,456 |
| Native segment 1 | 16,240 | 47,040 | 15,680 | 33,152 | 112,112 |
| Native segment 2 | 19,264 | 74,480 | 15,680 | 33,152 | 142,576 |
| First wrapped child | 47,040 | 580,160 | 141,120 | 1,606,528 | 2,374,848 |
| Second wrapped child | 47,040 | 580,160 | 141,120 | 1,606,528 | 2,374,848 |
| Local parent, verified by outer | 51,520 | 603,680 | 164,640 | 2,124,976 | 2,944,816 |
| Remaining wrapped child, verified by outer | 47,040 | 580,160 | 141,120 | 1,606,528 | 2,374,848 |

The labels follow this fixture's sequential capture order, not a general
inference from geometry. G rows are not complete AIR cells, memory peaks or
elapsed time. The preceding AIR census found over 92% of parent AIR cells in
hash-related cohorts, so these counts identify a consequential target.

For the 2,374,848-G wrapped-child verifier, upper paths are 67.65% of G work;
the transcript is 1.98%. Its four trace trees have depths 19 and widths
316, 669, 664 and 8 words. There are 18 FRI layers. Each Merkle node frame is
92 bytes and costs two BLAKE3 compressions (112 G rows). The existing two-level
frontier already shares the top path work; the census subtracts that saving.

## A. Fuse conversion and aggregation

Current small native forest:

```text
native proof 0 -> recursive wrapper 0 --+
                                      +-> local parent --+
native proof 1 -> recursive wrapper 1 --+                  +-> exact outer
native proof 2 -> recursive wrapper 2 --------------------+
```

Proposed first batch:

```text
admitted native proof 0 --+
admitted native proof 1 --+-> one recursive native-batch proof
admitted native proof 2 --+   [ordered span + exact public claims + open buses]
```

This does not omit native proof verification: it places the existing native
verifier equations directly in the aggregate AIR. It omits proving each
verifier separately and subsequently verifying that newly created STARK.
For larger workloads, form bounded batches of raw base proofs first, then
reduce batch proofs. Small complete jobs need no extra identity wrapper just
to conform to a uniform leaf type.

The measured three native verifiers contribute 431,144 G rows. A direct batch
also needs its new public binding, roster and endpoint constraints, so that
number is a floor, not a completed batch census. The budget for a 10x G-work
reduction on this fixture is at most 1,050,050 rows in total: about 618,906
additional G rows remain available for binding. Require the actual combined
AIR census and a complete fresh proof, not a sum of individual receipts.

The current restriction is identifiable in code:

- `recursion/block_v5_open_child_frames_v2.zig:fromNative` takes a
  **recursive** key and schedule; it does not admit the original native STARK
  as an aggregate child.
- `recursion/block_v5_native_exact_leaf_adapter_v1.zig:verify` verifies the
  reusable recursive leaf before the forest can consume it.
- `recursion/block_v5_open_parent_preparation_v2.zig:prepare` accepts parent
  `Verified` captures. Its public policy admits 2/4-child local nodes and
  dyadic outer roots, so a three-native direct root needs a new policy.
- `recursion/blake3_execution_parent_preparation.zig:State.plan` already knows
  native-v3 verifier equations. Reuse those equations and their admission;
  do not normalize a host success receipt into an in-circuit proof.
- `recursion/block_v5_recursive_public_bus_v1.zig` owns the native public-wire
  supply. Namespace rebasing must move this schedule with the verifier rows.

Implementation boundary: introduce a versioned native-batch admission, public
bus, prepared-row owner and detached receiver. Feed each independently admitted
native capture through `State.plan`, allocate one bounded combined hash owner,
rebase all row and public-wire namespaces, and join the equations before one
commitment/proof. Pin the native template/profile, ordered roster, seal, exact
segment count and public statement digests. Prove continuity and preserve each
open relation's type, sign and multiplicity. An aggregate sum alone must not
replace the physical claims that each child's transcript absorbs.

Qualification gates: modified native proof; swapped/duplicated/omitted child;
wrong template or key; changed first/last PC, clock, register endpoints or
memory roots; altered per-batch claim; wrong seal; injected public-wire supply;
and cancellation between distinct bus families. Reject empty batches. A partial
last batch carries its actual count and cannot be silently padded with null
children. Independently verify both the aggregate and its claimed relation to
the same native public statements. Keep global closure explicit.

The tiny fixture exaggerates wrapper overhead relative to native execution.
Before extrapolating to a block, repeat the census on realistic native widths,
memory-heavy segments, caller-heavy segments, and at least two recursive batch
levels. Select batch size from actual row/domain and peak-memory bounds, not
from an arbitrary large fan-in. The existing four-child forest is not a
substitute: it still consumes separately created wrappers.

## B. Co-design recursion's PCS schedule and layout

The work model gives these alternatives for the same 2,327,808 path-G baseline.
They exclude changed transcript, arithmetic, routing and provider costs.

| Alternative | Modeled reduction in PCS G work |
| --- | ---: |
| FRI fold step 2, existing frontier/framing | 1.50x |
| FRI fold step 4, existing frontier/framing | 1.64x |
| Fold step 4 plus optimally sized fixed frontier | 1.88x |
| Above plus one-compression domain-separated node hashing | 2.57x |

Even ideal coordinate deduplication of the **current** openings improves total
G work only 1.36x on that capture. Deduplication by itself is not a 10x project.
The same calculation looks far better on tiny native trees, where 70 queries
repeat a domain of 8 or 16 positions. Do not use that small-tree benefit as a
block estimate.

Core FRI supports steps 1/2/4. A focused existing test passed actual PCS
verification, typed opening reconstruction and malformed-opening rejection
for all three. That is component coverage; the canonical RISC-V parent profile
explicitly pins step 1. Wider schedules require a new profile, transcript/key
identities, complete recursive proof tests and a security-bound review. Keeping
70 queries and 26 PoW bits is not itself a proof that every error term is equal.

The fixed-frontier alternative proves every query's bit-selected path into a
complete top subtree; its hash count is `q*(depth-k) + 2^k - 1`. Choose `k`
using both hash and selection-AIR cost. Witness-derived equality of coordinates
or digests must never determine which obligations disappear without a proved
route. The model counts hash work only and deliberately omits that routing cost.

One-compression node hashing is a separate cryptographic version, not deletion
of the current prefix. The standard [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs)
supports keyed hashing; a reviewed fixed domain-key construction for the
64-byte left/right payload could remove the extra compression. Preserve full
256-bit outputs, distinct leaf/node/transcript domains, flags, counters and
lengths. Prove/reference-test the new construction and regenerate all keys;
old roots must remain incompatible. This is an unqualified design option.

### Optimize the reduction tree, not each AIR in isolation

Four G cohorts reduce padding and the largest domain, but their separate
columns also widen leaves verified by the next parent. A layout planner must
price `base proving + next verifier + further tree levels`, subject to a peak
memory cap. Never undo partitioning solely because narrower leaves look cheap:
the larger domain can increase composition scratch and proving cost.

Across same-family work, distinguish vertical batching from horizontal fusion.
Vertically concatenating compatible traces increases height while retaining
approximately fixed width; putting different AIR columns side-by-side retains
the sum of their opening payloads. For the observed depth-19 proof geometry,
the model's eight-way vertical batch plus fold4/frontier changes reduces PCS G
work by 12.66x versus eight independent verifiers, before batch-binding work.
The depth-22 geometry would grow to depth 25 for that batch and may be
infeasible. These are shape counterfactuals, not an implemented joint PCS.

A vertically batched native AIR must prove boundary resets, active lengths,
segment identifiers, cross-segment continuity and exact event emission. Local
proof time, latency, memory and batching delay can all grow. Direct-native
aggregation and vertical native proving remove overlapping wrapper work;
their gains must be measured together, not multiplied.

If measured FRI and batching changes plateau, [WHIR](https://eprint.iacr.org/2024/1586)
is a separate research candidate because it targets query and verification
cost. Its published Reed–Solomon construction does not establish a compatible
Circle-STARK replacement, security level or speedup here. A circle-domain
reduction and in-circuit verifier are prerequisites, so it is behind the
changes above.

## C. Fix the block's memory and challenge architecture

Retain local register custody across every ordinary instruction and caller;
only mutable RAM enters sorted global consistency. ROM/input accesses use
their independently authenticated immutable providers. Mode1/RAM2 already
exists in the lab; the small positive complete bundle passes. Hostile endpoint
and public-source tests and a block-scale comparison remain required. The
10.14x model is reproduced by `block-work-model.py` in the main worktree; its
evidence is in `ethereum-block-fast-path.md`.

Next remove the collection/proving reconstruction cycle. A bounded execution
batch should produce one local proof and retain only narrow event commitments
and spool data. Seal all ordered event/provider roots before global challenges;
prove the late relation against exactly those committed event columns. The
same events must be constrained by both execution and global consistency.
Do not resample independent per-segment challenges and then add their sums.
Do not cache the whole block's wide trace to avoid reconstruction.

This changes the transcript protocol and needs its own binding proof. It is an
enabler for bounded streaming and overlap, not an independent 10x claim. The
existing sparse state fold already shares siblings; page authentication should
only replace it after measuring additional hash calls it can remove.

## Implementation and decision order

1. Preserve the implemented direct native batch, public bus and adversarial
   receiver tests. The two-segment baseline and nine-segment upper proof are
   measured; the latter still contains only 832 guest cycles.
2. Extend to realistic segment widths and global proof families. Batch sizes
   1/3/4/8 and an 8+1 upper root pass, but do not establish block-scale capacity
   or closure. Choose the frontier by complete tree cost and memory.
3. Qualify register-local/RAM2 with hostile tests and matched full base proofs;
   compare mode0/mode1 under identical guest, public roots and security policy.
4. Review security of the implemented experimental fold2/fold4 profiles before
   considering production adoption. Their measured gain is about 1.5x, not 10x.
   Fixed-frontier and node-domain redesign remain separate experiments.
5. Introduce the narrow event-root bridge and joint proof tiles only after their
   exact global challenge and ownership contracts are executable.
6. Recursively close every global proof family before publishing a standalone
   block root. GPU implementation follows the reduced proof work, rather than
   accelerating the existing amplification.

ZisK remains useful precedent, not a soundness oracle. Its
[recursion fix #618](https://github.com/0xPolygonHermez/pil2-proofman/pull/618)
reinforces an explicit negative test here: optional or empty child slots must
not allow an aggregate with no verified execution. Preserve mandatory child
presence and canonical absent-slot values in every batching experiment.
