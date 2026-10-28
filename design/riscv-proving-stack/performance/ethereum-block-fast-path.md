# Ethereum block fast path: work reduction before acceleration

Status: architecture decision and falsifiable experiments. No full Ethereum
block-to-root proof or end-to-end speedup is established by this document.

## Why the present path is slow

The stopped block 24,628,607 run had 139,214,856 guest cycles and 67 execution
segments. Its first collection/sort/commit/admission pass took 1,650.976 s.
The recorded sorted-memory census was 356,303,914 events, of which 298,427,187
(83.76%) were registers. The pass planned 85 memory instances and admitted 622
base proof files. Nine segment sidecars took roughly 80 s each; their recursive
leaf stages took 17.6–22.4 s. The run stopped before a complete root, so none
of these observations is an end-to-end block proving measurement. Source:
`autoresearch/notes/2026-09-24-ethereum-block-delivery/block-v5-performance-roadmap-v1.md`.
The retained measurement also says its producer policy does not independently
admit an Ethereum block or external public-state policy. A production benchmark
must pin those inputs outside the prover-generated bundle.

This is a work-amplification problem. A faster hash kernel alone cannot remove
hundreds of millions of generic memory events or hundreds of proof instances.
The q193 test's 55,781 Poseidon calls describe one small recursive wrapper;
they do not describe the block's base-memory workload. In the stopped block,
the measured sidecar stage was several times the measured leaf stage.

The first-pass timer is also broader than its old name suggests. In the
archived driver it starts before pool creation and stops after source
collection, global first commitments, roster assembly, proof-store setup,
recursive key preparation and forest startup. The retained block log reports
42.238 s of bare guest preflight versus 1,650.976 s for that first-pass timer.
Those two values measure different work, but the 39.1x ratio rules out guest
execution alone as an explanation. The original run did not publish finer
first-pass times. The lab branch now has opt-in phase counters at the driver,
collector and global-source boundaries (`STWO_BLOCK_V5_COLLECT_PROFILE=1`).

### What the first pass actually scales with

The new focused first-pass experiment uses a real release-ABI ELF with one
SHA/Keccak/SHA caller sequence and a finite loop of real stores to the same
writable word. It covers the complete `Collect.collect` pass, including source
replay, native and sidecar first commitments, lookup-group completion, sorted
replay, global first commitments and binding. Three sequential runs of each
size passed the source and collection assertions at ReleaseFast on the M5.
These are **diagnostic q8/PoW0 collection runs**, not base or recursive STARK
proofs, and they exclude preflight, driver assembly and the later proof pass.
The stored inputs and order-specific stage counters are in
`block-collection-phase-sweep-20261028.json`; the instrumented fixture is at
lab commit `6f5fe61dc`.

| Stores | Guest cycles | Segments | Collected events | Collector phase sum | Ordinary sidecar | Native first roots | Sort finish |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 16,384 | 49,165 | 25 | 16,485 | 1.147 s | 0.221 s | 0.143 s | 0.001 s |
| 65,536 | 196,621 | 97 | 65,637 | 2.583 s | 0.853 s | 0.553 s | 0.003 s |
| 262,144 | 786,445 | 385 | 262,245 | 8.230 s | 3.390 s | 2.162 s | 0.018 s |

The phase sum adds medians of individually rounded millisecond counters, so
it is an approximate collector total. At 262k stores, ordinary sidecar
construction and native first roots account for about 67% of this sum. The
sort finish accounts for about 0.2%. The ordinary and native costs rise almost
fourfold at each fourfold workload increase. Fixed caller collection and
lookup-group completion stay near 0.33 s and 0.28 s across all three sizes.
This is evidence that **column construction and commitment**, not sorting,
dominate this store-heavy first-pass fixture. The target block has different
operations, segment size, and five external merge passes; do not project its
sort time or end-to-end speedup from these small runs.

An instrumented 262k-store follow-up at lab commit `f75b58a77` split the
ordinary sidecar's 2.866 s collection time into 1.086 s of commitment,
0.876 s of byte counters, 0.302 s of trace initialization and 0.252 s of
census scanning. Its changed loop shape has 513 segments, so its total is
not directly comparable with the earlier 385-segment sweep. These are
single-run diagnostic counters, retained in
`block-ordinary-subphase-20261028.json`, not medians; their unlisted remainder
includes cleanup and other work. Commitment is the largest substage, but
removing it alone cannot deliver a tenfold first-pass improvement. The trace
and repeated scans are also meaningful costs.

There is a further structural duplication: `block_v5_native_memory_stage_v1`
builds sidecar traces, scans them for byte counters, scans again for census,
and commits the sidecar witness during collection. Its warm proof path later
rebuilds the same traces and counters and recommits the same witness before
proving it. `block_v5_cpu_native_root_proposal_v1` likewise commits and drops
the native PCS state in collection. This is why a block-first protocol must
make first commitments reusable or make the late cross-table relation narrow
enough that only its event columns need a second pass. Retaining every full
trace at once would violate the memory budget; the chosen ownership and
challenge schedule need to be redesigned together.

### Address cardinality is a second memory axis

The sibling encoding research at
[`stwo-proximity-autoresearch-challenge` revision `9ff52f3`](https://github.com/teddyjfpender/stwo-proximity-autoresearch-challenge/tree/9ff52f3/research/encodings)
adds an important missing dimension to this model. In its diagnostic VM sweep,
same-address memory loops used 376.5 marginal cells per load/store, while
distinct-address loops used about 40,392, with BLAKE3 state commitments
accounting for 23.717 million of 26.675 million cells in the 256-address case.
Those are **different experimental q8/no-PoW proof layouts**, so their absolute
slopes must not be multiplied by the block event count. They establish a
strong hypothesis: first-touch cardinality and authenticated state paths can
dominate even after per-access RAM rows are narrowed. The retained block census
has 3,142,932 first-touch keys and 666,708 initially nonzero RW words. Its
57,876,727 writable-RAM events represent about 18.415 events per recorded
first-touch key; the key census may include register keys, so this is not an
exact mode1 RW-only average.

To isolate that axis, the lab fixture changes one loop instruction from NOP
to `ADDI x2,x2,4` and holds store count, guest cycles, segments and sorted
events fixed within each pair. Three alternating runs per arm at each size
passed collection assertions at lab commit `f75b58a77`; raw stage counters,
source hashes and the exact command are in
`block-address-cardinality-collection-20261028.json`.

| Stores | First touches, same/distinct | Ordinary sidecar, same/distinct | Native first roots, same/distinct | Global first roots, same/distinct |
| ---: | ---: | ---: | ---: | ---: |
| 4,096 | 53 / 4,097 | 49 / 49 ms | 46 / 46 ms | 18 / 19 ms |
| 16,384 | 53 / 16,385 | 184 / 183 ms | 165 / 166 ms | 46 / 51 ms |

The *first-pass collection* of this archived profile shows no large
distinct-address penalty at these sizes, apart from 5 ms in global first roots
at 16k stores. The later source/provider STARKs are unmeasured, so this result
does not refute the encoding challenge's large distinct-address proof cost.
Next compare complete q70/26 proofs and all first/last-state proof families
on matched same/distinct streams, including committed BLAKE3 rows and peak
memory. The matched fixture also prevents attributing a cycle-count difference
to address cardinality.

The encoding work also cautions against using cells as a time proxy. Its
producer/consumer wire-bound designs cut native BLAKE3 compression cells and
passed local proof/negative controls; the 1,024-compression producer-wire
variant reduced internal proving time from 326.700 to 275.678 ms. A different
batch-four lookup layout saved cells but raised the small-sort median from
136.752 to 234.749 ms because of composition geometry. Its ALU pairing cut
large-case cells by about 11% while full proving time stayed effectively flat.
These are valuable bounded component ideas for BLAKE3 and range providers,
but the block profile must retain canonical security and independently verify
full proofs before importing a candidate. The larger architectural target is
shared authenticated paths and batched state updates across first-touch keys,
combined with fewer per-access rows and no repeated wide commitments.

### Reproducible geometry experiment

Run `python3 design/riscv-proving-stack/performance/block-work-model.py`. The
model fixes the measured event census and compares three *protocol widths* at
row log 22, counting full padded commitment domains. The old memory AIR has
22 fixed + 36 main + 84 interaction cells/event. The archived word-v4 profile
has 12 + 27 + 68 cells/event. The archived RAM2 profile has 24 + 54 + 92
cells/two-event row. The latter two include the proposed mode1 projection,
which sends only writable RAM to sorted memory and closes register custody in
execution windows. The mode1 + word-v4 case is a **counterfactual comparator**:
the archived complete receiver admits mode1 with RAM2, not word-v4. Neither
layout was measured on the complete block.

| Geometry | Instances | Committed M31 cells | Raw trace bytes | Cell reduction |
| --- | ---: | ---: | ---: | ---: |
| Recorded all-memory layout | 85 | 50.625 billion | 188.59 GiB | 1.00x |
| Mode1 + word-v4, projected | 14 | 6.283 billion | 23.41 GiB | 8.06x |
| Mode1 + RAM2, projected | 7 | 4.991 billion | 18.59 GiB | 10.14x |

Raw trace bytes sum all committed domains; they are **not concurrent peak RAM**.
PCS expansion, quotient scratch, FRI and proof serialization add work. The
model demonstrates the size of the avoidable base-field workload, not runtime.
It also shows the limit of width tuning: after mode1 and RAM2, roughly five
billion committed cells remain. Further large gains require reducing *work
per mutable RAM event*, avoiding duplicated range requests, and reducing
fixed proof overhead. The existing archive's mode1 and RAM2 source gates do
not substitute for fresh full-security STARK proofs.

A fresh ReleaseFast M5 run of the archived, source-hash-pinned 32,768-event
RAM kernel comparison passed exact bus/counter parity. Median interaction
generation was 32.327 ms for word-v4 versus 22.004 ms for RAM2 (1.469x);
trace and interaction arrays were 14,024,704 versus 11,141,120 bytes (20.6%
less). This benchmark excludes commitment, FRI, recursion, guest execution,
shared inverse-table setup and whole-process peak. The archived prior run
measured 32.327 versus 21.500 ms, showing similar kernel behavior, but neither
run proves an end-to-end gain. See `block-ram2-m5-20261028.json` for the fresh
samples and scope.

The follow-up *full RAM component STARK* comparison changes the conclusion
from the kernel-only benchmark. The CPU prover used one eight-worker pool,
70 FRI queries, 26 PoW bits, ReleaseFast, the same synthetic sorted writable-
RAM events and fresh verification of each component proof. Each row below is
first commitment + shared inverse-table preparation + proof generation; it
excludes verification, event generation and other block proof families. Four
alternating-order pairs produced each median except the 4M row, which is one
pair. The archived proof source plus a corrected single-wait worker scheduler
is pinned at lab commit `99975023b`; raw paired totals are in
`block-ram-proof-size-sweep-20261028.json`.

| RW events in one component | Word-v4 | RAM2 | Word/RAM2 |
| --- | ---: | ---: | ---: |
| 32,768 | 0.611 s | 0.637 s | 0.96x |
| 65,536 | 0.372 s | 0.308 s | 1.21x |
| 262,144 | 2.004 s | 1.237 s | 1.62x |
| 1,048,576 | 4.701 s | 4.072 s | 1.15x |
| 4,194,304 | 19.591 s | 16.288 s | 1.20x |

This falsifies the assumption that a 10.14x reduction in *block aggregate
memory cells* makes this one component's proof 10x faster. Register event
removal accounts for most of the aggregate reduction; RAM2 alone provides a
size-dependent 0.96–1.62x component time ratio in this experiment. Small
instances favor word-v4, and the measured crossover lies between 32k and 64k
events on this host. A production planner should select a protocol by measured
whole-proof cost, peak and proof count for its hardware, with the protocol tag
bound in the independently derived roster. It must not silently switch layout
for the same committed claim. For the target block's seven large RW shards,
RAM2 remains the measured choice. A future small-instance word-v4 exception
requires a new versioned global policy and complete requalification; the
component-only benchmark does not authorize it.

The repeated large test originally stalled after two pairs. Sampling showed
the main thread blocked in the word quotient worker join while all helpers
were idle. That path called Zig `WaitGroup.wait()` explicitly and again in a
defer; the second wait can fabricate a pending count. Commit `99975023b`
guards the cleanup wait so it runs only if the explicit join did not occur.
The four-pair million-event canonical run then completed and verified every
proof. A long-lived block prover needs this lifecycle fix before parallel
quotient timing is trustworthy.

The row-cap sensitivity check is informative. For the RAM2 census, row logs
20, 21 and 22 commit the same 4.991 billion cells in 28, 14 and 7 instances.
Row logs 23 and 24 commit 5.704 billion cells in 4 and 2 instances because
of padding: **14.3% more cells for fewer proofs**. At this count, log22 is the
first capacity that minimizes proof count without increasing committed area;
raising the row cap blindly worsens the base-field workload and likely raises
per-instance peak. This is geometry evidence, not a measured time optimum.

## Chosen block-specific protocol

Use a versioned Ethereum-block profile with fixed security parameters and
independent public-state pins. Do not retain a generic all-access memory AIR
on this profile merely for code sharing.

1. **Execution-local registers.** Prove register reads, writes, predecessor
   clocks, x0 semantics and boundary values in typed native/caller AIRs. Close
   every ordered execution window with a shared random relation and exact
   counts. The global sorter sees only writable RAM. The archive contains a
   mode1 source path; qualify and measure that path before redesigning it.
2. **Block-global RAM.** Sort writable RAM accesses once for the whole block.
   Prove strict address/clock order, read-after-write continuity, first-touch
   values, last values, and exact permutation against the execution/caller
   requester tuples. Keep input and ROM in separate authenticated read-only
   families. Lane packing is selected by **total committed cells and owned
   scratch**, not by instance count alone. Narrow the predecessor and range
   witness before raising row caps. Keep RAM2 for the target block's large
   shards; any small-instance alternative requires a separately versioned
   global receiver and complete proof qualification.
3. **Ethereum-heavy operations.** Route Keccak, SHA-256 and elliptic-curve
   calls to dedicated typed AIRs with exact ordered call/return buses. Host
   precomputation may produce witnesses but never grants arithmetic authority.
   Derive every public state root from proved trie/hash transitions tied to
   the block's independently expected parent and output roots.
4. **One block dependency graph with no full replay tax.** Each execution
   shard proves its native transition and exact, narrow projections of every
   external bus: writable-memory events, ROM/input reads and precompile calls.
   Publish their commitment roots with the native proof so native proving can
   finish while later segments execute. The block relation proof opens those
   *same committed event columns* under block-wide challenges derived only
   after the ordered source and provider roots are sealed. Recompute or
   retain only the narrow event projection, not the wide native and sidecar
   commitments. Fuse sidecar row derivation, range counters and census into
   one construction pass. Sort RAM and seal ROM/precompile inputs concurrently
   where transcript dependencies permit. Reuse immutable fixed data, compiled
   kernels and capacity templates; reset request-specific witness and
   transcript state on every proof.
5. **Fewer proofs and fewer recursive verifiers.** Fuse compatible same-root
   projections while keeping distinct bus equations. Aggregate several
   already verified adjacent children per capacity-bounded recursive circuit;
   prove each child verifier equation and ordered state/clock span. Publish
   parents from a ready queue, with bounded memory and independent key/policy
   admission. A digest of child proof files cannot replace verification.
6. **Resident GPU proving.** Keep witness, interaction, quotient, LDE, Merkle
   and FRI buffers on device where capacity permits. Stream one bounded family
   at a time for near-capacity jobs. Batch BLAKE3 and field kernels, then
   schedule independent family proofs and forest nodes across GPUs. Use the
   CPU receiver as an independent proof verifier; preserve 70 queries and 26
   PoW bits for the canonical profile.

The existing archive already implements parts of items 1, 2, 4 and 5 as
source or focused tests. The performance ledger explicitly says the resulting
mode1/RAM2 complete-block proof, assembled forest and GPU throughput remain
unqualified. Reuse those sound pieces; do not count their projected gains as
achieved twice.

The old serial dependency is:

```text
guest preflight
  -> for every segment: replay -> native first roots -> sidecar first roots
  -> finish all lookup groups -> sort all memory -> global first roots
  -> assemble one roster and transcript seal
  -> replay staged native/sidecar columns -> prove base families
  -> recursive leaves and parent forest -> detached root verifier
```

The fast profile keeps the transcript barrier only where Fiat–Shamir requires
it. A single guest execution emits typed execution columns and a compact,
ordered event stream. Each segment can finish its native proof with a local
transcript as soon as its own roots are ready. The proof exports commitments
to all exact external-bus projections. RAM sorting and read-only/precompile source
sealing run concurrently. The ordered event roots and sorted-RAM root then
derive shared block challenges for *narrow relation proofs*. Those proofs
check event-column openings against exported roots and prove exact multiset
equality with the sorted RAM and other provider tables. A bounded spool or PCS lease
retains only event columns and their opening data; wide native commitments
are not regenerated after the block challenge. Ready recursive leaves and
parents enter a bounded dependency queue. This is a **new versioned proof
protocol and scheduler**, not a flag on the archived two-pass driver. The
first required prototype is an independently verified two-segment complete
bundle with every active external bus closed and malicious root, tuple, count
and order substitutions rejected. If the PCS cannot safely reuse an event root across
the two proof transcripts, the bridge must recommit the narrow event columns
and prove equality of both roots before this profile is admitted.

The closure conditions remain explicit. The native AIR constrains each
projection tuple from the executed instruction, its active selector and its
count; inactive rows cannot invent requests. Execution proves every emitted
writable-RAM tuple and its count; the sorted RAM AIR proves strict
address/clock order, read-after-write values, first-touch initial state and
last-value final state; the shared lookup challenge and roster bind their
multisets. Register reads and writes close within execution/caller windows,
with exact adjacent-window endpoints and x0 fixed to zero. ROM, input and
precompile calls have distinct authenticated buses. The final recursive proof
must verify every base family and the global cancellation, not only native
execution leaves. An independently supplied block policy must bind the ELF,
fork rules, parent state root and claimed output; a prover-generated policy
is insufficient for an Ethereum-block claim.

The experimental priority has changed accordingly. First restore and qualify
the existing register-local custody plus RAM2 *complete bundle* at canonical
security; its archived full-driver fixture currently stops at
`InvalidV5FullFusedTrees` after collection, so collector success cannot be
reported as a qualified proof. In parallel, remove the measured native and
sidecar reconstruction/recommitment tax through the versioned event bridge.
Then fuse proof families and schedule their GPU/recursive work. Replace the
external sorter only after a full-block phase trace shows its wall time and
memory traffic on the selected hardware. Smaller hash/lookup encodings from
the sibling research are secondary until these architecture changes have
measured full-root effects.

## Experiments that decide the architecture

| Experiment | Same-input comparison | Required evidence |
| --- | --- | --- |
| Register custody | Mode0 vs mode1, with the same block and q70/PoW26 | Fresh independent verification, exact register/RW census, changed-window and caller negatives, memory cells, per-family wall time and RSS/device peak. |
| RAM layout | Word-v4 vs RAM2 on the same authenticated RW stream | Full-security proof and verifier, padded cells, peak scratch, throughput, odd-tail and cross-instance negatives. Reject RAM2 if extra width/peak outweighs fewer events. |
| Address cardinality | Same-access-count streams with 1, 256, 4k and many distinct words | First-touch count, state-tree paths/hash rows, all source/provider proof times, full-block root equality, peak and exact mutated-initial/final-state rejection. This tests the encoding research's dominant distinct-address hypothesis in the block protocol. |
| Source pipeline | Existing 1,650.976 s pass vs streamed/staged pass | First-input-to-last-seal wall time and the new collector/driver phase counters on the same block. Split native commitment, ordinary witness/commitment, caller, lookup groups, sort, global first commitments and assembly. Record I/O wait and output-equivalent source seals. Distinguish actual latency cuts from work hidden before a timer. |
| Event commitment bridge | Wide native/sidecar replay vs completed segment proof plus a narrow late block relation | Two real adjacent segments, shared event roots, independently verified native and RAM proofs, exact tuple/count/order negatives, bytes and peak for retained opening data. A root digest alone is never accepted as a lookup proof. |
| Proof fusion | Current base roster vs fused same-root roster | Exact proof count, verification of every original bus, proof bytes, phase timings, hostile omission/substitution tests. |
| Recursive fan-in | Binary parents vs 2/4/8 child capacity cohorts | Child-verifier equations, span continuity, fixed-row inventory, proof time, key reuse, peak and depth on exact odd leaf counts. |
| Full block | Old profile vs selected fast path | Same ELF/input/expected roots, 70 queries/26 PoW, fresh detached verification, root proof, complete wall-clock and peak. Report stage and critical-path times and reject any result missing global family closure. |

The first-pass measurement alone exceeds a 60-second block target by 27.5x.
That makes its redesign mandatory for a one-minute target; a six-second target
would require 275x improvement or elimination of that serialized pass. These
are arithmetic ratios against one stopped CPU run, not forecasts. A claim of
an order-of-magnitude end-to-end gain must wait for a completed, independently
verified old/new block pair on stated hardware.
