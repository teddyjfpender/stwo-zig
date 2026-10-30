# Coefficient-backed input commitments

## Problem match and scope

Tiled RAM quotient evaluation reduces temporary expanded-domain storage, but
does not remove the full committed low-degree extensions (LDEs) retained by
every input tree. The applicable existing mechanism is Stwo's coefficient-backed
commitment storage, not a different RAM argument. It preserves the original
polynomial, Merkle root, relation challenges, physical claims and STARK format.

The new `input_storage` option on v7 joint memory and memory cohorts defaults to
`resident`. Its explicit `coefficients.minimum_trace_log` selects input columns
whose LDE storage may be released after commitment. Interaction and composition
trees keep their existing storage policy. No verifier accepts this option as
proof authority, and no existing execution route silently changes its default.

## Implementation

- `block_v7_input_storage_v1.zig` expresses the prover-only selection policy.
- Joint memory already retains original coefficients. It now optionally compacts
  each of its two input trees before sharing them with another proof owner.
- `block_v5_word_pcs_v1.commitWithStorage` exposes the same explicit input-only
  choice; the existing `commit` API delegates with compaction disabled.
- Memory cohorts use the distinct `B7MEC001` checkpoint format when selected:
  raw witness columns, original native coefficients and original Merkle layers.
  The existing `B7MEM001` resident format remains readable and unchanged.
- The coefficient checkpoint validates independent widths, native/extended logs,
  file length, resource caps, canonical field encodings, layer sizes, root and
  source identity. A cache file grants no acceptance authority. Fresh original
  proof verification still authenticates the resulting proof.

The shared core evaluates OODS values from retained coefficients, keeps them
alive through DEEP construction, and reconstructs query openings in column
batches. Its query scratch bound is **the larger of 128 MiB and one extended
column**, plus twiddles and query/Merkle metadata. At trace log 22 and blowup 1,
one column is 32 MiB. This is bounded in width, not constant in trace height.
The request's existing hard allocator remains authoritative for total memory.

## Expected tradeoff, not a measured speed claim

For a width whose raw field storage is `R` and blowup factor is two:

| Path | Resident input storage | Coefficient-backed input storage |
| --- | ---: | ---: |
| Joint stage, including raw witness | `R + R + 2R` | `R + R` |
| Cohort checkpoint/load, including raw witness | `R + 2R` | `R + R` |

These omit Merkle layers and metadata. The raw witness is still required to
generate interactions. Query openings perform additional FFT work instead of
keeping every LDE resident. This feature alone does not bound every component's
quotient, the global composition accumulator, or an entire block's resident
source roster; it complements the separate bounded staging and quotient work.

## Qualification gates

The focused `block_v7_coefficient_inputs_test_root.zig` gate checks:

1. A genuine five-shard joint memory proof with all input LDE values absent,
   byte-for-byte equality against the resident proof, detached fresh verification
   and physical-claim negatives.
2. All five RAM and three provider cohort proofs against the original in-memory
   oracle, including exact provider proof bytes.
3. Wrong checkpoint identity, allocation cap, noncanonical raw/coefficients and
   a canonical changed coefficient. An inconsistent cache must fail proving or
   fresh original verification, never become trusted by loading successfully.

The focused ReleaseSafe CPU gate passed all five tests. The joint proof was
byte-identical (99,491 bytes); its input stage's charged live memory fell from
20,945,296 to 19,280,592 bytes. This tiny heterogeneous fixture is dominated by
other retained data, so that reduction is not a large-shard memory estimate.
All eight separate cohort proofs also matched their resident originals exactly.
The coefficient corruption and source-identity/resource negatives passed.

Evidence: [receipt](../../../vectors/reports/block-v7-coefficient-inputs-20261029/receipt.json)
and [runtime log](../../../vectors/reports/block-v7-coefficient-inputs-20261029/run.log).
No controlled latency comparison or complete execution proof is claimed by
these scoped memory tests; larger and assembled qualification comes next.

## Interaction storage and consuming production

A second, separately selected `interaction_storage` policy compacts the
interaction tree immediately after its original commit. Composition remains
resident. `consume_rows` on standalone joint/cohort proving releases input and
generated interaction matrices after their last reader. Defaults retain these
rows for existing callers.

The multiwindow union uses `proveWithOptions.consume_memory_producer` instead.
It first commits the merged fixed tree, retains the source's private MAIN tree,
generates and commits every interaction, then releases:

1. The memory preparation context's separate transient row arena.
2. The source's raw witness.
3. The source commitment-scheme owner, after the union has acquired the needed
   immutable tree lease.

Claims, component equations, source roots and layout metadata remain live.
The consumed source rejects another proof attempt. The differential test creates
an independent oracle memory stage after the measured union proof, so oracle
retention does not prevent production lifetime qualification.

`ProducerStats` records the memory allocator's actual live bytes after
preparation, commit and consumption, and the outer allocator's live bytes before
core proving. These are distinct from peak memory: multiplying a whole proof's
peak by its number of cohorts would count shared phase scratch repeatedly.
At trace log 22 and blowup 1, the 116 interaction LDE columns alone occupy
3,892,314,112 bytes; their coefficients still occupy 1,946,157,056 bytes.
Actual complete-path results must include all other trees, metadata and scratch.

This second lifecycle passed seven focused memory tests and the complete
20,495-cycle, two-window canonical execution gate (q70/PoW26). All six original
oracle proofs' physical claims match. Its 6,063,212-byte portable envelope,
public metadata and ELF match the prior input-only artifact byte for byte.
A separate process verified the saved result with independently selected ELF,
security and terminal output; all eight receiver tests passed.

The memory source allocator fell from 27,968,069 live bytes after commitment to
10,170,064 after consumption. Whole proof-phase charged peak fell from the prior
337,564,021 to 311,708,246 bytes. These are small-fixture measurements, not a
block-size extrapolation. The diagnostic proving phase took 3.549 seconds on a
shared host; no controlled timing ratio or contiguous E2E result is claimed.

Evidence: [consumption receipt](../../../vectors/reports/block-v7-memory-consumption-20261029/receipt.json)
and [phase table](../../../vectors/reports/block-v7-memory-consumption-20261029/results.tsv).
The receipt identifies the exact pre-active-caller-V3 protocol snapshot; a later
layout migration must qualify its own artifacts.

### Producer storage admission

The previous multi-window scope always priced resident LDEs, even when the
producer held only native coefficients. That could reject a batch before the
bounded proof allocator had the opportunity to run it. The new explicit
`ProveOptions.compact_storage_admission` selects a producer-only calculation;
its default is false. `Scope.initForProducer` calls the same independent ELF,
window, epoch, geometry and source admission as the default receiver. Only its
retained-PCS resource estimate differs. No storage mode enters the proof wire,
statement, transcript or key, and default verifier/codec limits stay unchanged.

The model retains coefficients, Merkle trees and descriptors for every column.
It discounts only memory input/interaction LDEs selected by the actual stage's
storage policy. Original fixed-tree ownership remains counted, and the merged
fixed tree is still priced as resident. Before preparing interactions, the
producer checks committed column logs and coefficient lengths, requires dropped
LDE buffers to be empty, and checks that coefficient views alias the original
owned coefficients. It checks the committed interaction representation too.
A mutable policy cannot claim savings for a resident tree.

This is a retained-storage estimate, not a proof peak. Commit-time LDEs, source
rows, quotient scratch, composition, FRI and opening reconstruction remain
outside it. Opt-in proving therefore requires a `SharedHostBudget` allocator;
consuming source rows does not receive any speculative discount. The fixture
switch `STWO_V7_MULTI_UNION_COMPACT_ADMISSION=1` uses exactly the compact estimate
as its producer cap and verifies that materialized admission rejects that cap,
then uses the original receiver limits for independent verification. The combined active-layout-V3 canonical 20,495-cycle run passed all eleven
tests with this option enabled. Its retained-PCS producer model was 174,618,288
bytes, versus 187,993,904 under materialized admission. All six original oracle
proofs' physical claims matched; the original owners were destroyed before fresh
verification. The proof-phase charged peak was 311,708,246 bytes, which exceeds
the retained-PCS model because that model deliberately excludes other live work.
The 6,048,463-byte portable proof is saved in the
[separate V3 artifact](../../../vectors/reports/block-v7-active-caller-v3-20261029/two-windows).
The consumption receipt records this follow-up separately; prior storage/proof
parity evidence above remains valid for its recorded pre-V3 source snapshot.
