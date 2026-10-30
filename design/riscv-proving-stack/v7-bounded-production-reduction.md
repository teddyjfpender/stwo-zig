# Bounded production reduction after cohort roots

## Current limit

`block_v7_complete_cpu_producer_v1.produce` admits at most 64 original children
and materializes their verifier rows for one parent. The limit on child count
is not a memory estimate: one canonical-security child can be much larger than
several diagnostic children. Separate RAM cohorts solve original witness
lifetime pressure; they do not by themselves bound recursive witness lifetimes.

The existing batch modules already qualify two genuine direct windows followed
by one reduction proof. They preserve all original typed public frames and close
global execution only at the final receiver. Their current reduction supports
at most 32 direct batches, not an arbitrary-depth tree.

## Proposed production API

A new bounded producer should return the existing detached metadata owner plus
an explicitly tagged direct or reduction artifact. Its options should include:

- independently chosen security profile and maximum original roster size;
- maximum direct children (at most 64), fixed rows per component and host bytes;
- maximum reduction children (at most 32) and a separate reduction budget;
- bounded compiler-cache bytes, capsule count and optional intermediate sink;
- separately reported admission, compilation, capture, preparation, commitment,
  proof, encoding and reduction times and charged memory peaks.

Conceptually:

```
produceBounded(trusted, originalSource, options, intermediateSink)
    -> { metadata, taggedRoot, batchCounts, independentPins, phaseStats }
```

`originalSource` may first wrap the current borrowed `Original.Input`. A later
file-backed implementation must load one bounded original at a time and invoke
its original verifier; an on-disk success receipt is not a substitute.

## Streaming memory plan

1. Admit the whole immutable metadata roster once with an explicit whole limit.
2. Compile original family fixed geometry sequentially. Use exact per-AIR row
   counts and column widths, power-of-two padding, security expansion and parent
   PCS lifetimes to admit a bounded next window. Child count alone is insufficient.
3. Retain only the current window's cold compiler pieces, then capture and
   prepare its actual originals. Canonicalize G partitions before joining.
   Compare exact live fixed rows and public wires to independent cold setup.
4. Commit the independent fixed tree once and transfer that authenticated owner
   to the original parent plan. Prove and encode this OPEN direct batch.
5. Persist only its proof, independent key/schedule and range metadata. Destroy
   all capture, verifier MAIN, fixed compiler and PCS owners before the next
   window. A completed batch must never retain its wide verifier rows.
6. After all windows are known, construct the exact contiguous coverage plan.
   Existing direct keys bind the original epoch and selected roster, so direct
   proofs do not need future batch counts. The reduction binds the completed
   plan and cannot omit, overlap, reorder or substitute a batch.
7. Freshly capture the bounded direct proofs, compile their independent verifier
   keys and prove one reduction. Delete intermediate proof buffers after this
   step. The final receiver reconstructs all typed public frames, authenticates
   the sole final root and then closes every global relation.

The admission estimate must include source and destination coexistence during
the drain join, fixed-tree retention, FFT/commitment buffers and proof state.
`retainedBytes()` measures rows only; it is not peak proving memory. Enforce an
outer shared allocator budget in addition to estimates. If a single original
verifier exceeds the admitted budget, fail with an explicit size diagnostic;
do not weaken security or silently drop a provider. Original execution/caller
partitioning must change before retrying that case.

## Work to reuse, not repeat

The batch path should reuse `MixedFixed.deriveWindow`, `Collection.prepareWindow`,
`MixedBatchProducer.prove` and the final batch receiver. The missing production
piece is bounded scheduling and ownership, not another verifier implementation.
To avoid recompilation while choosing a window, expose a consuming fixed-roster
builder or retain only its bounded compiler pieces. Deriving the complete cold
roster merely to estimate it and then deriving it again would add the very
redundancy this architecture removes.

Before thousands of originals, fix whole-roster ownership too: existing family
profiles copy the same epoch entry list. N profiles each retaining N entries
is O(N²) metadata (roughly 2.9 GB of entry payload at N=4096 with 172-byte entries,
before overhead). A single immutable admitted roster owner with borrowed profile
views can preserve exact identity while making this O(N).

## Required gates and deliberate boundary

The next implementation gate is a real cohort job forced into multiple bounded
windows, exact direct cold/live parity, a reduction proof, producer/intermediate
teardown, and fresh complete verification. Add missing/duplicate/reordered range,
changed typed claim, wrong key/security and oversized-child negatives. Compare
its final global summary to the existing original execution receiver.

A first production version can explicitly cap the result at 32 direct batches.
For larger jobs, the reduction protocol must become level-aware and capture its
own reduction proof with independently derived keys while preserving original
range frames. Passing a reduction proof to the direct-proof adapter would be
incorrect. Arbitrary-depth reduction is therefore an additional qualified
protocol step, not a fan-in flag.

This note is an implementation plan. It introduces no new proof authority and
claims no new timing or capacity result.

## Initial implementation under qualification

`block_v7_bounded_complete_cpu_producer_v1.produce` implements sequential direct
windows with bounded in-memory proof staging and one final reduction. The default
window is four original children; explicit limits permit at most 64 per window,
32 windows and 2048 originals. A lower bound on required windows is checked
before any proofs. Cold geometry that exceeds the configured planning budget
shrinks the next window before live capture; a single oversized original fails
explicitly. Source and final verifier security configurations must agree.

`block_v7_parent_resource_model_v1` includes actual padded row/column counts,
original lookup tables, extended values, retained coefficients, Merkle buffers,
composition workspace, join coexistence and explicit scratch headroom. It is a
conservative planning model, not a formal upper bound on allocator behavior.
Independent shared allocator limits remain mandatory. The qualification test
checks observed charged peaks against estimates for every window and reduction;
this does not establish a bound for other inputs or canonical security.

Both direct windows and final reduction now retain the independently committed
fixed tree for the original prover plan, after exact cold/live row and wire
checks. They do not recompute that same fixed FFT/commitment during plan setup.
Every direct window destroys all wide owners before the next. The final
reduction still retains its bounded captures because its public sources borrow
them; those captures are not wide original witness owners.

The producer returns a candidate root and independent metadata/key schedules.
Only the existing complete detached batch receiver establishes full authority.
The actual ten-original separate-memory fixture passed 11 checks with windows
4+4+2 and a 148,671-byte final root. The fresh receiver closed the complete job
after all original and intermediate proof owners were destroyed. All direct
windows and the reduction stayed below their planning estimates; measured
charged window peaks were 5.707, 1.491 and 1.152 GB, and reduction peaked at
2.788 GB. Bounded proof staging, including duplicated schedules, peaked at
4.34 MB.

Root production took 78.37 seconds; the entire original-to-verified-root
qualification took 88.41 seconds with 5.809 GB maximum RSS. These are diagnostic
concurrent-compiler observations, not ranked production timings. The full
caller layout was used. Details and stage profiles are in
`performance/v7-bounded-root-qualification-20261029.json`; per-window data are
in `performance/v7-bounded-root-windows-20261029.tsv`.

The successful path predates the extracted cold resource-error retry helper.
That helper now halves only on recognized resource failures and preserves
malformed admission errors; its forced-cap gate passed 11 tests, recorded in
`performance/v7-bounded-cold-retry-qualification-20261029.json`.
Actual >64-original, canonical-security and higher-depth runs remain unqualified.

## Boundary segments, source lifetimes and canonical admission

The genuine seven-segment fixture includes an all-precompile native frame and
17 original proofs. Windows 4+4+4+4+1 produce a 148,535-byte root; fresh complete
verification passes after original and intermediate owners are destroyed.
The diagnostic q8/PoW0 record is
`performance/v7-bounded-boundary-root-qualification-20261029.json`.

One-shot direct and reduction producers now consume source rows after each
cohort's final interaction-generation read. The plan keeps its independently
authenticated fixed commitment and metadata; public frames keep their original
separate owners. The same 17-original test produces the identical root hash
`bbf199bdd0bca568fe6ec0737442cdf99aaec45f43b7f595e68aaccb7477c9ca`.
Charged peak falls from 4,923,049,866 to 3,912,504,450 bytes (20.5%). See
`performance/v7-consuming-parent-qualification-20261029.json`. This measured
memory gain is distinct from a timing claim on the shared development host.

At q70/PoW26, a caller singleton successfully compiles but its conservative
planned peak is 39,935,002,676 bytes, above the default 24 GiB direct cap.
An explicit diagnostic 40 GiB direct budget, still beneath the 48 GiB request
cap, permits proof generation. All five direct windows were generated; the
attempt then failed final-reduction resource admission. It produced **no final
canonical root**, and stopped before detached capture verification of those
direct proofs. Process peak footprint was 13,676,196,368 bytes; the caller's
charged window peak was 13,600,670,467 bytes. The estimate is not measured demand.
The run predates consuming rows but includes the sampled-value allocator fix.
See `performance/v7-canonical-bounded-attempt-20261029.json` and its adjacent
memory-stage CSV. Production resource defaults were not raised.

For subsequent sizing, the bounded fixture has a test-only
`STWO_V7_REDUCTION_COLD_ONLY=1` mode. It constructs the same independent direct
fixed keys and final cold schedule without generating recursive proofs, then
reports the exact final model and admission decision. It grants no proof
authority. `STWO_V7_SCALE_CANONICAL=1 STWO_V7_DIRECT_GIB=40` selects the canonical
diagnostic geometry; `STWO_V7_WINDOW_PROFILE=1` adds intermediate admission data.
This shortens rejected sizing experiments rather than repeatedly generating
direct proofs before discovering the final planning limit. The canonical cold
probe passed 12 tests in 108.62 diagnostic seconds. For counts 2+1+4+4+1, the
final schedule has row log 23, 1,862,008,028 fixed bytes, 9,638,702,300 retained
row bytes and 4,495,982,592 committed cells. Its conservative planned peak is
102,201,939,604 bytes; both the retained-row cap (4 GiB) and planned-peak cap
(28 GiB) reject it. The probe itself peaked at 4.14 GB process footprint and
created no recursive proof. See
`performance/v7-canonical-reduction-census-20261029.json`.

These results motivate reducing the original proof roster before recursion,
rather than repeatedly increasing budgets for the existing wide verifier.
The finite complete original-STARK experiment is documented separately in
`performance/v7-heterogeneous-original-stark-20261029.md`; it does not yet
qualify arbitrary-depth, multiwindow Ethereum execution.

## Subsequent measured hypothesis: reuse identical fixed commitments

Across many same-shape windows, independently compiled fixed rows may be exactly
identical even though epochs, statements and key contexts differ. A future
bounded cache could lease the physical immutable tree after comparing every
new fixed-row digest, row log and security configuration. It must independently
rederive the new context and full key; the old request's admission, witness and
transcript must never be reused. The current code reuses only within one window.
This cross-window proposal has not been implemented or measured.
