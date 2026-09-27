# Direct recursive witness columns

The recursive witness path previously retained arithmetic invocation buffers,
materialized multiply/inverse/linear logical row rosters, copied those rows into
the parent Builder together with compact fixed metadata, and then scattered the
Builder rows into committed main columns. Each intermediate overlapped the
authenticated graph and final column storage during preparation.

`recursion/air/arithmetic_fusion_rows.zig` now uses one typed emission kernel for
both the legacy row sink and a count-first column sink. The planning pass admits
the exact fused row counts from the same graph/matcher and does not construct
arithmetic invocation buffers or witness row rosters. The emission pass retains
the original authenticated lowering/evaluation checks, creates one transient
logical row at a time, and writes multiply/inverse/linear main coordinates into
their final columns via `framework.committedRow`. Compact fixed rows are kept
in their original logical order. Zero padding, minimum log 1, existing projection
log limit 24, fixed selectors and proof-kind parameters are unchanged.

`blake3_native_parent_rows.zig` adopts these columns and fixed metadata directly
for cohorts 3, 4 and 5. It skips their old Builder copy and final projection. The
returned storage is the existing `blake3_parent_row_storage.Prepared`; normal
fixed-fingerprint authentication, lookup registration, interaction generation,
main commitment and consuming cohort/row release continue to use that owner.
There is no alternate proof encoding or weakened verifier path.

The source-derived PCS/public cohorts 6, 8, 9, 10 and 13–17 now use one shared
source-append recipe for counting and typed column emission through
`blake3_direct_source_columns_v1.zig`. Their legacy Builder logical row arrays
and separately appended compact fixed arrays are no longer allocated. The
emitter validates the same independently supplied fixed tails and writes the
same final columns plus one compact fixed roster. These columns finish before
the original transcript/path source-release callback.

`native_pcs_fusion_rows.zig` retains the exact canonical dot4/query contraction
matcher in one shared emission kernel. It counts then emits final retained
scalar, detached-opening and native-opening columns for cohorts 12, 18 and 19.
The production path no longer allocates its three output row arrays, copies
them into the Builder, or runs the later row-to-column projection. Inventory
scalar rows are freed immediately after successful matching. Legacy row sinks
remain available for parity fixtures and retain all existing admission checks.

Remaining intermediates are explicit: the original arithmetic dot4 opening
rows remain matcher input; scalar inventory rows exist until inventory and
query matching; cohorts 2 and 11 still retain their inventory-dependent Builder
rows and later projection; and upstream Prepared transcript/path/public/PCS
sources still materialize their original source rows. The canonical arithmetic
invocation scratch and graph/matcher scratch also remain. Count-first native
PCS matching repeats the validation/matching kernel in two phases; it does not
retain both phases' scratch or claim a time improvement.

The direct scatter currently writes each emitted row into all main columns.
Compared with the old column/tile projection, its CPU locality can differ; no
timing, peak reduction or multiplicative speedup has been measured. All buffers
use the supplied allocator and therefore the existing aggregate host budget.
Count mismatch and incomplete emission fail before a column owner is returned.
Error cleanup and ownership transfer preserve the standard consuming release
contract.

Focused source fixtures compare legacy and direct main columns, all compact
fixed fields, FMA/dot4 counts, opening row sources, zero/minimum/non-power-of-two
padding, and segment/binary modes. They transfer direct buffers into canonical
Prepared storage and exercise partial/final release. Source-cohort tests cover
all nine direct cohorts, multiple append chunks, no legacy Builder allocations,
fixed-tail rejection, incomplete counts and caps. Native PCS tests compare all
three empty/nonempty output cohorts and retain changed/missing/duplicate source
rejections. The focused root is
`src/frontends/riscv/block_v5_recursive_direct_columns_test_root.zig`.

The arithmetic, source and PCS direct-column parity/admission/ownership checks
passed in the27-test bounded custody gate. No fresh recursive proof has been
run; segment/proof runs remain stopped. Eliminated allocation sites are
source-reviewed facts, not measured peak or timing reductions.

[Custody qualification log](../../autoresearch/notes/2026-09-24-ethereum-block-delivery/cpu-performance-gates-v1/witness-and-direct-columns-custody.log).
