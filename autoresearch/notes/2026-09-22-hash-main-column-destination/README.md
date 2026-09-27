# Native main-column hash destination

The canonical hash emitter now supports physical G/XOR main columns plus separate
logical witness metadata. Each emitted row writes its main coordinates directly
at committedRow(first+index, log), zeroes metadata main slots, and copies only the
metadata suffix. Boundary rows retain the canonical row sink. It does not build
full G/XOR live-row arrays. Caller owns nonoverlapping storage and padding; every
column/range/metadata/boundary shape is checked before mutation. Later failures
may leave unpublished output partially written.

Generated metadata is witness data, not trusted preprocessing. This API does not
replace independent fixed admission. Parent integration is not yet wired; this
stage establishes the exact destination representation needed by that integration.

Focused ReleaseSafe hash gate passes 4/4 steps, 5/5 tests (644 ms /32 MiB reported
MaxRSS, compile 7 s /666 MiB). For empty/65-byte/1025-byte inputs, new tests compare
all reconstructed rows and boundary rows with the owning witness, check metadata
main zeros, nonzero offsets and untouched padding, and compare complete interaction
columns/claims through the existing column-view generator against the row oracle.
Invalid metadata, columns, ranges and boundaries reject before earlier main-column
writes; initial allocation failure also preserves those outputs. Existing hash
vectors, full-column destination and graph-allocation tests still pass.

No native proof rerun or memory/timing claim: production orchestration still uses
the previously qualified logical-row path. Its last measured preparation/worker
peaks remain 382,427,223 /982,008,191 bytes; those are not measurements of this sink.

## Required integration path

1. Separate native transcript replay/planning from live emission. Its existing
   trusted transcript plan provides G/XOR counts before live rows are built.
2. Derive path G/XOR counts from admitted capture geometry (trace column count,
   query positions, FRI fold width/depth), then independently check actual emission.
3. Allocate combined main domains once; lend transcript/path subranges at their
   global logical offsets. Carry destination access through frame/draw/group
   adapters, including XOR metadata use-count updates.
4. Preserve independent fixed metadata comparison and explicit ownership transfer
   into Prepared; State destruction must not free the returned columns. Remove
   redundant final projection for these integrated cohorts.
5. Qualify full native proof/key/codec parity, handoff lifetime, mutation rejection,
   allocation failures and production geometry before claiming integration complete.

Smaller cohorts, production profiles, reusable keys, multi-level/distinct-child
recursion, Metal/default migration and reviewed parameters remain incomplete.
