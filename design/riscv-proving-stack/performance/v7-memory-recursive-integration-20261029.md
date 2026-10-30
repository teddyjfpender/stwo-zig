# V7 memory recursion: original equation authority and remaining integration

The replacement memory protocol removes machine-memory-image RAW/FOLD proofs.
It must still recursively verify every packed RAM, initialization interval,
range16 and terminal original proof under the independently reconstructed
execution policy. Native/caller demands and all provider relations must close
in the final root. The new original-execution receiver is a separate milestone;
it is not a recursive root.

## Implemented and checked

`block_v7_ram_component_v1.zig:equations` is the shared authority for all 161
RAM equations. Scalar and packed evaluators call it with their original
endpoints; symbolic recursion calls the same body with symbolic endpoints.
`block_v7_provider_component_v1.zig:equations` serves the other three families.
No constraint is removed by this extraction.

`recursion/air/block_v7_memory_composition_v1.zig` records exact original
quotients, coefficient order and four-chunk composition reconstruction.
Physical sums are circuit inputs and divided by the admitted domain size
inside the graph. RAM endpoints, boundary flags and preceding ordinal are
inputs, so their received values cannot select fixed code. The incoming link
inverse is computed and constrained inside the graph; the first shard uses a
denominator of one with zero weight.

The separate `accumulate` entry carries a single Horner accumulator across
independently sized components using the global maximum log for each quotient
denominator. This is the seam for the new joint original memory proof; its
caller must constrain one final composition reconstruction after all parts.
Mixed-log parity against the original quotient adapter is tested, including
a nonzero incoming accumulator and corrupted sums/openings.

`recursion/air/block_v7_memory_shape_composition_v1.zig` constructs this graph
from row log, configuration and the original quotient adapter's sample layout.
Its source map includes all 53 relation pairs from the execution epoch:
Universal47, Word5, then interval1. The memory kernels use pair indices 47
(transition), 48 (link), 52 (interval), and 51 (range16). Complete keys must
also bind the original transcript and openings; the shape is explicitly not
complete-family authority.

The focused ReleaseSafe gate passes for all four families against the actual
original quotient adapter at arbitrary OODS values. It rejects changes to each
physical sum and each composition chunk, RAM endpoints/boundary flags, and a
nonfirst shard's incoming ordinal. First, middle and last shard claims produce
identical symbolic code. The independently compiled source map rejects a
mutated map even after its self-identity is recomputed.
All 106 challenge ports are checked against the actual execution epoch v3
draw order and final channel. The five focused ReleaseSafe tests pass. The RAM public vector now includes
84 scalars, including the halt address and four permitted clock values. These
remain symbolic inputs; mutation tests reject incorrect halt constants.

Evidence: [current first-halt qualification receipt](v7-memory-halt-composition-qualification-20261029.json).
The earlier four-test receipt retains its pre-halt source hashes.

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_memory_composition_test_root.zig \
  -OReleaseSafe --test-filter 'v7 memory composition'
```

## Actual original-proof integration

The joint-memory original proof now passes fresh verification after producer
rows are destroyed. Its captured composition, DEEP and FRI all evaluate against
independently derived geometry; the actual v7 transcript has cold/live fixed
plan parity, including changed-root/claim invariance. The fixture is 99,491
proof bytes. This qualifies the original-proof verifier components, not an
outer recursive parent or the complete block.

## Complete acceptance checklist (partially satisfied above)

1. Capture the actual newly verified original proofs under the v7 epoch and
   compare sample geometry, scalar composition, DEEP and FRI against these
   independent shapes. Arbitrary-OODS parity alone is insufficient.
2. Record the v7 epoch and memory-family transcript, binding every first root,
   physical claim, composition root, opening, PoW and query exactly as the
   original verifier. Do not reuse a v5/v6 claim tag or source seal.
3. Bind normalized sums and symbolic endpoint/ordinal inputs to exact public
   metadata derived from the independently admitted memory shard sequence.
   Bind interval/terminal fixed roots to ELF initialization and expected output.
4. Compile fixed arithmetic, transcript and Merkle-opening rows without producer
   capture authority; establish live/cold equality and independent key parity.
5. Add new typed children to the complete root closure with actual native and
   caller exports. Preserve local register-window closure, ROM/table census,
   RAM transition counts, initialization and terminal checks. Verify a detached
   root after destroying intermediate files and producer witnesses.
6. Qualify canonical security, then measure matched complete workloads. None of
   these equation checks establishes Ethereum block performance or a 10× gain.

The complete v6 fixture's source RAW/FOLD children account for 75.68% of its
recorded recursive arithmetic rows; this motivates the removal. New providers
add work, and arithmetic rows omit other AIR cohorts and padding. The
[work census](complete-root-arithmetic-work-census-20261028.json) is a design
priority signal, not a runtime forecast.
