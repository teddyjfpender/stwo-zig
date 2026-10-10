Word protocol version 2 retained 36 main columns and removed eight duplicate predecessor range requests while
preserving every direct equation: an interior predecessor is the previous
committed current endpoint, and a shard's first predecessor is an independently
pinned, typed public endpoint. Both routes still have nine equality equations.
Public u1/u32/u64 fields are checked by exact packed-limb round trips before
trace construction and fresh admission. No clock or value is field-reduced.

Version 2 has 17 range slots and nine paired range recurrences. Interaction
columns decrease from 84 to 68. Actual range demand is ten current limbs plus
three key-gap or four clock-gap limbs per non-global-first row. Independent
planner and verifier bounds are 13*rows-3 through 14*rows-4 for the first shard,
and 13*rows through 14*rows for later shards. The dense 103 distinct-key case
therefore has 1,336 requests and 6,400 rational terms over its 256-row domain.
The protocol version, relation ABI, memory instance domain, and range-plan
domain change explicitly. Existing persisted version-1 artifacts do not acquire
the new proof geometry by relabeling.

The canonical source now implements word protocol version 3, with 27 main
columns; fresh proof qualification remains pending. It removes previous_key[3], previous_clock[4], previous_value[2]. The
ordering constraints instead use the previous sampled current endpoint except
on the fixed first row, which supplies the public preceding endpoint (zero on
the global first row). All current address/clock/before/after and gap range
requests remain. The two groups of nine copy equations and the redundant
predecessor-space Boolean equation disappear, leaving 46 direct equations.
The public endpoint types and the previous row's current-space Boolean and
range equations authenticate the replacement. The native/register custody
policy and the independently pinned shard roster remain separate obligations.

A naive denominator built from that first-row blend has degree two. Pairing
an endpoint term with the final current endpoint would then produce degree-five
weight products and invalidate the existing degree-four quotient domain. The
version-3 endpoint recurrence must instead separate these three fractions:

* Interior: shifted endpoint denominator, with weight
  active*(1-same)*(1-first)*shifted_space.
* Shard boundary: public preceding endpoint denominator, with weight
  first*public_boundary_count. The boundary count is independently derived
  from the pinned preceding and first integer keys, whose exact adjacency and
  continuity are validated; sorting constraints enforce that same decision.
* Global final: public last endpoint denominator, with weight
  global_last*public_last_space.

For register endpoints the corresponding space factors are 1-space. Both
public denominators are constants under the already drawn word challenges;
they are independently determined by the admitted claim. The recurrence is
`(delta - first*public_boundary_fraction - global_last*public_final_fraction)*interior_denominator - interior_weight`.
Its degree is at most four, without an extra committed interaction column.
An identically absent public partition contributes the constant zero; its
unused denominator must never enter a clearing product that could nullify the
equation. An active singular public denominator is rejected before proving or
fresh verification. Host integer predicates apply only to independently pinned
claims; there is no branch on arbitrary field-valued OODS selectors.

The existing link recurrence can retain its aggregate claim and paired form:
the blended prior denominator has degree two, the current denominator degree
one, and their prefix delta degree one. The product therefore stays degree four.
Each transcript still binds the aggregate endpoint/link/range sums and exact
counts, including independently reconstructed first-round instance IDs and
fixed/main roots. The endpoint generator, scalar evaluator, packed evaluator,
and fresh verifier must use the same public fractions and weight split.

The coordinated source change spans air/block/word_memory_v5.zig and
word_memory_trace_v5.zig, then prover/block_v5_word_memory_{interaction,component,
proof,protocol}_v1.zig and the packed challenge/constant helper if needed. The
generic quotient row engine remains unchanged. Both default producer and
independent codec policy derive their dimensions from the new Spec. No parallel
backend or silently selected compatibility path is proposed.

The canonical previous-main opening mask is explicit in both component specs.
Word27 opens and gathers the previous row only for current_key[2..5),
current_clock[5..9), and after[25..27). Range16 has no previous-main dependency.
Every main column still opens its current value; fixed columns open current
only; every interaction column retains both current and previous values.
The v3 ABI binds this grammar. The adapter rejects missing required previous
openings and extra openings on omitted columns before evaluating constraints.
Scalar and packed domain kernels use the same static mask and initialize
unused previous cells to zero, without allocating recovery buffers or changing
worker ownership. Independent equations ignore those cells even when the
reference fills them with arbitrary extension-field values.

The focused source-only mask tests are `block-v5 authenticated previous
openings preserve exact word and range OODS equations` and `block-v5 masked
previous gathers preserve all scalar and packed quotient rows`, imported by
block_v5_word_cpu_optimization_test_root.zig. The latter uses only 8 and 64
domain rows and no worker pool. These tests have not been run by this agent;
segment, proof, and benchmark runs remain stopped.

Required qualification includes scalar versus PackedQM31 constraints at
arbitrary extension-field points; zero/first/interior/final boundary weights;
singular active and unused public denominators; u32/u64 maxima; adversarial
shard predecessor/public first and last mutations; independent obsolete-count
and geometry rejection; and fresh dense/multi-shard range/source/endpoint
closure. Segment proving and benchmark runs remain stopped. Version-2 source passed the focused scalar/SIMD/worker gate. Version-3 source
and formatting checks are complete. Its new row-equation and singular public
endpoint tests, existing scalar/SIMD parity and fresh dense/multi-shard proofs
await the coordinated test lane. No segment runs were launched.
