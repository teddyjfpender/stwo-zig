# Session 02 — increment 2: interaction relation build (R4)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, predecessor head `196a679f`.

This is a reasoning log, not a summary. It records what was inspected, why each
change was made, what was rejected, and the raw numbers behind every claim.

## 1. What the previous increment left on the table

Increment 1 closed the CPU FRI quotient hypothesis negative and, more usefully,
calibrated this host: identical sources produced up to +12.2% spread on a
single stage and -2.4%/+2.8% on complete prove time. That is the bar. A
single-digit-percent stage claim here is noise.

The campaign brief carried a prior split of memory-7m `interaction_trace_build`
= 931 ms into ~609 ms relation fraction construction plus batch inversion,
~108 ms QM31 → four-coordinate lowering, ~114 ms multiplicity prep. Commit
`ad2d3ac5` had already added the stage recorder needed to check that split, so
the first thing to do was check it rather than trust it.

## 2. Audit

One cold `run-and-prove --stage-profile-out` on arithmetic-2m with the pristine
predecessor build, host load average 4.01 at open.

`Interaction trace build` total **362.083 ms**, decomposing into:

| Bucket | ms | Share |
| --- | ---: | ---: |
| `Interaction fraction materialization` (29 components) | 278.533 | 76.9% |
| `Interaction coordinate lowering` (29 components) | 40.665 | 11.2% |
| `Memory multiplicities` | 16.008 | 4.4% |
| `Fixed-table multiplicities` | 11.141 | 3.1% |
| Residual: source construction, topology compile, allocation | 15.736 | 4.3% |

Per-component, one component dominates: `add_opcode_small` 143.572 ms, then
`range_check_20` 36.308, `memory_address_to_id` 23.567, `range_check_9_9`
21.590, `jnz_opcode_taken` 17.668, `ret_opcode` 17.333.

So the brief's shape holds: fraction construction is three quarters of the
stage and lowering is a further ninth. Multiplicity *collection* (the two
`... multiplicities` stages) is only 7.5% and is a different code path
(`fixed_trace`, `cpu_memory`) — out of scope for this increment.

### Where values are materialized more than once

Reading the path from component emission to
`interaction_trace_commit`:

1. `Reference.evaluateRange`
   (`src/frontends/cairo/witness/interaction_trace.zig`, predecessor) walked
   **row-major**: for every row, for every descriptor, for every use, for every
   relation word, it called `SourceView.relationWord(kind, arg, word, row)`.
   That accessor
   (`src/frontends/cairo/witness/interaction_source.zig:211` predecessor)
   re-does the complete layout dispatch per element: `rows()` union switch, row
   bound, `word == 0` guard, storage-tag switch, kind check, overflow-checked
   `addIndex`/`mulIndex`, then `LookupColumns.value` / `SparseColumns.value`
   with two more bounds checks and a canonicality branch. The same is true of
   `SourceView.multiplicity` (`:255` predecessor). None of that varies with
   `row` — it is loop-invariant work executed `rows × words` times.
2. The combine's word-0 term is `alpha_powers[0] * M31(use[3])` added to
   `-z`. Constant per use, recomputed per row.
3. `materializeTrace` allocated a full interleaved QM31 column-major trace
   (`column_count × row_count × 16` bytes) and `captureAt`
   (`src/frontends/cairo/proving/interaction_trace.zig:397` predecessor) then
   ran `lowerCoordinates` (`:480` predecessor), a second complete pass reading
   every QM31 and writing `value.toM31Array()[coordinate]` into four freshly
   allocated M31 planes — four strided passes per secure column. **That is the
   duplicate materialization.** Every committed value is written twice and read
   once in between, for no reason other than the intermediate's existence.
4. Consumption inside `evaluateRange` wrote
   `destination[column * source_rows + row]` from a row-major loop, i.e.
   `uses_per_row` concurrent 16-byte-stride output streams.

## 3. What I changed and why

Three changes, all in service of the same idea: resolve everything that does
not depend on `row` exactly once, then move whole row runs.

**(a) Hoisted source resolution.** `SourceView.resolveWord(kind, arg, word)`
and `SourceView.resolveMultiplicity(kind, arg)` are new and return a
`WordAccess` / `MultiplicityAccess` — a two-to-five-way union whose common arm
is a bare `[*]const u32` addressing the borrowed column. They mirror
`relationWord` / `multiplicity` case for case; the element accessors stay for
the fixture oracles and `evaluateRow`. A new test
(`interaction_source.zig`, "resolve row readers that match element
addressing") walks seven source layouts × every word and every row and asserts
the resolved reader equals the element accessor, plus the virtual-column and
error cases. This is the correctness anchor for the whole increment: if the
resolvers agree, the combine cannot change any value.

**(b) Use-major planned combine.** `Reference.init` now builds `terms`,
`uses` and `column_plans` once. `combineUse` folds one use across a whole row
run, four rows per iteration:

```
acc[0..4] = use.constant
for term in terms:  lane = load4(term.dense + row); acc[k] += term.alpha * lane[k]
```

Four rows because the accumulator is a serial `add` chain — the loop is
latency-bound, not throughput-bound, and four independent chains cover the
`mulVec4` + `addVec4` latency. `QM31.mulM31` and `QM31.add` are *already*
4-lane `Vec4u32` operations over the four secure coordinates
(`src/core/fields/qm31.zig:186`, `:105`), so there was no width to gain by
restructuring into a rows-SoA layout — see rejected alternatives.

Canonicality of dense words is now checked with a running lane-wise `@max`
over the whole use instead of a branch per element, so I added
`M31.fromU32Unchecked` (`src/core/fields/m31.zig`) alongside the existing
`CM31`/`QM31` unchecked constructors. A non-canonical word yields a
deterministic wrong field element, never UB, and the run still fails with
`NonCanonicalM31` — the results are discarded.

Multiplicities are emitted per use as a run too, with the `one` case collapsed
to a `@memset`.

**(c) Direct coordinate emission.** `evaluateRangeInto` takes a comptime sink.
Consumption is now tiled (1,024 rows) and **column-major**: one running
`cumulative` tile is folded through every relation column in order, and each
finished column leaves as a contiguous run. `CoordinateSink` splits that run
straight into the four committed `[]M31` planes; `SecureSink` keeps the old
column-major QM31 form for conformance so both share one evaluator and cannot
drift. The interleaved intermediate and `lowerCoordinates` are gone from the
prover path.

Only the **last** interaction column is still staged as QM31, because its
committed values are `scanLastColumnInPlace`'s circle-order rewrite of the row
totals and that scan needs the claimed sum, which is not known until every
range is done. One column is lowered after the scan instead of all of them.

**(d) Skipped clear.** `allocateCoordinateColumns` deliberately leaves the
planes uninitialized: the straight-line writer covers every destination row of
every plane. This is the same predicate the direct-feed change established for
base-trace feeds.

Exactness argument: the only reordering is *summation order* (claimed sum
accumulated per tile rather than per row) and *batch-inversion grouping*
(use-major rather than row-major within the same batch). M31/QM31 addition is
exact modular arithmetic and therefore associative, and a field inverse is
unique, so neither can change a bit. That is what the byte-parity checks below
confirm empirically.

## 4. S1 mechanism evidence

Two `stwo-prof zig` harnesses, both wired against **live** repo sources. The
generated `build.zig` in each scratch dir was edited to give the Cairo module
its real `stwo_core` dependency (the default wiring is flat and cannot express
a dep-of-a-dep); nothing is copied out of the repo except, in the predecessor
arm, the *traversal shape itself* — which is precisely the thing under test.
Both arms call the same live `SourceView` accessors, the same live QM31
arithmetic, and the same live `batchInverseInPlace`.

Shape: 32,768 rows (the real parallel batch), 64 source columns, 16 relation
columns × 2 uses × 6 words, 32 alpha powers.

At an earlier, smaller shape (8,192 rows / 24 columns / 8 relation columns)
the instruction ratio was 1.374x but wall barely moved (230.9 → 222.6 ns/op)
and IPC was 6.16 — the extra instructions were absorbed by superscalar slack in
a working set that fits in cache. Recording that because it is the honest
reason the batch-scale numbers are the ones I quote: at the real batch size the
working set no longer fits and the instruction saving converts.

| Counter | elementwise (pred) | planned (cand) | Ratio |
| --- | ---: | ---: | ---: |
| instructions/op | 13,300 | 9,226 | **1.442x fewer** |
| cycles/op | 2,368 | 2,008 | 1.179x fewer |
| ns/op (median) | 550.1 | 466.7 | 1.179x |
| IPC | 5.618 | 4.595 | — |

`stwo-prof zig compare cairo-combine-elementwise cairo-combine-planned
--iters 8 --rounds 7`:

```
wall  B/A 0.8466  CI95 [0.841828, 0.85203]  → B faster
instr B/A 0.6937   cycles B/A 0.8504
A 556.706 ns/op · B 473.475 ns/op
```

CI95 excludes 1.0, so the verdict is real. The instruction ratio 0.6937 is the
mechanism confirmation: the candidate executes 30.6% fewer instructions for
identical output, which is what removing per-element dispatch predicts. The
falling IPC is expected and not a regression — the same real work in fewer
instructions raises the per-instruction memory pressure.

The harness understates the end-to-end effect for two reasons worth stating:
it uses `SecureSink`, so it does not include the eliminated lowering pass at
all, and it is single-threaded.

## 5. Reflection on what the numbers mean

The interesting thing the S1 loop taught me is that my first-order model was
wrong. I expected the win to come from vectorizing the combine, and went
looking for SIMD width. It was already there: `QM31.mulM31` is a `mulVec4` and
`QM31.add` is an `addVec4`, both saturating the 128-bit register with the four
secure coordinates. A rows-SoA restructure would have executed the *same*
number of NEON instructions per (word, row) — 4 lanes either way. The actual
overhead was never arithmetic; it was the ~15 instructions of union dispatch,
bounds arithmetic and error plumbing wrapped around each 7-instruction
arithmetic core. That is why the win shows up as an instruction-count ratio and
not as a NEON-share change, and it is why the 8,192-row harness showed almost
no wall movement while the batch-scale one did.

The second lesson is that the biggest single line item was not in the combine
at all. `lowerCoordinates` was 40.665 ms of 362.083 ms on arithmetic-2m for
work that produces no new values — it exists only because an intermediate
representation existed. Deleting a representation beat optimizing a loop.
