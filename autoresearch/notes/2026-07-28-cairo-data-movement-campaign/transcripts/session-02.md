# Session 02 — Narrowed witness planes (D2)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head `f7012f6d` (clean) at open.

Host: Apple M5 Max, 12 performance + 6 efficiency cores, seven other users.
Load average 2.59 at session open — the quietest window this campaign has had —
drifting to 16.5 by mid-session and back to 5 by the end. Every timing block
records its own `uptime`.

## The brief's premise had a hole in it, and finding it was the audit

The brief said the widths come from "the claim registry / column specs /
template programs" and warned me off per-program guessing. Campaign 1's D2
sketch was more specific: "chosen per column from the captured program's
declared value range."

There is no declared value range. `Program`
(`src/frontends/cairo/witness/program.zig:52-59`) is seven fields, all counts:
`insts`, `n_regs`, `n_inputs`, `n_cols`, `n_mult_tables`, `n_lookup_words`,
`n_sub_words`. The on-disk bundle format (`bundle.zig:37-76`) carries exactly
those plus a semantic hash. `air/official_claim_registry.zig`,
`air/template_library.zig` and the preprocessed column specs describe geometry,
not ranges. So the structural source the brief demanded does not exist in the
form it was expected in.

What exists is better, and it took reading `validate` to see it.
`Program.validate` (`program.zig:124-162`) rejects any program where
`inst.dst != next_register`, with `next_register` incrementing monotonically and
`deduce_call` advancing it by `inst.b`. That is an enforced **straight-line SSA
invariant**: no register is ever written twice, and no control flow exists. On
such a program a single forward pass is a complete and sound value-range
analysis. The width source is the opcode semantics themselves, in
`executeRow`'s switch — `u16_*` and `trunc16` mask to `0xffff`, `*_and` is
bounded by its immediate, `m31_eq` is boolean — plus one table fact:
`execution_tables.memoryValueLimb` masks every limb to `& 0x1ff`
(`execution_tables.zig:60` and `:65`), nine bits, for both the big and small
value paths. `ADDRESS_TO_ID_TABLE` limbs are encoded ids with a two-bit tag and
stay 32-bit.

That reframing is the increment's first real output: **the structural width
source is the bytecode's own dataflow, not a metadata field**, and it is
stronger than a declared range because it needs no one to maintain it.

I prototyped the pass in Python against the real bundle
(`vectors/cairo/official/witness_programs_v1.bin`, 64 programs, sha
`b2108615…`, byte-identical to the installed
`zig-out/share/.../witness_programs_v1.bin`) before writing any Zig. First pass,
with `table_limb` and `as_m31` both treated as opaque, said 2.2% of columns were
narrow — which would have been a negative audit. Adding the two precision fixes
that the source actually justifies (the nine-bit limb, and the fact that
`as_m31`/`m31_add`/`m31_mul` preserve small operand bounds) moved it to 40.2%.
The lesson is that the audit's verdict was a property of my abstraction's
precision, not of the code, and I nearly recorded a negative audit off a lazy
transfer function.

## Plane lifetimes, read before deciding scope

I traced every plane end to end before choosing what to narrow, because the
scope constraint from increment 2.1 is about consumer count.

- **Output columns.** Written at `program.zig:484`
  (`output_columns[inst.imm][row] = a`). Read exactly once, immediately, by the
  observer `base_trace.zig` `observeGenerated` → `Collector.capture`, which
  emits `[]M31` via `M31.fromCanonical`. Then `execution.deinit()` frees them.
  **One consumer, no retention.**
- **Lookup words.** Written at `program.zig:493` in column-major layout
  (`imm * row_count + row`) explicitly so interaction consumers avoid a
  transpose. Retained as `ProducerOutput.lookup_words`. Consumed by
  `interaction_source.LookupColumns` (the 387 ms
  `interaction_fraction_materialize`), `interaction_topology.compile`,
  `cpu_memory_multiplicity`, `fixed_trace`, and the resident/recovery path.
  **Five consumers, retained across stages.**
- **Sub words.** Row-major (`row * n_sub_words + imm`), retained as
  `ProducerOutput.words`, consumed by the gathered/compact input materializers.

Then the traffic math, weighted by the claim log sizes from a real memory-7m
proof (`add_opcode_small` at 2^22 = 4,194,304 rows):

```
output-plane traffic     2369.7 MB   savable  820.5 MB (34.6%)
lookup-word traffic      6841.1 MB   savable 2369.4 MB (34.6%)
sub-word traffic          993.2 MB   savable  240.3 MB (24.2%)
TOTAL                   10204.0 MB   savable 3430.2 MB (33.6%)
```

33.6% against a 15% gate. Positive audit, recorded before implementation.

And the ranking is inconvenient: **lookup words are 67% of the bytes and have
five consumers; output columns are 23% and have one.** I chose output columns,
knowing it capped the achievable effect, because the alternative was starting a
five-file width-tagging refactor with a full paired measurement still ahead of
me. I priced the lookup-word half in the note instead of half-building it.

## The before-shape said the premise was already shaky

One instrumented predecessor run on memory-7m:

```
witness_program_execute (all components)   605.3 ms
witness_base_lower                          74.7 ms
interaction_fraction_materialize           387.2 ms
                              region     1067.2 ms   (20.1% of 5308 ms prove)
```

10,204 MiB (10.70 GB) in 1,067 ms is 10.0 GB/s. The campaign's bandwidth-wall evidence
(increment 7's efficiency-core parity, increment 8's three-to-seven-worker
plateau) shows this region is not *core*-bound. It does not show it is running
at the bus ceiling, and 10.0 against ~40 GB/s says it is not. I wrote down before
measuring that I expected the byte-to-time conversion to be well under 1, and
that the increment's real product would be the conversion factor.

## Implementation

The one design question worth the time was the brief's "no per-row branching on
width in hot loops". A per-column width tag forces a branch at
`col_write`, because `inst.imm` is only known at run time. I could not find a
branch-free store-width selection on ARM.

The SSA invariant solves it. Since no register is rewritten inside a row, every
`col_write` can be **deferred to the end of the row** and still observe the same
value. So I partition the `col_write` instructions once per program into a
narrow list and a wide list, and the row loop ends with two straight-line write
loops. The width decision moves from per-row to per-program, exactly as asked,
and the interpreter's switch arm for `col_write` becomes a comptime-dead
`continue` in the planned path.

Pieces:

- `plane_widths.zig` — `columnBounds` (the forward pass) and `plan` (the split
  write lists + the per-column narrow predicate).
- `program.zig` — `NarrowColumns`, a `comptime planned: bool` on `executeRow`
  so the non-narrow path keeps its inline stores with no runtime test, the
  hoisted write loops, and `validateAllBuffers` accepting the split geometry
  (exactly one non-empty destination per column, all the same height).
- `component_executor.zig` — split `[]u32` / `[]u16` arenas and
  `Execution.plane(i)` as the width-tagged accessor.
- `base_trace.zig` `captureExecution` — the pre-extension widening boundary.

The PCS was not touched at all. Increment 2.1's constraint said not to carry
narrow planes past `prepareColumnsForCommitOwnedForBackend`, and honouring it
cost nothing: the lowering consumer already produced `[]M31`, so widening there
was free.

## The bug, and why it is worth a paragraph

First build: memory-7m `error: ConstraintsNotSatisfied`. all-opcodes was
byte-exact, so the analysis was wrong on something only memory-7m activates.

I trapped it rather than reasoned about it — `if (registers[write.reg] > 0xffff)
std.debug.panic(...)` in the narrow write loop — and got
`narrow overflow: col=12 reg=141 value=3854122` in `add_opcode_small`.

My Python prototype said that column's bound was `2147483646`. Same algorithm,
different answer. The difference is Zig's `@min`, which **narrows its result
type**: `@min(a, m31_max) * @min(b, m31_max)` was being evaluated in a 32-bit
type, and `(2^31 - 2)^2 mod 2^32 = 4`. An unbounded register acquired a bound of
4, and 4 fits in 16 bits.

A wrapped bound is always the unsound direction, which is what makes this class
of bug dangerous in a width analysis: it silently widens the admitted set. The
fix is explicit saturating u64 arithmetic (`+|`, `*|`, `<<|`) with `@as(u64, …)`
on the immediates. After it, memory-7m, arithmetic-2m and all-opcodes were all
byte-exact under `--verify` — `e3317e55…`, `25e5719f…`, `79ae76e1…`.

I would keep that trap behind a debug build in any future width pass. It found
in one run what I had spent fifteen minutes failing to find by reading.

## Mechanism

Paired instrumented, memory-7m:

```
witness_program_execute   605.345 -> 598.705   1.0111x
witness_base_lower         74.704 ->  69.901   1.0687x
base_witness_graph        714.672 -> 697.604   1.0245x
base_trace_build          763.738 -> 747.314   1.0220x   (-16.4 ms)
witness_output_allocate     0.036 ->   0.069   (the width pass + 2 allocs)
```

The arithmetic closes both ways:

- base lowering moves 1,184.9 MB in + 1,184.9 MB M31 out; narrowing the input
  side to 775.0 MB is 17.3% fewer bytes for 6.4% less time → **conversion 0.37**
- execution writes 5,102 MB of planes; removing 410 MB is 8.0% fewer bytes for
  1.1% less time → **conversion 0.14**

That asymmetry is the physically expected one. Stores retire into the store
buffer behind the interpreter's dependent vector work; the lowering loop is a
bare streaming pass with nothing to hide latency behind.

## Prove level, and one number I had to retract

A-B-B-A, 1 untimed warmup per arm, uninstrumented, both arms
`STWO_CAIRO_PREPROCESSED_CACHE=0`, predecessor = pristine `zig-out` copied from
clean `f7012f6d`.

```
memory-7m blocks 1-3 (load 3.0->12.1)
  1.0034  0.9435  0.9559    geomean 0.9673x  CI [0.8924, 1.0484]
memory-7m blocks 4-6 (load 6.2->11.1)
  1.0036  1.0071  1.0093    geomean 1.0066x  CI [0.9995, 1.0139]
arithmetic-2m (load 11.3->13.4)
  0.9914  1.0216  0.9849    geomean 0.9992x  CI [0.9520, 1.0487]
all-opcodes (load 10.1->12.0)
  0.9882  0.9887  0.9860    geomean 0.9876x  CI [0.9841, 0.9911]
```

The all-opcodes reading is the trap in this session. Three blocks, same sign,
interval `[0.9841, 0.9911]` disjoint from parity — by the campaign's own rules
that is a demonstrated 1.2% regression. It is not. Every one of those blocks ran
at load average above 10, and when I re-ran the same workload in a quiet window
(load 2.1-7.7) with a three-arm design it read `1.0001x`, `[0.9920, 1.0083]`.

That is the second time this campaign a loaded window has produced a
confidently wrong tight interval (increment 2.1's arithmetic-2m was the first,
and it was at least obviously noisy). A tight CI under load is not evidence of a
small true effect; it can be evidence of a *stable systematic* one — thermal or
scheduling asymmetry between the arm that runs first and the arm that runs
second within a block, which A-B-B-A cancels only if the drift is linear.

## Three-arm decomposition

I wanted to know whether the hoisting was eating the byte saving, so I built a
third arm identical to the candidate with the width predicate forced to `false`:
hoisted writes, no narrow planes. A-H-B-B-H-A per block, all-opcodes, quiet:

```
block 1: A 1253.84  H 1257.57  B 1255.89
block 2: A 1268.91  H 1274.66  B 1263.94
block 3: A 1298.35  H 1309.00  B 1300.83
hoisting tax  A/H  0.9948x  [0.9882, 1.0014]
narrowing gain H/B 1.0054x  [0.9963, 1.0145]
total         A/B  1.0001x  [0.9920, 1.0083]
```

Hoisting costs about half a percent, narrowing returns about half a percent, and
both intervals touch parity.

memory-7m, 4 blocks, load-gated start (waited 460 s for the host) that still
drifted 3.5 → 15.1:

```
block 1: A 6374.34  H 6389.51  B 6259.30
block 2: A 6755.30  H 6779.59  B 6772.52
block 3: A 6903.52  H 6992.20  B 6912.29
block 4: A 6799.05  H 6948.76  B 6775.52
hoisting tax  A/H  0.9899x  [0.9758, 1.0043]
narrowing gain H/B 1.0147x  [0.9976, 1.0321]
total         A/B  1.0045x  [0.9894, 1.0198]
```

I nearly wrote this up as "hoisting is eating the gain". It is the right shape
for that story: 1.0147x of narrowing against 0.9899x of hoisting. But 1.0147x is
98 ms and 0.9899x is 68 ms, and the mechanism the instrumented spans actually
measure is **11.4 ms**. Decomposing an 11 ms effect into two ~80 ms components
off a series with ±9% same-arm spread is not decomposition, it is pattern
matching on noise.

So I tested it instead of writing it up.

## The writer question, settled

Fourth arm: same narrowing, width selected by an ordinary **per-row branch** on
the plane tag inside the `col_write` arm, no hoisting. This deliberately breaks
the brief's "no per-row branching on width" constraint — as a diagnostic, not a
candidate — because if the constraint was costing the increment its result, that
is worth knowing explicitly rather than inferring. Byte-exact, `e3317e55…`,
`--verify` true.

A-P-B-B-P-A, 4 blocks, load 4.8-11.2. Tightest series of the session; the
predecessor's own samples span ±3.7%:

```
block 1: A 5674.96  P 5716.23  B 5673.37
block 2: A 5828.07  P 5825.97  B 5834.77
block 3: A 5960.31  P 5977.08  B 5992.89
block 4: A 5973.16  P 6015.09  B 6058.18
branch          A/P  0.9958x  [0.9901, 1.0016]
hoist           A/B  0.9949x  [0.9847, 1.0052]
hoist vs branch B/P  1.0009x  [0.9912, 1.0108]
```

`B/P = 1.0009x`, interval tight around parity. **The two writer designs are
indistinguishable**, which retires the 1% hoisting-tax reading as noise and
settles that the write structure is not the limiter. Both narrowing arms sit at
`0.995x` against the predecessor in the cleanest window I measured all session,
against a mechanism the spans put at +0.19%.

The useful conclusion is negative and clean: **the write restructuring is not
what limits the lever, and neither is any implementation choice available inside
D2.** The limit is the conversion factor, and I have now closed the one
alternative explanation rather than leaving it as a recommendation.

## Why I am returning this as rejected rather than pressing on

Applying the measured conversions to the full census — lookup words write side
~19 ms, lookup words read side ~25 ms, sub words ~5 ms, on top of the 11.4 ms
measured — the complete D2 lever projects to about **61 ms on a 5,860 ms
memory-7m proof: 1.011x**. Below the 1.02x bar with all three plane classes
narrowed and every consumer converted.

Worse for the lever, it is below the amplitude of the change's own side effects.
The paired phase split shows the candidate at `composition_evaluation` +21.7 ms,
`main_trace_commit` +11.0 ms, `interaction_trace_build` +8.6 ms — stages
narrowing cannot touch, moved by the different heap layout that two extra
allocations per component produce. When the incidental layout term is larger
than the mechanism term, finishing the lever cannot produce a defensible
acceptance no matter how carefully it is measured.

So the honest statement is not "D2 is too small to implement" but **"D2's
premise is wrong: this region converts bytes to time at 0.14-0.37, not near
1."** Increments 7 and 8 established the region is not core-bound. Nobody had
tested whether it is bus-bound. It is not — it runs at 10.0 GB/s against ~40.

## Verification

- `test-cairo-cpu-product test-cairo-frontend test-stwo-prover` at
  `-Doptimize=ReleaseFast`: exit 0, `stwo-cairo-cpu closure: PASS`.
- The first build failed 12 of 20 frontend tests —
  `recorded graph mismatch component=add_opcode ordinal=0 column=4` — because
  `conformance/base_execution.zig` `compare` read `execution.output_columns`
  directly and got an empty slice for every narrow column. Teaching it
  `Execution.plane` fixed all 12. That leak into the conformance harness is a
  real cost of the split representation and is recorded as such.
- Official verifier, revision `82f21252`: memory-7m `verified: true`
  `e3317e55…`; arithmetic-2m `verified: true` `25e5719f…`.
- Metal, `-Dmetal-core-aot-bundle=/private/tmp/cairo-quotient-baseline-v2/aot-bundle`,
  identity `core-aot-manifest-sha256=0bc89238…`: arithmetic-2m `25e5719f…`,
  `metal-pcs`, `accelerated_without_fallbacks`, 74 dispatches,
  `cpu_fallbacks: 0`, `--verify` true. No Metal-side change was needed.
- `STWO_ZIG_WORKERS=1` arithmetic-2m: `25e5719f…`, `--verify` true.
- Known pre-existing, not chased: merkle-worker-stress `blake_deep`
  `InvalidNRounds` (did not surface), stale untracked `vectors/`/`reports/`
  artifacts, corpus `pedersen.json` `SegmentPointerOverflow`.

## What I did not do

- Lookup words and sub words. Priced, not built. Five consumer sites for the
  lookup feeds against the increment's budget, and the projection says the
  finished lever does not clear the bar anyway.
- No branch-variant measurement on all-opcodes or arithmetic-2m. memory-7m is
  where the writer cost would show, and it did not.
- No attempt to isolate the heap-layout term by forcing identical allocation
  addresses. That would be the only way to measure a 16 ms mechanism cleanly at
  prove level, and it is worth doing *for D1*, which will have the same problem
  at a larger amplitude.
- No seven-workload portfolio.

## Commits

- `4b106372` the narrowing, byte-exact on all three workloads
- the conformance-harness fix
- the revert
- note and this transcript
