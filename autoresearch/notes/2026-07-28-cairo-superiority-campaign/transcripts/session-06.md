# Session 06 — Strip-mining the Cairo AIR interpreter (R6b)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head `6e3daaf2` (clean).

Host: 18 cores, `hw.l2cachesize` 8 MB. Load average 3.37 at session open,
4.40 / 3.95 during the paired probe, 6.00 at the audit close. Nothing else of
mine was running during timed work.

## What I was asked and what the gate meant

Increment 5 handed me a specific hypothesis with a specific kill switch. The
composition stage is interpreter-bound at ~22 cycles per interpreted
instruction; strip-mining amortises the opcode dispatch over `T` four-row
groups; but the dominant component's extension register file is 31.5 KB at
`T=1`, so `T=4` puts 126 KB of register file (144 KB counting the base
registers) against a 128 KB L1D. The gate: sweep `T` at S1 first, and if
nothing beats `T=1` by 1.15x cycles, stop and spend the budget on the fallback
audit.

I want to record that I read the gate as genuinely binding before I ran it,
because the outcome turned on believing the number rather than arguing with
it.

## Building the S1 harness

First the implementation, because a `T` sweep on live sources needs the tiled
loop to exist in the repo. `evaluatePartRangeTiled(comptime tile, ...)` in
`src/frontends/cairo/proving/air/simd_evaluator.zig`: register files sized
`max_*_regs * tile`, laid out register-major so slot `t` of register `r` is at
`r * tile + t` and an instruction's `tile` values are contiguous; each opcode
arm becomes `inline for (0..tile)`. `evaluatePartRange` dispatches through
`inline switch` on `chooseTile(program)`, which reads `max_base_regs` and
`max_ext_regs` from the program header and picks the largest specialised width
fitting a byte budget. Residual groups fall through to the `tile == 1`
instantiation, guarded by `if (comptime tile > 1)` so `tile == 1` does not
recursively instantiate itself.

Byte-exactness is structural rather than argued: slot `t` reads operands at
`a * tile + t` and `b * tile + t` and writes `dst * tile + t`, so a value never
crosses a slot boundary, and `(dst - a) * tile == t' - t` with `|t' - t| < tile`
forces `dst == a, t == t'` — no cross-slot aliasing even when a destination
register is also an operand. Output rows are accumulated ascending exactly as
before. The one reordering I allowed is hoisting `PackedQm31.splat` of the
constraint coefficient out of the tile loop in the root fold; it is the same
value `tile` times.

Wiring the harness took two false starts worth recording. `stwo-prof zig
isolate --import` builds one module, and rooting that module at
`simd_evaluator.zig` fails with *import of file outside module path* because
the interpreter reaches `../../witness/eval_program.zig`. Rooting it higher
needs the frontend's real dependencies, so I read
`build_support/graph/modules.zig` and reproduced the actual graph in the
harness `build.zig` — `stwo_core` ← `stwo_backend_contracts` ← `stwo_prover_impl`
← `cairo_frontend`, with `cairo_frontend` self-imported under its own name.
That means the sweep compiles the live working tree on every run, which is the
point of the tool. I also had to `pub` the `eval` import in
`simd_evaluator.zig` so the harness names the same `Program` type the
interpreter compiles against — otherwise the harness's `Program` and the
interpreter's are distinct types.

Second note: `stwo-prof zig run --json` writes `counters.json` into the scratch
dir rather than emitting JSON on stdout. My first sweep loop parsed stdout and
produced twelve identical decode errors.

## The synthetic program

Structural match, not name match. From increment 5's census of the dominant
arithmetic-2m component: 278 base instructions of which 63 are mask reads, 493
extension instructions, 32 constraint roots, two distinct mask immediates, SSA
registers so `max_base_regs`/`max_ext_regs` equal the instruction counts. That
reproduces the 36,000 B/slot register file that the whole question is about.
The opcode mix follows the census's dynamic ratios (about 20% ext `param`, 5%
ext `constant`, multiplies dominating the rest). Reads are placed first so
every later operand is written, which `Program.validate` enforces.

Evaluation domain log 18 over trace log 17, so the 63 columns are 512 KB each
and 32 MB total — past this host's 8 MB L2, so gathers behave like the real
thing rather than sitting in cache and flattering the tiled arms. 2^16 rows per
call, one op = one four-row group, so instructions/op and cycles/op are
directly comparable across `T`. The runtime seed is threaded through
`parameters[0]`, which changes values without changing a single opcode or
operand.

## The sweep

Three rounds, twelve iterations. Dominant shape:

```
round1 T=1 ns/op 2173.203 instr/op 50067.231 cycles/op 9399.253 ipc 5.327
round1 T=2 ns/op 2119.765 instr/op 44646.106 cycles/op 9162.937 ipc 4.872
round1 T=4 ns/op 2105.029 instr/op 40886.870 cycles/op 9101.443 ipc 4.492
round1 T=8 ns/op 2096.561 instr/op 39337.828 cycles/op 9066.679 ipc 4.339
round2 T=1 ns/op 2194.994 instr/op 50067.467 cycles/op 9483.874 ipc 5.279
round2 T=2 ns/op 2106.219 instr/op 44645.743 cycles/op 9099.995 ipc 4.906
round2 T=4 ns/op 2058.936 instr/op 40887.020 cycles/op 8906.474 ipc 4.591
round2 T=8 ns/op 2094.436 instr/op 39337.969 cycles/op 9059.265 ipc 4.342
round3 T=1 ns/op 2189.429 instr/op 50067.149 cycles/op 9458.772 ipc 5.293
round3 T=2 ns/op 2134.568 instr/op 44645.634 cycles/op 9226.923 ipc 4.839
round3 T=4 ns/op 2056.498 instr/op 40886.929 cycles/op 8887.139 ipc 4.601
round3 T=8 ns/op 2091.135 instr/op 39337.789 cycles/op 9049.404 ipc 4.347
```

Means: cycles/op 9447.3 / 9163.3 / 8965.0 / 9058.4 for T = 1/2/4/8. Best
1.054x at `T=4`. Gate is 1.15x.

Before accepting that I wanted to know whether the register-file cliff was
doing the killing, because if it were, the fix would be a smaller tile on the
big components and a large tile everywhere else — still a viable increment.
So I built the same harness at 70 base / 120 extension instructions, an 8,800
B/slot register file that keeps even `T=8` (70 KB) inside L1D:

```
round1 small T=1 ns/op 715.486 instr/op 16107.073 cycles/op 3123.096 ipc 5.157
round1 small T=2 ns/op 689.547 instr/op 14601.414 cycles/op 3004.027 ipc 4.861
round1 small T=4 ns/op 665.891 instr/op 13641.770 cycles/op 2899.803 ipc 4.704
round1 small T=8 ns/op 659.423 instr/op 13449.629 cycles/op 2867.099 ipc 4.691
round2 small T=1 ns/op 717.073 instr/op 16106.926 cycles/op 3120.816 ipc 5.161
round2 small T=2 ns/op 692.513 instr/op 14601.574 cycles/op 3009.968 ipc 4.851
round2 small T=4 ns/op 667.186 instr/op 13641.967 cycles/op 2901.770 ipc 4.701
round2 small T=8 ns/op 660.130 instr/op 13449.732 cycles/op 2869.755 ipc 4.687
round3 small T=1 ns/op 722.533 instr/op 16107.036 cycles/op 3143.554 ipc 5.124
round3 small T=2 ns/op 692.575 instr/op 14601.356 cycles/op 3012.855 ipc 4.846
round3 small T=4 ns/op 668.265 instr/op 13641.943 cycles/op 2902.341 ipc 4.700
round3 small T=8 ns/op 659.929 instr/op 13449.691 cycles/op 2866.920 ipc 4.691
```

1.091x at `T=8`. Still short.

That control is the informative half of the sweep. In the most favourable
cache regime available, deleting 16.5% of the machine instructions bought
9.1%; on the real shape, deleting 21.4% bought 5.4%. The cliff exists — `T=8`
loses 1% to `T=4` on the big shape and gains 1% on the small one — but it is a
second-order term. The first-order fact is IPC: 5.30 at `T=1` falling to 4.34
at `T=8`, tracking the instruction count almost exactly. At IPC above 5 on an
8-wide core the dispatch instructions were being issued in slack next to the
vector work. They were already free. Increment 5's ~22 cycles per interpreted
instruction is vector-issue and dependency latency, and no amount of loop
interchange reaches it.

This also retro-explains increment 5's rejected row-invariant hoist: 24.3% of
interpreted instructions removed for 1.01x. Two independent mechanisms have
now removed roughly a quarter and a fifth of the work for ~1% and ~3%. The
loop is not instruction-count-bound, and I think that closes the family.

## One confirmatory whole-prover probe, then stop

The gate had fired, so I did not run the acceptance portfolio. I did run two
A-B-B-A blocks on arithmetic-2m, because the binary was already built and
byte-exact and the cost was two minutes — and because a whole-prover number
that disagreed with S1 would have meant my harness was lying, which is worth
knowing either way.

```
block1 pred comp 371.468 prove 2490.966  cand comp 361.335 prove 2472.034
       cand comp 361.463 prove 2517.963  pred comp 373.814 prove 2557.877
block2 pred comp 376.144 prove 2562.225  cand comp 363.847 prove 2561.374
       cand comp 372.823 prove 2575.035  pred comp 386.506 prove 2601.989
```

Block ratios 1.0311x and 1.0353x on composition, pooled 1.0332x; prove
1.0118x / 1.0054x, pooled 1.0086x. Acceptance was 1.10x composition or 1.02x
prove. Both fail, and 1.033x is what S1's 1.054x predicts once the stage's
non-interpreter residue is included. The harness read the machine correctly.

All eight samples digested `25e5719f…`. Predecessor was the pristine `zig-out`
tree copied whole from `6e3daaf2` before I touched anything; outputs deleted
before every run (the CLI refuses to overwrite, which silently produced
duplicate numbers for increment 5 and would have for me).

Preserved at `c02ce7f1`, reverted at `e130f7cb`. `git diff 6e3daaf2` is empty.

## Fallback: base-witness graph attribution

Roughly 40 minutes left, and the fallback scope was pool-scale attribution of
`base_trace_build`. I did not need instrumentation — the prover already emits
a `base_witness_graph` subtree with per-component leaf timings, so the whole
audit is reading existing stage profiles at `STWO_ZIG_WORKERS` 18 / 8 / 4 and
asking which buckets move.

The pedersen leg is not available: `pedersen.json` from the benchmark corpus
fails at `error: SegmentPointerOverflow` in the adapter, before proving. I did
not chase it; arithmetic-2m served as the second workload.

memory-7m `witness_program_execute` 1704.918 → 1039.870 → 593.221 ms for W =
4 / 8 / 18. Everything else is flat to within 3%: 94.1 / 93.9 / 93.9 outside
the graph, 73.4 / 72.5 / 70.7 for `witness_base_lower`, 15.0 / 15.3 / 14.4
materialize, 48.8 / 49.4 / 48.0 unattributed per-component residue.
arithmetic-2m shows the same shape at a quarter the size.

Four things fell out.

`witness_output_initialize` is 19 µs on memory-7m and 12 µs on arithmetic-2m.
The brief's three-way split — execution vs output init vs memory tables — is
really two-way; increment 2 already killed output init and there is nothing
left there to budget for.

The flat buckets sum to 231.4 ms on memory-7m and 79.9 ms on arithmetic-2m,
28.0% and 28.8% of `base_trace_build` at W=18. Two workloads 4.5x apart
agreeing to 0.8 points makes that structural. And the largest single flat
bucket is the 94.1 ms *outside* `base_witness_graph` that no probe attributes
at all — 11.4% of memory-7m's stage, completely dark. That is where I would
put the next instrument.

Program execution parallelises at 64% efficiency on memory-7m and 52% on
arithmetic-2m. The component nodes sum to about their parent (669.2 of 730.6
ms across the top six of twelve), so components run as a serial chain, each
internally pool-parallel — and one link dominates: `add_opcode_small` is 67.6%
of program execution on memory-7m and 95.9% on arithmetic-2m. On arithmetic-2m
the other eight components are noise. So the lever for R2 is intra-component
row-range parallelism in the witness writers, not more components in flight.

Last, an incidental correctness finding I nearly missed. `STWO_ZIG_WORKERS=1`
fails with `ConstraintsNotSatisfied` — on arithmetic-2m and memory-7m, on the
pristine `6e3daaf2` binary and the reverted head alike, while
`STWO_ZIG_WORKERS=2` proves and digests `25e5719f…`. Pre-existing, nothing to
do with this increment. `component.zig:170-174` returns
`evaluation.evaluateRange(0, row_count, false)` with `additive` hardcoded
false and never touches `column.next_fresh_index`, while the parallel path at
180-199 derives `direct_store` from that index, passes `additive =
!direct_store`, and writes it back. A second component sharing a composition
column therefore clobbers the first. The `row_count < parallel_row_threshold`
branch on the line above has the same hazard. Audit-only scope, so recorded
and not fixed.

## What I did not do

- No memory-7m or all-opcodes paired blocks for the strip-mined candidate.
  The S1 gate had already closed it and the brief says stop.
- No fix for the single-worker defect. Out of the fallback's audit-only scope,
  and it is correctness on a non-default configuration, not throughput.
- No new instrumentation for the 94 ms dark bucket. That is the recommendation,
  not this increment's work.
- No Metal or Rust-verifier rerun. The reverted tree is bit-identical to
  `6e3daaf2`, whose record already carries both against these digests.

## Commits

- `c02ce7f1` the strip-mined interpreter, byte-exact, measured 1.054x at S1 and
  1.033x whole-prover (reverted at `e130f7cb`, preserved for the record)
- `e130f7cb` the revert
- note and this transcript
