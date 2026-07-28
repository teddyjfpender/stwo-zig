# Session 07 — increment 3.6: fused composition kernel pricing

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Head at start `bcf3ad09`, clean. Raw data `/private/tmp/i36/`.

## The first ten minutes rewrote the increment

I was told to implement the fused emission in the codegen. It is already there,
and it has been since `1dc983e3` (2026-07-17) on `main`:
`eval_codegen.generateFusedKernel`, `fusedKernelName`, `fusedKernelHash`,
`fusionGroupEnd`, `hybridFusionPartition`, and a `--fusion-cap` /
`--experimental-hybrid-source-diagnostic` surface on the `metal-eval-source`
tool. Note §6.2's "fusion requires a source artifact and is therefore not in the
asset" is true about the *metallib* and was read forward as though the emission
itself were missing. It is not; only the compiled artifact is.

So item 2 collapsed into "verify and price what exists", which is the more
useful increment anyway, and it freed most of the budget for item 3. The one
thing I did add to the codegen is a probe surface, `generateFusedKernelUncapped`
plus `fusedKernelNameUncapped`, because the 4,096-operation
`max_fused_instruction_cap` turns out to be a policy number with no recorded
provenance and no stated relation to any device limit, and you cannot ask "where
does the compiler actually stop" through an entry point that refuses first.

## The cheapest experiment in the increment cost one command

Before writing any test I ran the existing tool across the cap range:

    metal-eval-source ... --fusion-cap 512   dispatches=279->279
    metal-eval-source ... --fusion-cap 1024  dispatches=279->168
    metal-eval-source ... --fusion-cap 4096  dispatches=279->77

**The shipping default cap fuses nothing.** My first explanation for that was
wrong and the census caught it: I asserted the smallest *part* exceeded 512 and
the test failed, reporting `ops_per_part_min=28`. The cap bounds a *group's* sum,
and the smallest adjacent pair in the bundle is 574 operations. Same conclusion —
the fused emission has been dead code at its own default for eleven days — but
arrived at by an assertion that failed rather than by a sentence that sounded
right. That is worth a line in the note independently of anything else I
measured.

## The number that turned the increment around

I built the projection out of two measured inputs rather than one: each
workload's own proof `claim` for per-component log sizes, and the authenticated
bundle for parts per component (log-size-independent per §6.2). Then
`rows x parts x 5.6 ns`:

    arithmetic-2m   row_parts 15,612,032 -> 87.4 ms   vs 435.7 ms host
    memory-7m       row_parts 41,332,096 -> 231.5 ms  vs 1,219.4 ms host

Unfused. Five times faster than the host stage, with the artifact that exists.

That contradicts the headline I inherited, so I went looking for my own error
and found instead the error in the inherited number. Increment 3.5 compared
`partial_ec_mul_window_bits_18` — 2^21 rows, 41 parts, 484 ms — against
arithmetic-2m's 435.7 ms host composition stage. **That component is not in
arithmetic-2m.** It is not in memory-7m, all-opcodes or pedersen-aggregator
either; it is an EC-multiplication component. One SN2 component's 86M row-parts
was being priced against a workload whose entire composition is 15.6M
row-parts. The comparison was cross-workload, and the conclusion drawn from it
— that the unfused library cannot win the stage — does not follow.

The corollary is the one that decides this increment: across the four portfolio
workloads I have claims for, **no component has more than 2 parts.** 41 and 90
parts are real, and they are entirely outside the portfolio. So the maximum
fusion available to the workloads that define the bar is 31 dispatches to 29 on
arithmetic-2m and 34 to 32 on memory-7m.

I would rather have found this by being clever, but I found it by insisting the
projection be built from a live census instead of from one component's number,
which is a habit and not an insight.

## The measurement I added because of it

3.5's four components were selected structurally (smallest, largest by
rows x constraints, most parts, largest arithmetic). Every one of the interesting
three is an EC or blake component. So the cost model was calibrated entirely on
shapes with 500-1,500 operations per part, and then applied to a portfolio whose
work is in `add_opcode_small`, `range_check_20` and `assert_eq_opcode`. I added
those three as a `live-dominant` role. `add_opcode_small` in the SN2 bundle sits
at `trace_log = 21`, which is *exactly* arithmetic-2m's claimed log size for it,
so 53.7% of arithmetic-2m's composition work is measured here at its real size
with no extrapolation at all.

## What byte-exactness had to mean here

I did not re-run the host reference on the large components. The chain is
`fused == per-part` (this file, every row, every coordinate, on the same arena)
composed with `per-part == host` (the 3.5 smoke, same four components, same fill
seeds, same layout, still in the same test closure). Both links are exercised in
one `metal-test` run. I also anchored fused output to the host *directly* on the
small control and on the smallest multi-part component, so the composition is
not the only evidence. Duplicating the 2^21-row scalar-lane host reference would
have added a quarter-hour to the closure to re-establish a link that already
runs beside it.

## The ceiling is the compiler, and it bit me

My first sweep had no pre-compile ceiling. `MTLCompilerService` went to 100% of
a core and stayed there for more than seven minutes on one group — a five-part,
roughly ten-thousand-operation fused function — without completing. A Metal
compile cannot be interrupted once handed off, so a test that lets the sweep
climb freely is a test that hangs. I rebuilt the sweep to decline *before*
compiling anything above the codegen's own 4,096-operation ceiling, to print an
attempt line before each compile so a hang is attributable, and to stop climbing
once one compile exceeds a 20-second budget.

So the honest answer to "what is the real fusion ceiling" is not a register
count or a threadgroup-memory figure. It is that the Metal front end's cost on
one enormous straight-line QM31 function grows fast enough that the ceiling is
practical, not architectural — and, given that the portfolio never exceeds two
parts, finding its exact location would be spending budget on a case no
workload has.

## The dividend I did not plan

The 3.5 smoke and my pricing sweep run in the same `metal-test` process. The
smoke dispatches the AOT metallib; mine dispatches a JIT library from the same
codegen source. So the closure handed me a controlled AOT-vs-JIT comparison for
free, and it says the two compilers do not produce equivalent code:
`partial_ec_mul_generic` 412.45 ms AOT against 135.18 ms JIT, `add_opcode` 46.88
against 28.44, and `partial_ec_mul_window_bits_18` essentially equal. I had
written this up as an unexplained cross-run discrepancy and had to rewrite it as
a measurement, which is the better problem to have. It also forced me to state
the go/no-go on two bounds rather than one, because a product hook loads the AOT
library and every price I measured is JIT. The stage is worth moving on either
bound; whether it clears §2.3's 3.13x requirement depends on which one holds, so
that experiment is now the first item in the recommendation instead of a footnote.

## Commits

- part-structure findings: the census test, the uncapped probe surface, and the
  cap-sweep evidence.
- the byte-exact fused pricing sweep.
- pricing evidence, the projection, and this note.
