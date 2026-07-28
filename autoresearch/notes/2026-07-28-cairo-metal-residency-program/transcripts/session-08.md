# Session 08 — increment 3.7: the AOT-vs-JIT verdict, and the ABI fact

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Head at start `06cf0154`, clean. Raw data `/private/tmp/i37/`.

## The blocking experiment cost twelve minutes and it was the cheap half

I was told the AOT-vs-JIT gap was the program's most consequential open item and
to spend half an increment on it. It took two experiments and neither needed the
device for the first one.

The staleness hypothesis is decidable offline. The metallib was committed on
2026-07-11 and the emitter has changed six times since, so I extracted the tree
at `7123cc22` with `git archive` — no worktree, nothing touching `.git` state —
built `metal-eval-source` there and at head, and ran both over the same
`sn_pie_2_composition.bin`. 4,306,723 bytes against 4,322,603 for the same plan
hash and the same 271 programs. My first reaction to a 15,880-byte delta was that
I had found it. I had not: `diff` was 1,863 lines of `acc` becoming `part_acc`,
and `sed 's/part_acc/acc/g'` makes the two emissions byte-identical. An
identifier rename from the fusion work. That is the whole difference between the
source CI compiled and the source we emit today.

I record that as a near-miss rather than a clean result, because a 15 KB delta on
a 4 MB file *looks* like a real code change and I was one step from writing
"stale bundle confirmed, blocked on CI".

Then the compile options, which I checked by reading both producers rather than
by inferring from behaviour: CI uses `-std=metal3.1 -fno-fast-math`, the runtime
sets `mathMode = MTLMathModeSafe` and `languageVersion = MTLLanguageVersion3_1`.
Same language, same math mode, default optimisation both sides. No asymmetry.

## The in-process comparison, and the number that made me stop looking

So I built the interleaved test: both libraries from one runtime, one arena per
component filled once, pipelines prepared once outside the timed region, one
warmup per arm, A-B-B-A over two blocks, every sample printed, and the two arms'
coordinate planes byte-compared before and after every block.

    blake_round_sigma        AOT/JIT 0.992x
    add_opcode                       1.005x
    add_opcode_small                 1.143x
    partial_ec_mul_generic           1.000x

`partial_ec_mul_generic` is the 3.05x outlier. It comes out at 1.000x. And
`add_opcode_small`'s 1.143x is one 59.8 ms sample in an arm whose other three are
38.08-38.10 — I kept it in the mean rather than trimming it, and reported the
minimum beside it, because trimming an outlier in the arm that favours my
conclusion is exactly the move that should not be available.

I then went looking for what 3.6 *had* measured, because refuting a number
without explaining it leaves it free to come back. I added reporting of the
warmup samples I was already discarding. `add_opcode`'s AOT warmup is 28.4404 ms.
3.6 records 28.44 as its JIT price for that component. That is not a coincidence
I need to argue about — `gpu_ms` is `GPUEndTime - GPUStartTime`, so the first pass
over a freshly CPU-filled multi-gigabyte buffer charges page residency to
whichever dispatch runs first, and neither 3.5 nor 3.6 warmed up. The whole table
was warmup on both sides.

The consequence runs the other way from what everyone expected. Steady state is
*faster* than 3.6's JIT bound: 4.54 ns per row-part rather than 6.82. I had been
sent to find out whether the central number needed dividing by three and it
needed multiplying by 1.4.

## Then I read the kernel I was about to hook up

With ~95 minutes left I started the arena extension, and the first thing I did
was read `trace_value` in the emitted preamble to write the offsets correctly.

    uint target = offset == 0 ? row : offset_circle(...);
    return arena[arena[args.trace_offsets + global] + target];

`row` runs over the evaluation domain. So a column in the arena is `2^eval_log`
words. Then I went to find where the product's columns come from —
`pcs/scheme_views.polynomials`, straight off the committed trees, `log_size =
column.log_size` — which is `2^trace_log`, and `component.zig:355` therefore
passes the host evaluator `shift_amt = 2`, not 1.

I sat with that for a few minutes because it contradicted my brief, which says
placing the interaction columns is "placement, not LogUp computation" and treats
the base columns as already resident. Both halves are true and neither is
sufficient: the columns are the right *values* in the right *place* and the wrong
*length*. This is increment 3.5 §1's corollary — 3.5 proved `shift_amt = 1` is the
identity and never said out loud that it is the identity only for a column stored
at evaluation-domain length, which is a property of the test's arena and not of
the product's.

I could have written the arena extension anyway and discovered this when the
first digest came out wrong. What stopped me was that 3.5's own transcript
records the same class of mistake — a silent wrong answer from an unbounded slice
— and the lesson it drew was to make the convention observable before building on
it.

## Pricing the two ways out rather than picking one

Option A materialises a lifted copy; option B teaches the codegen the shift. B is
obviously better — no copy, no extra memory, reads the arena that is already
page-aligned — and it needs a metallib this host cannot compile
(`xcrun --find metal` fails; CommandLineTools only). So the useful thing I could
do with the remaining budget was make A a *measured* fallback rather than a
guess, and hand the next increment a decision instead of a dilemma.

The lift is byte-exact against the host reading trace-domain columns at the
product's own shift, on a 1-part control and on `bitwise_builtin`'s 5 parts —
which is where the accumulator and `rc_base` conventions live, the same reason
3.6 leaned on that component.

The price nearly fooled me twice in opposite directions. In the Debug test
closure the lift is 576 ms against a 28 ms dispatch, i.e. 20x, and for about a
minute I believed option A was dead. It is 1.8 GB/s, which is absurd for a
streaming pair-duplication, so I wrote a standalone ReleaseFast benchmark: 89.84
GB/s, 50x faster, 11.5 ms for the same work. Debug artifact. I put that
explicitly in the note as a number not to quote, because the test prints it and
someone will read it.

With the real throughput, option A is a 19-28% surcharge and the stage still
comes out 4.60-5.87x faster than host single-threaded. So the ≥ 2.0x gate this
increment reinstated is clearly reachable on *both* options — which is the one
thing I can say about the gate, since without a hook there was nothing to measure
it on.

## What I did not do, and why I am saying so plainly

No hook. No arena extension. No proof produced, therefore no digest comparison,
no official verifier run, no `STWO_ZIG_WORKERS=1` lane, and the corrupt-metallib
fail-closed test is still unreachable for exactly the reason 3.6 left it
unreachable: the product does not load the composition metallib yet. I ran
`package-workspace`, `metal-check` and the pre-commit conformance gates, and I
listed the rest as unrun rather than implying otherwise.

The honest shape of this increment is: the blocking item is closed and closed in
the program's favour; the item it was blocking turned out to have a prerequisite
nobody had costed; and both are now measured. I would rather hand that forward
than a hook that produces the wrong digest.

## Commits

- `8d02ba92` — the AOT-vs-JIT verdict: the interleaved parity test, the offline
  rename-equivalence finding, and the emission-shape assertion that keeps it
  honest.
- `377ec3bd` — the ABI finding: the lifting map pinned against `Poly.at`, the
  byte-exact bridge, the column census, and the measured price of both options.
- this note and transcript.
