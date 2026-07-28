# Session 09 — increment 3.8: the Option-A device composition hook

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Head at start `c7237d72`, clean. Raw data `/private/tmp/i38/`.

## The brief was right about everything except which bundle the product proves with

I inherited four increments of unusually good preparation. 3.5 had verified the
eleven-offset `EvalLayout` ABI byte-exact on four real components including a
41-part and a 90-part one. 3.6 had priced the marginal cost and killed the fusion
prerequisite. 3.7 had killed the AOT-vs-JIT discount, found the eval-domain
column-length fact, and verified the lift byte-exact against the host at the
product's own `shift_amt = 2`. The brief handed me a cost model, a per-dispatch
floor, a throughput number with an explicit warning not to quote the Debug
artifact, and a gate. Nothing about the hook's design was in doubt.

So I built it, in the shape the brief described, and it declined.

## The design, and the one place I disagreed with the obvious route

The obvious hook is `B.computeCompositionEvaluation` — the Metal backend already
implements it and `computeCompositionEvaluationForBackend` already dispatches
through the proof's backend *type*, which is a genuinely good isolation property.
It cannot work here: that function lives in `src/backends/metal` and would have to
interpret a captured Cairo AIR program to do anything. Inverting that dependency
would be the worst change in the tree.

The second obvious route is a per-component hook on the Cairo `Component`. I
started down it and stopped when I read `component_parallel.compute`: components
are evaluated *concurrently*, one per pool worker. A per-component device hook is
therefore called from N threads at once, and the arena and the metallib are
per-stage objects. I would have had to serialize with a mutex and would have lost
the ability to parallelise the lift, because spawning pool work from inside a pool
worker is the one thing that file's doc comment warns about.

So the hook is whole-stage and carried on `ProveOptions`, which is per-call rather
than process-global, and the accumulator loop lives in the *frontend* rather than
in the integration. That last choice is the one I would defend hardest.
Byte-exactness of the composition polynomial is not a property of the kernels —
3.5 and 3.7 already settled the kernels. It is a property of
`DomainEvaluationAccumulator.columns`, which hands out coefficient powers from the
tail of the powers vector, and of the fact that `component_parallel.compute` walks
`power_cursor` down exactly the order the sequential path walks `columns` up. I
wanted that one assignment written once, next to the host evaluator it has to
agree with, driving *both* device and host components — because then a
per-component refusal cannot shift the coefficients of its neighbours. Putting the
loop in the integration would have meant two implementations of the thing that
actually decides correctness.

The lift I did not write. I copied 3.7's routine, including its per-column shift
taken from the same `ResolvedColumn.shift_amt` the host reader is handed, because
that is what "byte-exact verified" is worth. I parallelised it over the existing
pool with a striding worker and left the timing span in.

## Spot-proving early was the brief's best instruction

The brief said to spot-prove all-opcodes before any measurement. I did, and got
`79ae76e1ac0c48b1` — the campaign digest, unchanged — under thirty-odd lines of
`Missing Metal function stwo_zig_eval_f121becb27a01b51`. Both halves of that were
informative: the fail-closed path worked on its first try, and no kernel resolved.

My first hypothesis was the obvious one and it was wrong. I assumed
`semantic_hash` must include `domain_log_size`, which would have made §6.2's
log-size independence false and Option A dead. Reading
`witness/eval_program.zig:284` excluded it in a minute: the hash covers base
constants, both instruction streams and the constraint roots, and no geometry.

The real answer was one directory over. The product does not prove with
`sn_pie_2_composition.bin`. It proves with `air_template_library_v1.json`, which
points at three separate program bundles under `vectors/cairo/official/`. Nobody
in this campaign had asked whether those are the same programs, because 3.4
through 3.7 all loaded the SN2 bundle directly — a coherent closed world in which
every result stands and which the product never enters.

I did not argue this. I ran the shipping `metal-eval-source` over all four bundles
and intersected the emitted kernel names. 271 kernels from SN2, 69 from the union
of the three template bundles, intersection zero. Then I intersected each
workload's *observed request set* — the hook logs every name it fails to resolve,
which turned the failure into a measurement — against that union: all-opcodes
46/46, memory-7m 31/32, arithmetic-2m 28/29.

That is when the increment turned from "the gate missed" into something worth
having. The fix needs no codegen change, no ABI change and no design work: one CI
`xcrun metal` invocation over artifacts that are already in the tree, plus one
manifest entry. CI already compiles a composition metallib exactly this way. The
hook that is already committed then covers 96.6-100% of every portfolio workload's
parts, and the one straggler per large workload falls back to the host inside the
stage through the coverage mechanism I had already built for all-opcodes' three
missing components — which, ironically, turn out not to be missing at all.

The straggler's mechanism I can name from the code rather than measure:
`air/template_binding.zig` rewrites base constants at instantiation —
`memory_address_to_id`'s chunk strides when the claim's log size differs from the
template's, and builtin segment start addresses — and rewriting a base constant
changes the hash. all-opcodes resolves 46/46 precisely because its claim needs no
rebinding. I state which component I believe it is and leave confirming it as the
successor's first five minutes, rather than claim it.

## Two things I got wrong in the measurement, and one judgement I'd defend

I pointed the paired run's predecessor at `/private/tmp/i38-pred` after copying
the pristine `zig-out` to `/private/tmp/i38-pred-zigout`. Every predecessor arm
failed with `cd: no such file or directory` and I lost a full A-B-B-A pass. The
candidate arms were fine, so I fixed the path and re-ran the whole thing paired
rather than splicing the surviving B samples against fresh A samples — an unpaired
comparison would have been worse than no comparison.

Then I ran the test gates in the background *during* the re-run to save wall
clock, and watched `loadavg` go 4.52 → 52.55 across three workloads. Absolute
prove times came out 20-70% above every quiet-host figure in the campaign and
arithmetic-2m's predecessor arm spans 1.823x. I report the table and say plainly
that nothing at 1-3% is resolvable in it. Trading measurement quality for wall
clock was the wrong trade and I would not make it again; the honest cost is that
this increment's timing evidence is a screen, not evidence.

What the contaminated arms did surface, consistently in sign across all three
workloads, is the hook's own cost when armed: a 15-40 ms
`composition_device_admission` span, being a 7.7 MB SHA-256 plus a library load
plus 29-46 failed pipeline resolutions, paid on every proof for nothing. So I
flipped `STWO_ZIG_COMPOSITION_DEVICE` to default off and measured that too:
0.029 ms, one env-var read, digest unchanged. The brief said to prefer landing
admission-off if the gate was missed; I landed it off for a measured reason rather
than a cautious one.

The judgement I would defend: a whole-stage decline does **not** increment
`cpuFallbackTotal`. `composition_aot.authenticateFromProcess` records
`.cpu_composition_evaluation` on rejection by design, and I deliberately did not
call it. Before this increment every Metal Cairo proof evaluated composition on
the host and reported `cpu_fallbacks = 0`; a decline returns the proof to exactly
that path. Counting it as a fallback would retroactively mis-classify every proof
in this campaign's record, and would have made all-opcodes hard-fail
`requireAcceleratedWithoutFallbacks` the moment any component fell back for
declared-coverage reasons. Only a proof that *started* composition on the device
and finished on the host is a fallback, and that path does record it. This is
3.5 §3's precedent for the alias/memcpy/upload codes applied to a new counter:
count it, surface it, don't destroy the meaning of the classification.

## The item I could finally close, and the ones I could not

The corrupt-metallib fail-closed test has been carried as unreachable since 3.6,
for the good reason that the product did not load the metallib. It is reachable
now and it passes on the first try: a byte-flipped length-preserving copy, named
through `STWO_ZIG_COMPOSITION_METALLIB`, is rejected as
`UnapprovedCompositionMetallib`, the stage declines, the digest is
`25e5719f4c578eb7`, and the official verifier accepts that proof. The absent-file
case declines too, 60x faster, because `open` fails before the hash.

What I could not close is the gate, and what I ran out of budget for is the five
`zig build test-*` steps. I launched them, they had not returned, and I record them
as unrun rather than assumed green — the same disclosure 3.6 and 3.7 made, with the
same narrower reassurance that `package-workspace` links the whole 17-package
workspace at both commits and that the digest table was produced by binaries
rebuilt at the clean head. A successor must run them.

One thing the pre-commit hooks caught that I would rather they caught than a
reviewer: `component_prover.zig` hit 852 lines against the 850 ceiling on my first
commit attempt. Moving the stage consultation into `device_composition.tryStage`
left it at 846 and made the call site one statement, which is better code than
what the ceiling refused.

## What I would tell the next session

Do not scope a new design. The hook is landed and default-safe, the arena plans,
the lift is 3.7's verified routine, the admission policy has three gates and a
proven fail-closed test, and the telemetry is in the stage profile. The only thing
between this branch and the first real measurement of device composition in this
program is a metallib compiled from artifacts that are already checked in — and
this host cannot compile it, which was true in 3.7 and is still true.
