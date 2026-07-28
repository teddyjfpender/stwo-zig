# Session 03 — Register-resident compiled AIR evaluation (codegen-v2)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`autoresearch/cairo-native-throughput-10x`, head `efe4bef3` (clean) at open.

Host: Apple M5 Max, 12 performance + 6 efficiency cores, 7 users. Load average
**2.47** at session open — the quietest window this campaign has had — drifting
to 6.3 by the end of the timing block. Every block records its own `uptime`.
For once, host load is not a caveat on any number in this session.

## The brief handed me a falsifiable prediction, which is the good kind

The hypothesis was specific enough to be wrong in a measurable way: if the
interpreter's ~22 cycles per interpreted instruction are the cost of its
*memory-resident register file*, then compiled code that holds values in
registers should show its memory operations **collapse**, and cycles should
follow. That gives two independent observables — mem ops and cycles — and I
could check the first one directly with `objdump` rather than inferring it.

I read increments 5 and 6 first, and the thing that struck me was increment 6's
IPC column. At `T=1` the interpreter runs at IPC **5.30** on an 8-wide core.
That is not a machine waiting on memory. Increment 6 read that correctly for
strip-mining ("the dispatch instructions were already being issued in
superscalar slack") but the same reading has a second implication the note did
not draw: at IPC 5.3, cycles are approximately instructions / 5.3, so removing
instructions *should* help — you just have to remove a lot more than 21%.
50,067 machine instructions per four-row group for 771 interpreted instructions
is 65 machine instructions each, and compiled code ought to need two or three.
So I went in expecting a big number and a cleared gate.

## Finding the real program instead of a synthetic one

Increment 6's harness used a program *structurally matched* to increment 5's
census. That was the right call for a tile sweep, but for a hand-translation
the actual instruction stream matters, so I went looking for it.

`vectors/cairo/official/*.air_programs_v1.bin` are composition bundles
(`STWZEVA` magic). I wrote a Python parser against `composition_bundle.zig`'s
and `eval_program.zig`'s own `parse` functions and censused the whole thing.
`add_opcode_small` part 0 came back at **278 base / 493 ext / 63 reads / 32
roots / mbr 278 / mer 493 / offsets [-1, 0]**, matching increment 5's census
digit for digit. Semantic hash `0x6e7d9762fbd1969a`.

Two things I checked before trusting the hash as an admission key, because
getting this wrong would be a soundness bug rather than a performance one:

- `template_binding.zig` rebinds base constants in exactly two places —
  `rebindDomainConstants` (only `memory_address_to_id`) and
  `rebindSegmentConstant` (only builtin segment labels). `add_opcode_small` is
  neither, so `replaceBaseConstant` never fires and the runtime program's
  semantic hash equals the shipped template's.
- `setDomainLogSize` touches the header only, and `semanticHash` covers
  constants + instructions + roots, not the header. That is correct for my
  purposes: the domain size is an *input* to the evaluator, not something
  compiled into it, so it must not be in the key.

I also decided FNV-1a-64 was not enough to key generated code on, and made
admission re-hash the whole canonical payload with SHA-256. The generator
asserts that its own byte encoding of that payload reproduces the program's
`semantic_hash` before it emits anything — so if I had got the encoding wrong,
generation would have failed rather than baking in a digest of the wrong bytes.
That assert fired zero times, which is the only reason I trust the digest.

## Generating rather than typing, and saying so

The brief said hand-translate. I wrote a ~180-line Python emitter instead, for
the reason the brief itself gives — "this is what a generator would emit" — and
because 771 mechanical transcriptions typed by hand is 771 chances to introduce
an operand-order bug that byte-parity would catch but only after a build. The
translation rule is one line per opcode and the whole thing is auditable in the
generated file, which is checked in.

Design decisions inside the emitter that turned out to matter:

- **Named struct, not array, for the base→ext handoff.** 90 base registers feed
  the extension stream through `secure_col`. Returning `[278]PackedM31` or
  `[90]PackedM31` risks LLVM materialising a stack array — which is precisely
  the memory register file I was trying to remove, so the experiment would have
  tested nothing. A generated struct of 90 named fields plus `inline fn` gives
  SROA no excuse.
- **Row-invariant splats hoisted to the driver.** 100 of the 493 extension
  instructions are `param` (26 distinct) and 24 are `constant`. In the
  interpreter these re-splat every group; increment 5 tried hoisting them and
  got ~1%. In compiled form they are free, so I hoisted them without expecting
  credit for it.
- **Two files.** 803 instructions plus scaffolding does not fit under the
  850-line ceiling, so base and ext are separate modules. Worth flagging for
  the generalization: `partial_ec_mul_generic` has 18,128 instructions.

## The product wiring fired on the first build, and I checked rather than assumed

First `run-and-prove` on arithmetic-2m: digest `25e5719f…`, `--verify` true,
prove 2,418.9 ms at load 2.47. Byte-exact immediately.

But the composition stage read **350.4 ms**, which is inside increment 5's
post-candidate range. That is exactly the reading you get when your new code
is not running at all, so I refused to interpret it until I had proved
admission fires. I tried a `@panic` probe first, which failed to compile, and
the run silently used the *stale* binary — a trap worth recording, because the
report it produced looked perfectly normal. The clean probe was to sabotage the
generated body to `return PackedQm31.zero()`: that produces
`error: ConstraintsNotSatisfied`, so the compiled path is demonstrably the one
executing. (It also demonstrates the fail-closed property for free.)

So the compiled evaluator was running, byte-exact, and worth ~1.03x on the
stage in a first paired block. That was already telling me the answer, but the
gate is an S1 measurement and S1 is where the mechanism lives.

## S1: 1.242x, and the two lines of objdump that explain it

`i23-interp` / `i23-compiled`, real program out of the bundle, live repo module
graph, one op = one four-row group, four rounds of twelve iterations:

```
interp    instr/op 43,395   cycles/op 8,698.3   IPC 4.99   ns/op 2,025.3
compiled  instr/op 30,961   cycles/op 7,000.5   IPC 4.43   ns/op 1,640.1
ratio            1.402x            1.242x               0.89     1.235x
```

Per-round cycles/op, interp: 8,522.5 / 8,882.2 / 8,615.2 / 8,773.2.
Compiled: 7,054.4 / 6,973.3 / 6,931.3 / 7,042.9. Instructions/op stable to five
significant figures. **1.242x against a 1.5x gate — falsified.**

The gate failing is the easy part. The interesting part is that instructions/op
fell only 1.40x, to 30,961 — 40 machine instructions per template instruction,
where I had predicted six. `stwo-prof zig asm` could not run (it does not use
the harness `build.zig`, so `cairo_frontend` is unavailable), so I disassembled
the harness binaries directly. Two rows:

```
generated.add_opcode_small.evalGroup    n=6,552  ld=1,513  st=1,397  calls=139
simd_evaluator.PackedQm31.mul           n=  161  ld=    5  st=    3  calls=  0
```

`evalGroup` is straight-line, so static count = dynamic count per group. And
then the arithmetic closes exactly: `139 x 161 = 22,379`, plus 6,552, plus the
driver's gather/offset/denominator/scatter ≈ 30,961. **139 QM31 multiplies per
group — 107 extension `mul` plus 32 fold multiplies — are 72.3% of the compiled
arm's entire instruction budget.**

And the prediction about memory: 1,397 vector stores per group against the
interpreter's 2,250 by construction. **1.61x, not a collapse.** 493 live
PackedQm31 values are 31.5 KB; 32 NEON registers are 512 B. LLVM spilled,
because it had to, and a spill slot is the same L1D round trip. The hypothesis
had a specific quantitative prediction and the measurement contradicts it
directly rather than ambiguously, which is the most useful way for a hypothesis
to die.

The IPC column is increment 6's signature repeated: 4.99 → 4.43, falling in
lockstep with the instruction reduction, exactly as 5.30 → 4.34 did under
strip-mining. Three mechanisms, 24.3% / 21.4% / 28.6% of instructions removed,
1.01x / 1.05x / 1.24x of cycles gained. Monotone, largest here, and converging
on a floor at ~7,000 cycles per group that is the field arithmetic itself.

## One diagnostic, and a stale-binary correction I have to own

If 72% of instructions are an out-of-line multiply, the obvious question is
whether the call is the cost. `pub inline fn mul` on the interpreter arm:
43,394 → 40,416 instructions/op (−6.9%), 8,773.2 → 8,667.1 cycles/op (−1.2%,
inside round spread). Instructions move, cycles do not. Call overhead is not
where the multiply's cost is.

I initially recorded a compiled-arm inline-mul number too, and it was wrong:
the harness had silently reused a binary from before the edit (mtime proved
it), and a forced rebuild failed with `m31.zig:255: evaluation exceeded 1000
backwards branches`. So there is no compiled inline-mul figure and the earlier
one is discarded. Second time this session that a stale build produced a
plausible-looking number — the lesson is to check the mtime whenever a counter
comes back *identical* rather than merely similar.

## Whole-prover, for corroboration rather than acceptance

Three A-B-B-A blocks, warmup per arm, cache off both arms, predecessor a
pristine `zig-out` from `efe4bef3` in a detached worktree. Load 4.45 → 6.30, no
block above 10, so for once the CIs mean what they say.

```
b1  comp 381.909 -> 362.720  1.0529x   prove 2559.856 -> 2536.505  1.0092x
b2  comp 398.032 -> 382.997  1.0393x   prove 2639.375 -> 2606.531  1.0126x
b3  comp 416.825 -> 388.102  1.0740x   prove 2677.059 -> 2659.926  1.0064x
    geomean                  1.0553x                               1.0094x
```

Same sign in 3 of 3 blocks on both observables, and every untouched stage inside
noise (`main_trace_commit` 1.0033x, `fri_quotient_build_and_commit` 1.0004x,
`interaction_trace_commit` 0.9858x). The effect is real, small, and confined.

One number does not close and I am recording it rather than smoothing it: S1's
1.242x on a component the census implies is ~70% of the stage should give
~1.157x, and the stage gives 1.0553x, which back-solves to a 27% share. Either
the census's *instruction* share overstates its *time* share, or the real log-22
instance is more mask-gather-bound than my log-18 harness (its columns are 4.2 M
rows and cannot be cache-resident). Settling it needs increment 5's per-component
probe, and I chose to spend the remaining budget on the note instead.

## Reconciling the old AOT rejection, which I think the brief got wrong

The brief offered a theory for the earlier 1.017x / 5.9 MiB AOT rejection: it
"still routed values through a memory register file or blew i-cache". My result
says that theory is wrong. This implementation does not route through a register
file — its values are locals, its spills are LLVM's own choice — and its hot
body is 26 KB against 192 KB of L1I with one component hot at a time. It is
neither of those things, and it measures 1.0094x prove for 17 KiB.

The two results are the same finding at two binary sizes: **compiling the AIR is
worth about one percent of prove time**, because the stage's cycles go to the
AIR's field arithmetic and not to its interpretation. The old verdict was right;
what it lacked was the mechanism, and the mechanism is now a measured number
(72.3%) rather than a guess.

## What I am handing back

Generalization sizing, measured rather than estimated: +17,456 B for 803
instructions = 21.7 B each, so the bundle's 64,193 instructions project to
+1.33 MiB — a quarter of the old AOT's 5.9 MiB, which suggests the old one
emitted ~4x more code per instruction than mechanical translation needs. And
64 K lines of generated Zig for ~1% of prove. My recommendation is not to do
it, and the reason is not that it fails but that the same measurement points at
something better.

The redirect: 139 QM31 multiplies per group at 16 M31 multiplies each. Karatsuba
at both levels is 9 instead of 16 — a 1.78x cut on 72% of the instruction budget,
in **one function** in `simd_evaluator.zig`, benefiting the interpreter directly
with no admission machinery, no generated code, and no binary growth. This
increment's own conversion evidence says cycles follow instructions at roughly
half rate here, so I would price it at ~1.2x on the stage and ~1.04x on prove —
four times what compiling the whole AIR bought, for one function. The byte-exactness
risk is real and specific (reassociation must preserve canonical representatives)
and is checkable at S1 in minutes.

Increments 5, 6 and 2.3 have now closed "make the interpreter cheaper" with
three independent measurements. The composition stage's cost is the arithmetic,
and the next attack on it has to be arithmetic.
