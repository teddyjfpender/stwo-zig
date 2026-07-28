# Session 04 — increment 2.4, Karatsuba QM31 multiplication

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Branch `autoresearch/cairo-native-throughput-10x`, worktree
`/private/tmp/stwo-zig-cairo-native-throughput-10x`, head at open `15b2fecb`
(clean). Budget 75 minutes; the session ran slightly over while packaging.

## Reading the brief against the code, before doing anything

The brief asked for Karatsuba at three sites: the packed QM31 multiply, the
scalar `QM31.mul`, and the `CM31` multiplies. The first thing I did was read
`src/core/fields/qm31.zig` and `src/core/fields/cm31.zig`, and two of the
three sites turned out to be **already done**:

- `QM31.mul` (`qm31.zig:157-184`) is already Karatsuba over `u^2 = 2+i`:
  `ac`, `bd`, `(a+b)(c+d)`, three `CM31` products.
- `CM31.mul` (`cm31.zig:97-112`) is already Karatsuba over `i^2 = -1`, with
  the comment "3 base-field multiplies instead of 4".

So the scalar QM31 product is already 9 M31 multiplies and both files already
carry `mulReference` schoolbook oracles under test. The increment collapsed
to the one site that is still schoolbook: `PackedQm31.mul` in
`src/frontends/cairo/proving/air/simd_evaluator.zig:79-118`, which is exactly
the 161-instruction body increment 2.3 fingerprinted. I record this because it
changes the increment's expected value before any measurement — the "benefits
EVERY QM31×QM31 site" argument in the brief only holds for the packed site,
since the scalar sites already have the optimization.

## The range proof turned out to be short, for a specific reason

The brief expected the hard part to be intermediate-range overflow: `(a0+a1)`
reaches `2p-2`, so `(a0+a1)(b0+b1) < 4p^2 < 2^64` overflows the bounded
reducer's `< p^2` assumption. I went looking for where I would need
pre-reduction, `+2p` offsets, or the generic `u64` reducer, and found that the
question does not arise, because **every primitive in `m31.zig` already
returns a canonical value**:

- `mulVec4Aarch64` ends `@min(folded, folded -% P_VEC)` → `[0, p)`.
- `addVec4` ends in the same unsigned minimum → `[0, p)`.
- `subVec4` returns `a-b` or `a+p-b` → `[0, p)`.

Forming the Karatsuba sums with `addVec4` therefore hands `mulVec4` canonical
operands, which is precisely SQDMULH's precondition. No value in the body can
exceed `p-1`, so there is no bound arithmetic and 2.2's `@min`-narrowing trap
cannot bite (both operands are `Vec4u32`). Exactness is then ring algebra, not
range reasoning: Karatsuba is an identity over the exact field, and canonical
representatives of equal field elements are equal bit patterns.

I did not want to rely on that argument alone, so the exactness test compares
`mul` against the retained `mulSchoolbook` over 20,000 trials with **per-lane
distinct** operands — a lane-crossing bug is the failure mode a splat-only
test cannot see — plus each lane against scalar `QM31.mul`, plus a boundary
sweep over `{0, 1, 2, p-2, p-1}`.

## The paper estimate predicted the failure, and I ran the gate anyway

Counting AArch64 instructions per primitive: `mulVec4` is 6
(`mul`, `sqdmulh`, `bic`, `add`, `sub`, `umin`), `addVec4` is 3, and
`subVec4` — as it stood — was 5 (`cmhi`, `bic`, `add`, `sub`, select).
Karatsuba trades 7 multiplies (`-42`) for 13 extra additions/subtractions
(`+49`). On paper it loses. The brief says "if the extra reductions/adds eat
the multiply savings on paper, S1 will tell — that's the gate", so I wrote it
up as expected-to-lose and measured.

Harness setup cost more time than expected. `--import evaluator=simd_evaluator.zig`
fails because the file relative-imports `../../witness/eval_program.zig`,
outside a module rooted there. Rooting at `src/stwo_cairo_cpu.zig` fixes the
module directory but then `simd_evaluator` cannot see `stwo_core`, because
`stwo-prof`'s generated `build.zig` wires named imports into the workload
module only. I patched the generated `build.zig` to cross-wire all five repo
modules into each other. Consequence worth flagging for the skill:
`stwo-prof zig asm` bypasses `build.zig` and shells `zig build-obj` directly,
so it cannot see the cross-wiring and fails — I used `objdump` on the
installed harness binaries instead, the same route 2.3 used.

Kernel shape: 8 independent accumulator chains × 128 serial multiplies. The 8
chains are deliberate — the compiled AIR body issues 139 *independent*
multiplies per four-row group, so a single serial chain would measure latency
where the real loop is throughput-limited.

### The measurement, and the pivot

Arm 1 (schoolbook, live) came back at 173 instructions/op, 38.96 cycles/op,
IPC 4.44. Arm 2 (Karatsuba) came back at 179 / 42.34 / 4.23 —
**`0.920x`, a regression**, within a few percent of the paper estimate.

The `objdump` evidence is what made this worth continuing rather than
stopping. The Karatsuba body is 167 instructions with **9 `mul` and 9
`sqdmulh`** against the schoolbook's 16 and 16: the designed mechanism landed
exactly, and cost more anyway. In the same table, `cmhi` went `5 → 14` and
`sub` went `5 → 14` — one pair per additional `subVec4`. The regression is
entirely attributable to one primitive, and the schoolbook arm's body measured
**161 instructions, the same figure increment 2.3 obtained by a different
route on a different binary**, which is the provenance that let me trust the
attribution.

That made the next test obvious. `addVec4` reduces with `@min(sum, sum -% P)`;
`subVec4` was still using `@select` on `a < b`. The same trick works for
subtraction, and I checked both branches before writing it:

- `a >= b`: `d = a-b` in `[0,p)`; `d+p` in `[p,2p)` and `2p = 4294967294 < 2^32`,
  so no wrap and `d+p > d`; `@min` picks `d`.
- `a < b`: `d = a-b+2^32 >= 2^32-p+1 = 2147483650 > p`; `d +% p` wraps to
  exactly `a-b+p` in `[1,p)`, which is smaller; `@min` picks it.

Same precondition as the code it replaces (the `@select` form also needs
`a +% P_VEC` not to wrap, i.e. canonical `a`). Exact identity, so it cannot
move a digest.

Re-running both arms against the new primitive gave the 2×2 that is the real
result of this increment:

| multiply | `subVec4` | instr/op | cycles/op | ns/op |
| --- | --- | ---: | ---: | ---: |
| schoolbook | select | 173.0 | 38.96 | 8.965 |
| Karatsuba | select | 179.0 | 42.34 | 9.662 |
| schoolbook | umin | 170.3 | 40.64 | 9.674 |
| Karatsuba | umin | 139.2 | **33.68** | 7.671 |

Karatsuba is a regression on the old primitive and a `1.157x` win on the new
one. The two changes are not separable, which is why they are one commit.
`stwo-prof zig compare` with `subVec4` held equal: wall `1.1315x`,
CI95 `[1.11994, 1.140758]`, cycles `1.1297x`, instructions `1.2125x`.

**`1.157x` against the `1.2x` gate. The gate fails.** I did not round it up.
I continued to whole-prover because the brief's compounding policy keeps small
real wins with a confirmed mechanism, and because the artifact was already
built and the measurement is cheap (~2.6 s per proof).

## Byte-exactness first, then timing

Before any timing I spot-proved all three campaign workloads with `--verify`:
arithmetic-2m `25e5719f…`, memory-7m `e3317e55…`, all-opcodes `79ae76e1…`,
all matching the campaign values, `verify.zig = true`. Then committed.

`m31.zig` is shared with `src/prover/**`, the native prover and the RISC-V
prover, so unlike 2.3 this increment genuinely needed `test-stwo-prover`. It
passed: 188-source `stwo-prover` closure PASS, 334-source `stwo-cairo-cpu`
closure PASS, exit 0.

## Whole-prover, and the number that closed 2.3's open discrepancy

A-B-B-A, 3 blocks, warmup per arm, caches off both arms, predecessor a
pristine build of `15b2fecb` in a detached worktree. Host caveat I want on
the record: an unrelated `stwo-native-metal` build from another session was
resident and pushed the load average to `10.05` at one point. Blocks were
taken at `6.51 / 9.65 / 9.18`, under the ceiling, but this was not a quiet
host, and I measured arithmetic-2m only — the budget expired before memory-7m
and all-opcodes, which I am reporting as not-run rather than estimating.

Prove geomean `1.0092x` (blocks `1.0205 / 1.0013 / 1.0059`), ranges
overlapping. `composition_evaluation` geomean `1.0390x`, favourable 3/3, but
ranges overlap at `392.268` vs `395.186`. Neither acceptance limb is met:
the stage limb wants `>= 1.10x` disjoint x3 and the prove limb wants
`>= 1.02x` with non-overlapping CI. **Undecided-borderline**, sign consistent
3/3 on both observables.

The result I did not expect is the cross-validation. 2.3 closed with an
explicitly unresolved discrepancy: its `1.242x` S1 result should have given a
`1.157x` stage if the multiply were 70% of it, but the stage read `1.0553x`,
back-solving to a **27%** share, and 2.3 said resolving it needed a
per-component probe it could not afford. This increment is that test, cheaply
and from the other direction: move the multiply by a known `1.157x` and read
the stage. A share `f` predicts `1/(1 - f + f/1.157)`; at `f = 0.27` that is
`1.038x`. The measurement is `1.0390x`. Two increments, two unrelated
mechanisms, the same 27%.

That converts 2.3's loose end into a **bound**, which I think is this
increment's most durable output. If the QM31 multiply is 27% of the
composition stage, then even an infinitely fast multiply caps the stage at
`1.37x` and prove at roughly `1.06x`. The arithmetic family is not closed,
but the ceiling on it is now measured rather than assumed, and any future
proposal in the family has to be priced against `1.06x` of prove, not against
the 72% instruction share.

`sampled_value_evaluation` came in flat at `0.9957x`, which is the right
answer and a useful negative control: that path uses scalar `QM31.mul`, which
was already Karatsuba, so there was nothing there for this change to move.
`fri_quotient_build_and_commit` at `0.9995x` and the commit stages inside
noise confirm the change is confined despite `m31.zig`'s reach.

## What I did not get to

The official verifier, Metal byte-identity with `cpu_fallbacks 0`, and the
`STWO_ZIG_WORKERS=1` digest are all unrun. Two of those three are
load-bearing for *this* change specifically, because `m31.zig` is the
Metal host-side field module and the single-worker path is a different
composition schedule. I would not promote this without them, and the note
says so rather than burying it.

## Judgement I would flag to the orchestrator

The increment as scoped is a **negative audit**: Karatsuba QM31
multiplication, the stated hypothesis, is a `0.920x` regression, and the S1
gate it was given fails at `1.157x` against `1.2x` even in its best
composite form. What is left is a different change — a cheaper canonical
subtraction — that Karatsuba then makes worthwhile. That is a real
mechanism-confirmed win of about `1.009x` prove and it is byte-exact, so
under the compounding policy I believe it should be kept; but the honest label
is undecided-borderline on the acceptance criteria and negative on the
hypothesis, and the two should not be conflated in the campaign summary.
