# Session 16 — increment 3.15, Library-2 consumption

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Branch `autoresearch/metal-residency-l2`, head at start `f51e6bb9`.
Raw data: `/private/tmp/i315/`.

Reasoning first, then the raw numbers. The short version: the thing the
increment was built to remove does not exist, and finding that out cost most of
the budget's value and none of its correctness.

---

## 1. What I expected to be doing

3.13 §8 ranked Library-2 consumption second and called it "highest value-per-risk
of anything remaining", projecting stages of 170.99 / 439.53 / 110.96 ms —
2.295x / 2.873x / 3.168x — on the strength of two things: 3.7 §3's statement that
the product publishes columns at `2^trace_log` (so the arena must lift each one to
`2^eval_log`), and 3.10 §3's measurement that stored-domain kernels are
1.22-2.26x faster than eval-domain kernels reading the lifted copy.

Both are load-bearing and only one of them is about the product.

## 2. The build

Straightforward, and the design decisions are in the note. Two are worth
restating here because they are where I deviated from the brief and where I
nearly introduced a bug.

**I could not place columns at a fixed trace-domain stride.** The brief says
"place trace-domain columns at planned offsets WITHOUT lifting", which reads as a
stride of `2^trace_log`. A column's required extent is its own length, and
column lengths are not uniform in principle — a preprocessed column may be
committed at a different log size than the component's trace — and are not known
at plan time, because `open` has no trace resolver and `resolve` runs per
evaluation. A fixed trace-domain stride is therefore an out-of-bounds read
waiting for the first component that reads a longer preprocessed column, and it
would have been a *silent* one: the kernel would have read a neighbouring
column's words and the proof would still have completed, just wrong.

So the plan reserves `columns * 2^eval_log` as a capacity and `store` packs
consecutively, publishing real offsets through `trace_offsets` — a block that was
already rewritten on every evaluation in Option A, so runtime placement is free.
The serial prefix pass checks `(eval_rows >> shift) << 1 == values.len`, which is
exactly the statement that the largest index the reader can form lands inside the
column. That check is the whole safety argument and it is one line.

**The brief's admission rule cannot fire.** "Stored-domain mode engages when
Library 2 authenticates AND every eligible component's sd-kernel resolves." Both
libraries are minted from the same three program bundles, so both are missing the
same rebound-constant straggler on arithmetic-2m and memory-7m (3.8 §1). Under
the literal rule tier 1 would demote on two of three gate rows and the increment
would be unmeasurable. I implemented the rule Option A already uses — unresolved
component becomes declared host coverage, tier engages on at least one acceptance
— and moved coverage equality from an asserted property to a verified one. §4 of
the note verifies it: identical census on all seven workloads.

## 3. The moment it went sideways

First armed spot proof, all-opcodes, stored-domain: byte-exact
`79ae76e1ac0c48b1`, 46/46 accepted, 121 dispatches, `cpu_fallbacks = 0`. That is
the result I wanted and it arrived on the first try.

Then the close log:

```
device composition (stored): stage 32.723 ms over 723 MiB (23.18 GB/s),
  46 dispatches in 46 submissions, device 38.080 ms
```

723 MiB. Option A's all-opcodes lift volume is 723 MiB. If Option B were removing
a 2x duplication this number had to be ~361.

I ran the other arm off the same binary to be sure I was not comparing against a
remembered figure:

```
device composition (lifted): stage 33.674 ms over 723 MiB (22.52 GB/s),
  46 dispatches in 46 submissions, device 30.292 ms
```

Identical. Two readings were available: my stored accounting was wrong, or the
columns were already eval-domain length. Rather than reason about it I made the
product report the quantity directly — `store` now returns a `Volume` carrying
staged bytes, the bytes Option A would have written, and the observed shift
range, and the stage folds and logs it. One rebuild:

```
stored: eval-domain equivalent 723 MiB, shifts 1-1
lifted: eval-domain equivalent 723 MiB, shifts 0-0
```

`shifts 1-1`. Every column, shift 1. `shift = eval_log - column_log + 1`, so
`column_log == eval_log`: the committed columns are already at evaluation-domain
length, `((p >> 1) << 1) + (p & 1) == p`, and the lift was already the identity.
Confirmed on arithmetic-2m and memory-7m immediately after (`shifts 1-1`, same
staged-equals-equivalent volumes at 1,482 and 4,317 MiB).

The cause is one line: `pcs/tree_builders.zig:169` — "Each entry stores the
*extended* column values and their log_size" — and `scheme_views.polynomials`
hands those columns straight to the composition path. 3.7 §3 asserted the
opposite, the arena's own module comment repeated it, 3.13 §6 priced it, and
3.10's projection rested on it.

**Why four increments of byte-exact verification did not catch it.** Every test
that has ever exercised this ABI — 3.5's binding smoke, 3.6's fusion census,
3.7's lift bridge, 3.10's Option-B anchors and price test — builds its **own**
column store at trace-domain length and compares device against host over it.
That is a coherent closed world and every result in it stands, including 3.10's
1.22-2.26x. None of them ever asked what log size the *product* commits at. It is
the same class of gap as 3.8 §1's "the metallib is compiled from the wrong
bundle": a fixture that is self-consistent and unlike the product.

## 4. The measurement, which I ran anyway

Not because the answer was in doubt but because "parity" is a claim and needs the
same evidence a win would. A-B-B-A, 3 blocks, 6 samples per arm, warmup per arm
per workload, caches off both arms, same binaries, env-only pairing, loadavg
1.21-3.92.

Composition stage, stored over Option A: **1.0044x [0.9909, 1.0179]**,
**0.9945x [0.9650, 1.0249]**, **1.0028x [0.9937, 1.0121]**. Three intervals, all
containing 1.

The decomposition is the part I would keep if I could keep one table. Staging
1.0404x / 1.0294x / 1.0334x, intervals excluding 1 — a `@memcpy` beats the
pair-duplication loop over identical volume. Device GPU 0.9919x / 0.9797x /
0.9881x — the stored reader pays one load through the shift table and computes
the identity with it. +1.0/+4.4/+1.1 ms and −0.4/−3.1/−0.4 ms. The stage is the
sum and the sum is zero.

That is 3.10's result, correctly transported: its stored kernels were fast
because they read half the bytes, and on the product they read all of them.

## 5. Disposition

Default back to Option A, tier opt-in, one test pinning the default so a future
flip has to touch the line where the reason is written. Everything stays: the
mode is correct, general, byte-exact, and is what a column set committed at
trace-domain length would need. Nothing about it is worth defaulting to at zero
gain.

## 6. Raw numbers

### Gate, `/private/tmp/i315/gate.json` (36 timed samples)

```
composition stage (ms, mean of 6)
  arithmetic-2m   Option-A 245.43   stored 244.37
  memory-7m       Option-A 573.34   stored 576.48
  all-opcodes     Option-A 128.15   stored 127.79

prove (ms, mean of 6)
  arithmetic-2m   Option-A 1542.87  stored 1538.36
  memory-7m       Option-A 3692.45  stored 3692.25
  all-opcodes     Option-A 1014.36  stored 1015.73

staging pass (ms, mean of 6)
  arithmetic-2m   Option-A 71.84    stored 69.07
  memory-7m       Option-A 151.03   stored 146.67
  all-opcodes     Option-A 32.65    stored 31.60

device GPU (ms, mean of 6)
  arithmetic-2m   Option-A 64.65    stored 65.18
  memory-7m       Option-A 152.97   stored 156.10
  all-opcodes     Option-A 29.56    stored 29.92

admission (ms, range)
  arithmetic-2m   Option-A 11.05-11.80   stored 10.76-11.37
  memory-7m       Option-A 11.75-13.06   stored 11.43-12.79
  all-opcodes     Option-A 12.56-12.73   stored 12.15-12.35

digests, all 36 samples, singleton per workload per arm
  arithmetic-2m 25e5719f4c578eb7   dispatches 102   fallbacks 0
  memory-7m     e3317e55a5db5a42   dispatches 110   fallbacks 0
  all-opcodes   79ae76e1ac0c48b1   dispatches 121   fallbacks 0

staged / eval-domain-equivalent MiB, identical on both arms
  arithmetic-2m 1482 / 1482      memory-7m 4317 / 4317     all-opcodes 723 / 723
observed shift range
  stored arm 1-1 on every sample of every workload
```

Library 2 cold pipeline cliff, first armed proof: `composition_device_admission`
**141,307 ms** (prove 142,571 ms). Warm thereafter at 10.8-13.1 ms. Library 1's
equivalent was 181,740 ms in 3.13 §3. Both libraries pay it once per host.
poseidon-aggregator's first stored-domain proof paid a second cliff of the same
kind at 73,142 ms, for the component set only that workload requests.

### Seven-workload checklist, `/private/tmp/i315/verify.json`

See note §4. Every digest equal to the campaign value on all three arms, all 21
proofs `--verify` accepted by the Zig verifier, census identical between the two
Metal tiers on every workload.

### Fail-back, `/private/tmp/i315/f/`

See note §5.

## 7. What I would tell the next session

Do 3.13's item 1. Instrument the composition residual before building anything
else against that decomposition. This increment is the second lever in a row that
was ranked and scheduled off `stage = lift + kernels + residual` where two of
those three terms had never been checked against the product — 3.7's projection
failed because the residual was assumed zero, and this one failed because the
lift was assumed to be a duplication. The residual is 81.5-289.7 ms, it is the
largest term on every workload, and nobody knows what is in it.

Second: the staging copy is still 32.6-151.0 ms and is now the only term with a
known mechanism. The columns are already the right length and already committed;
the arena copies them because it owns its allocation. Aliasing rather than
copying is the shape of the answer, and the campaign already aliases elsewhere
(`commit_source_arena_aliases` is non-zero on every Metal proof here). It is
harder than it sounds — it needs per-column contiguity and residency in
`pcs/tree_builders.zig`, not in the composition stage — so scope it before
promising it.

Third, and cheapest: the `Volume` diagnostic exists now. Any future claim about
what the product commits, at what length, can be read off a proof's stderr
instead of inferred from a test fixture. Use it before pricing the next lever.
