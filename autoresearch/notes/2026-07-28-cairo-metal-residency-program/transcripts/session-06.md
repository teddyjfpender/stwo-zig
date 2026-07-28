# Session 06 — increment 3.5: byte-exact device composition binding

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Head at start `4d2472b1`, clean. Raw data `/private/tmp/i35/`, predecessor
binaries `/private/tmp/i35-pred/zig-out`.

## The convention took twelve minutes, and that is the interesting part

I was told to work through 3.4's three candidates systematically and to build a
discriminating experiment for each. I did not need to, because reading the two
evaluators side by side answered it before I ran anything, and I want to be
precise about what the reading was, because it is the kind of thing that is
invisible until you look at the right two lines.

The device kernel reads `arena[arena[args.trace_offsets + global] + target]` —
straightforwardly `column[row]`. The host reads
`values[((position >> shift_amt) << 1) + (position & 1)]`. Those are the same
expression only when `shift_amt = 1`. The smoke passed `0`. The test's own header
comment said `shift_amt = 0` meant "the same columns at evaluation-domain
length, so any disagreement is a real semantic disagreement" — and that sentence
is precisely backwards: `0` is the one value that is *not* the identity.

I then checked I was not pattern-matching by finding the product's own producer
of that struct. `air/component.zig:355-359` sets
`shift_amt = evaluation_log_size - column.log_size + 1`. Column at
evaluation-domain length gives 1. That is the whole diagnosis, and the one-line
change made the smoke pass on the first try: `blake_round_sigma`, 22 columns, 32
rows, byte-exact.

The reason it took a whole increment to find is worth recording because it is a
testing-technique lesson, not a Metal lesson. The smoke gave the host reader
`words[start..]` — an unbounded slice to the end of the arena. So the stride-2
walk that `shift_amt = 0` produces read **the neighbouring column's data**
rather than running off the end. A bounded slice would have turned a silent
wrong answer into `index out of bounds` and named the file and line. I changed
the reader to slice exactly the column's extent, which is why the next person to
get this wrong will get a bounds panic instead of two field elements.

## Building the experiment anyway, and the iteration it cost

I built the discriminating experiment even though the fix was already confirmed,
because "I read two lines and changed a 0 to a 1" is not evidence, and because a
regression here would otherwise reappear as unattributable numbers. The design:
one column, one constraint, coefficient 1, denominator inverse 1, column filled
with `index + 1`, kernel JIT-compiled from the same codegen the bundle's kernels
came from. Then the coordinate at row `r` *is* `map(r) + 1`, so the assertion
reads the index map out of the buffer.

It failed first time: `expected 33, found 1`. I had predicted the shift-0 map
correctly but filled only `row_count` words, so at `r = 16` the map reaches
index 32 — one past the column — and read `trace_offsets`, whose value is 1.
That is the same class of mistake as the original bug, one level up, and I
enjoyed that more than I should have. Filling `2 * row_count` fixed it and the
experiment now asserts all three maps positively: device `r`, host-at-1 `r`,
host-at-0 `2r + (r & 1)`.

## Coverage, and the case I did not expect to be the important one

The brief asked for the dominant component of arithmetic-2m plus one small
component. I generalised the runner from one part to whole components and
selected structurally: smallest, largest by `rows x constraints`, most parts, and
the largest of a named arithmetic set. Three of the four came out of the
structural picks; `add_opcode` at 2^21 rows came out of the named one.

The case I expected to be a formality and was not is **most parts**.
`partial_ec_mul_generic` has 90 parts, 1,252 columns, 448 constraints. All 90
accumulate into the same four coordinate words, each addressing the shared
coefficient block at its own `rc_base`. That means candidate 2 of 3.4's three —
the `rc_base` accumulator convention — is now *positively verified* rather than
merely not-the-culprit, and it could never have been verified by the single-part
smoke 3.4 wrote. If I were re-scoping 3.4 I would have made it multi-part from
the start; the extra parts cost nothing to write and they are where the
accumulator conventions live.

It passed on the first run of all four cases. I did not expect that and I
re-read the comparison loop to convince myself it was not vacuous — it iterates
every row and every one of the four coordinates, and I had watched it fail on
row 0 an hour earlier, so it is not.

## A cap I added and then removed

The four cases cost ~15 minutes in the Debug `metal-test` closure, because the
host reference is a scalar-lane interpreter and two components are 2^21 rows. I
added a `selection_evaluation_log_cap = 17` to keep the committed test snappy,
and then reverted it when I worked out what it excluded: `add_opcode` (2^21) and
the dominant component (2^21) — i.e. exactly the two the brief asked for. A fast
test that does not test the thing is worse than a slow one that does. I recorded
the cost in the note instead.

## The counter, and the number that reframes 3.4

3.4 called the alias counter the cheapest missing evidence in the program and it
was right. I considered computing the predicate in Zig from the pointers and
sizes I already pass, and rejected it: that would be an *inference* about what
the Objective-C did, and it would drift the first time either side changed. So I
added one `uint32_t *source_binding` out-parameter and set it inside the branch
that decides, which makes the counter an observation.

The result is the most useful thing in the increment after the smoke:

    all-opcodes    alias 6   memcpy 8   upload 31
    arithmetic-2m  alias 8   memcpy 5   upload 30
    memory-7m      alias 11  memcpy 4   upload 32

Two readings I did not anticipate. First, **the alias is only taken on 43-73% of
arena-sourced commits.** `trace_arena` page-aligns each group start, but
`circle_legacy.m:229` also requires the flat span's byte length to be a page
multiple, and a group whose `columns x rows` is not fails that. So 3.4's null
commit-stage result was not "the mechanism did nothing" — it was "the mechanism
engaged on somewhere between a quarter and a half less work than the arena
telemetry implied", and the fix is layout padding, which is cheap and now
priced. Second, **~30 of the ~45 circle-LDE commits per proof are not
arena-sourced at all** — interaction, preprocessed and composition columns, none
of which the trace arena covers. I had been reading "arena bound" as "the commits
are aliased" and it is not close to that.

The counts are identical across all 8 candidate samples per workload and the
`W=1` run, so they are structural rather than sampled, which is what makes them
usable as an attribution baseline.

## Measurement, and the cost model I got for free

Quietest host of the campaign (`loadavg` 2.12 → 3.96). 2 blocks A-B-B-A:
all-opcodes 1.0012x, arithmetic-2m 0.9982x, both inside their own arm spreads
(1.006-1.025x). `main_trace_commit` moved +1.0 and +1.4 ms — a control, since I
changed nothing in the commit, and it behaves like one. That is the first time in
this campaign the noise floor has been tight enough for a ~1x result to mean
"no change" rather than "cannot tell".

The unplanned dividend is the per-dispatch cost model, which fell out of the
smoke's `gpu_ms` totals: 39.69 ms / 3 parts at 2^21 rows, 484.59 / 41 at 2^21,
418.82 / 90 at 2^19 — about 11.8-13 ms per dispatch at 2^21 and 4.65 at 2^19,
i.e. roughly `5.6 ns x rows` per part and **flat in constraint count** across
27-448 constraints. The dispatches are row-bound. That is the number that says
the unfused one-kernel-per-part library cannot win the composition stage: one
2^21-row component costs 484 ms unfused against a 435.7 ms whole-stage host cost
on arithmetic-2m. I did not go looking for that and it is probably the most
consequential thing I can hand forward, because it turns "fuse eventually" into
"the artifact that exists cannot clear the bar, and here is the arithmetic".

Which is why I recommended against inheriting §6.8's ≥ 2.0x stage bar for the
product-hook increment. That bar cannot be met with the checked-in metallib, and
a rejection on it would restate what this cost model already shows rather than
learn anything.

## Official verifier

Found the binary and worked out its argument shape by reading its own strings
(`verify --proof --channel --proof-format --result`; `--proof-format json`, not
`official-json`). Ten proofs, `verified: true` on all ten, including two
independent arena-engaged all-opcodes samples — which is 3.4's open item 2, and
the one that mattered because all-opcodes is the row whose path changed.

## Commits

- `6abcf346` — the convention fix, the discriminating experiment, bounded host
  reader, coverage extended to whole components and four structural roles.
- `39be40f0` — the `source_binding` out-parameter, three telemetry events, and
  the `BackendEvidence` / `BackendCounterDelta` surfaces.
- this note and transcript.
