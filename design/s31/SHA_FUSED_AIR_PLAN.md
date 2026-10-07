# Fused SHA256d AIR: next proving-speed experiment

## Measured reason to try it

The shift-register SHA AIR in the one-proof Bitcoin header profile uses 93
fixed, 521 main, and 140 interaction columns. In the matched seven-pair
production run, proving took a median 187 ms after excluding the 20-bit
interaction and 26-bit FRI proof-of-work grinds. An earlier generic circuit
run took about 154 ms under the same source, assignment, public output, and
FRI settings, though its package timing path differed. Rerun both through
one harness before claiming a final comparison. The shift profile reduced
proof size and verification time against the preceding dedicated SHA profile,
but does not yet beat the generic
circuit on proving time. See the v3 measurement record for raw samples.

Most SHA columns live in three separate, structurally identical compression
calls. Their 128-row tables reserve space for one 68-row shift-register
execution each. The resulting roster has 24 AIR components, including
separate schedule/round and feed-forward word buses. This plan tests whether
one call-indexed trace and fewer word buses lower FRI composition and
opening cost enough to beat the generic circuit.

## One trace for three calls

Use a 256-row table with three 68-row segments. For call `c` in `{0,1,2}`,
let `base=68*c`. The first three rows are state history; rows
`base+3..base+66` execute 64 compression rounds; row `base+67` holds the
terminal `a,e` pair. Rows 204..255 are zero padding. A fixed call ID and
selectors identify each segment. The SHA state at active row `r` is still

```text
(a[r], a[r-1], a[r-2], a[r-3], e[r], e[r-1], e[r-2], e[r-3]).
```

Schedule word `W[t]` for round `t` sits in the same row as its round,
`base+3+t`. The first 16 words are input rows. For `t>=16`, the schedule
equation opens `W[t-2]`, `W[t-7]`, `W[t-15]`, and `W[t-16]` from the same
committed word-bit columns. The round equation consumes the current word
bits directly. This removes the 64-event schedule-to-round lookup per call.
The current SHA round's two half-word columns also become unnecessary:
the equation computes both halves from the current 32 schedule bits.

The fixed selectors must enforce all of these domain boundaries:

- The round transition is active only at `base+3..base+66`; its next-row
  opening therefore cannot cross a call segment or the circle boundary.
- Schedule recurrence is active only at `base+19..base+66`; its farthest
  `-16` opening remains inside the same call segment.
- History, terminal, and padding rows have no round or recurrence event.
  All unused committed bits and carries are constrained to zero.
- A canonical verifier-derived fixed root binds all selectors, constants,
  call IDs, round indices, and word-bus signs. These are never witness
  choices.

The caller's 80 header bytes, the three initial SHA states, the three
terminal states, and the final digest still need authenticated custody.
Keep word events for those boundaries, with the call ID in every tuple.
The feed-forward computation may initially remain an eight-row component
per call; only remove an event after its replacement is constrained in the
same AIR and its surrounding bus claims still close. The circuit Gate claim
must close in the same STARK transcript as every remaining SHA word claim.

## Expected cost and acceptance gate

This layout stores one 256-row copy of the 64 `a/e` bits, 12 carry bits, and
36 schedule bits, or about 112 main columns in its fused round/schedule
table. The comparable three separate tables store approximately
`3 * 128 * (78 + 36)` cells. The proposed table stores `256 * 112` cells,
roughly a third fewer for these two operations. This is a trace-cell estimate,
not a measured proving gain; other caller, feed, circuit, and lookup columns
remain. The fused component may also be more expensive to evaluate per row.

The acceptance gate is a matched production FRI 26/70 benchmark against the
generic circuit and the v3 shift profile, with separate interaction and FRI
proof-of-work times. Report raw runs, medians, stage times, proof bytes,
verification time, and OODS opening counts. Require native verification of
the full joined proof, independent SHA256d test vectors, and mutation tests
for each call's history, schedule predecessor, carry, terminal word, call ID,
selector, word claim, public root, source key, and serialized proof. Keep v3
as the known-correct oracle until the fused profile passes those checks.

If the fused profile fails to improve proving speed materially, inspect FRI
composition and PCS opening stages before changing the AIR again. In
particular, duplicate fixed columns are small 128-row tables; sharing them
alone is unlikely to save much if the sparse circuit's large fixed columns
dominate its commitment time.
