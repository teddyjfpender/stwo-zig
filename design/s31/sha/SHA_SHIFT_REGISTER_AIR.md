# Shift-register SHA round AIR: next performance experiment

## Why this is the next chip

The direct SHA round AIR is correct in a joined native proof, but it commits
eight 32-bit state words on every round row. Six words are copies of prior
state. The current version eliminates the separate 32-bit `T1` witness and
uses 270 main columns per call; three calls still account for 810 of the
joined proof's main columns. A trace that stores only the two changing words
`a` and `e` can recover the other six from earlier rows of the **same
committed trace**. This is a new AIR layout, not an unverified prover shortcut.

## Trace and hand example

Use a 128-row table for each of the three SHA-256 compression calls. Its
logical rows 0–2 are history, rows 3–66 perform SHA rounds 0–63, and row 67
contains the last `a,e` pair. On each row store Boolean bits for only `a,e`,
four three-bit carries, and the private schedule word's two 16-bit halves:
`64 + 12 + 2 = 78` main columns before any further optimization.

| Logical row | Stored `a` word | Stored `e` word | Role |
| ---: | --- | --- | --- |
| 0 | initial `d` | initial `h` | history |
| 1 | initial `c` | initial `g` | history |
| 2 | initial `b` | initial `f` | history |
| 3 | initial `a` | initial `e` | round 0 |
| 4 | round 0's next `a` | round 0's next `e` | round 1 |
| 67 | round 63's next `a` | round 63's next `e` | final history |

At round row `r`, the SHA state is obtained from the committed openings
`(a[r], a[r−1], a[r−2], a[r−3], e[r], e[r−1], e[r−2], e[r−3])`. For example,
at row 3 this is precisely `(a,b,c,d,e,f,g,h)` from rows 3,2,1,0. The
round equations constrain `a[r+1]` and `e[r+1]`; advancing one row shifts
the other six words automatically. The terminal state is read from rows
67,66,65,64 in that order. Padding rows 68–127 are zero and have no round,
schedule, or state events.

For each 16-bit half, let

```text
A = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
E = d + A
B = A + Σ0(a) + Maj(a,b,c)

low(E): sum_low(A) + d_low             = next_e_low + 65536*cE0
high(E): sum_high(A) + d_high + cE0   = next_e_high + 65536*cE1
low(B): sum_low(A) + Σ0_low + Maj_low  = next_a_low + 65536*cA0
high(B): sum_high(A) + Σ0_high + Maj_high + cA0
                                         = next_a_high + 65536*cA1
```

All source and destination halves are reconstructed from Boolean bits. The
largest integer side has seven 16-bit addends and a carry, below `2^19` and
far below the M31 modulus `2^31−1`. Each carry is encoded by three Boolean
bits. The equations therefore implement the intended additions modulo
`2^32` without field-wrap aliases. `Σ`, `Ch`, and `Maj` use the existing
Boolean polynomials; their selector-gated degree stays within the q2 split.

## Lookup custody and verifier checks

The caller already supplies the eight initial state words and receives the
eight terminal words through the SHA word bus. The shift-register round chip
must consume initial state words from rows 0–3 in the order above and emit
terminal state words from rows 64–67. It must consume `W[t]` from the
schedule on rows 3–66, using the verifier-pinned round index `t=r−3`.
These are 80 signed events per call. At most three events are emitted on one
row (two state events and one schedule event), allowing a smaller round
LogUp than the current nine-slot layout. Call IDs, addresses, role selectors,
and signs remain fixed by the verifier's canonical preprocessed commitment;
word values come from the round's committed main columns. All word claims
must close with caller, schedule, and feed-forward inside the same STARK.

The verifier must sample row offsets `−3,−2,−1,0,+1` from the **same** round
polynomials. It must use the PCS-lifted trace step for OODS openings and the
trace-row offset on the quotient domain. The first three and last four rows
need fixed selectors so an active round cannot cross the circular boundary.
Zero padding and Boolean constraints must cover all rows, including history
and terminal rows. The key must bind the new layout, fixed root, component
roster, and public-output ABI; it cannot accept a proof-selected layout.

## Acceptance and measurement

1. Compare every row's reconstructed state, schedule word, and terminal
   state with independent SHA-256 compression vectors, including non-IV
   initial states. Mutate each history word, a middle transition, final word,
   carry, `K`, schedule word, selector, and padding row.
2. Prove and natively verify the isolated chip and its word LogUp, then join
   all three calls with the caller and sparse-wide Bitcoin circuit. Reject a
   changed private header, public root, proof claim, source key, and proof
   bytes. Test both digest visibility modes; the private-digest statement is
   the benchmark target.
3. Benchmark the same Bitcoin source, witness, production FRI settings, and
   public ABI as the existing generic circuit. Record column widths, OODS
   openings, prover stage times with proof-of-work separately identified,
   verification time, and proof bytes over repeated runs. A width estimate
   is not a speed result.

The round main width is 78 rather than 270 columns. Replacing three round
tables removed 576 main columns from the joined layout; the smaller round
bus also reduced interaction width. The full private-digest circuit proof
passed native verification. In the [matched v2/v3 SHA comparison](../measurements/sha/bitcoin-sha-shift-circuit-v3-private-digest-2026-10-07.json),
v3 proved 16% faster after excluding both proof-of-work grinds, verified
30% faster, and produced a 31% smaller proof. The v2 direct SHA path remains
the correctness oracle for further changes.

The generic circuit benchmark previously timed its prover *after* building
a reusable fixed-column commitment. The v3 SHA test initially timed that
commit inside proving. The SHA prover now accepts a `PreparedFixed` tree
built from its canonical fixed columns and checks every column and PCS
setting before leasing it. Its proof still uses the independently derived
fixed root and native verifier. Report both warm proving and one-shot proving
for **each** profile; subtracting a stage estimate is not a warm proof test.
The earlier v2/v3 measurements also used Zig test mode, which disables the
production worker pool, while the older generic package used a production
executable. Their cross-profile times are not a matched speed comparison.
The [five-trial production executable comparison](../measurements/bitcoin/bitcoin-generic-vs-sha-shift-matched-v1-2026-10-07.json)
now uses the same source, assignment, public output, FRI 26/70 settings,
allocator, and native verification. Median warm proving after excluding both
PoW grinds was 160.36 ms for generic and 42.62 ms for v3, a 3.76× ratio on
this header. With each canonical fixed commitment built inside the timer,
the medians were 175.69 and 46.76 ms. The v3 proof was larger (502,783 versus
338,282 bytes) and native verification took longer (7.14 versus 4.08 ms).
These are local latency measurements for one fixed witness, not a throughput
or recursive-proof result.
The [fold-step-4 experiment](../measurements/sha/bitcoin-sha-shift-fri-fold4-experiment-2026-10-07.json)
passes native verification and reduces non-PoW work in three paired runs,
but the production package remains pinned to fold step 1. Its fixed header
had a much slower FRI nonce at fold step 4, so those paired runs do not
establish lower wall time or throughput.

## Admission and privacy boundaries

The full circuit verifier must receive a sealed verification key derived by
an independent compilation of trusted source. A key can be internally
consistent while carrying an arbitrary `source_digest`; the digest alone does
not prove which source produced the circuit topology. The package build must
bind the source digest to the compiled topology and publish that key as the
verifier's trusted input. A prover-supplied key is not sufficient.

The isolated SHA verifier leaves the circuit Gate claim open. It is useful
for testing the SHA components, but only the full joined verifier establishes
that the header consumed by SHA is the one used by the S31 circuit. The full
verifier also enforces the production FRI configuration outside tests.

The digest and header are absent from the *public statement*. The current
proof uses unmasked trace commitments and openings, so this is not a
zero-knowledge confidentiality claim about the private witness.
