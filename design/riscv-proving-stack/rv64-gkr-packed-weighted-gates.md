# Packed weighted GKR gates

The remaining prefix GKR time was concentrated in its numerical circuit and
sumcheck work. The compact-public-aux receipt measured2.155s numerical of2.701s
GKR, against5.100s native completion. The matched16-worker QM31 classic control
proved in5.252s; that comparison also changes the secure field, so it does not
isolate GKR overhead or establish an equal-security speed claim.

A weighted binary LogUp gate uses `nA*b+nB*a+lambda*a*b`. Factoring it as
`(nA+lambda*a)*b+nB*a` removes one secure multiplication when numerators are
secure, including its evaluation at both sumcheck sample points. Including Eq
weighting, generic points require four secure products rather than five.
Base-M31 leaf numerators save one secure-by-base product. Singles retain their
previous expression. Scalar tails and the independent scalar oracle are intact.

A separate concrete packed wrapper forces inlining of the existing packed
multiplication authority. Before the change, AArch64 emitted out-of-line calls
with128-byte operands/results copied through stack storage. GKR reduction,
next-layer, owned-fold and Eq helpers plus the existing packed binding dot now
use the wrapper. Generic field and circuit arithmetic are untouched. No new
buffer, pool, cache or transcript operation is introduced. The final binary
removed36 static packed-mul call sites from those paths; other grouped AIR and
classic witness calls remain. Other packed arithmetic methods were already
inlined, so no additional helpers were added for them.

All47 frozen-source capture tests pass, including Q and OM proof JSON and next
draw parity against unchanged5ada lookup source at1/2/4/8workers, with fresh
terminal verification. Safe/Fast numerical tests cover independent scalar
formulas, zeros, negative multiplicities, cancellation, unaligned ranges and
tails. The complete two-CPU plus Keccak/ADD/DOUBLE services fixture freshly
closes all globals under Safe/Fast.

Six alternating real4.19M-step prefix runs used identical16-worker q70/P26/fold4
control profiles with public auxiliaries and row-packed DEEP already enabled.
All24 physical/bundle/cell/manifest hashes matched and all six fresh prefix
receivers accepted.

| Median seconds | Baseline | Factored and inlined |
| --- | ---: | ---: |
| Numerical GKR | 2.073 | 1.706 |
| Total GKR | 2.585 | 2.210 |
| Complete proving | 9.016 | 8.444 |
| Binding witness | 0.304 | 0.300 |

These are shared-host observations. The final candidate run slowed broadly to
12.37s proving and3.25s numerical; it remains in the raw data and medians.
Binding showed no material gain. The two changes are measured together, so the
whole difference is not attributed to either one individually. This is not a
full-block, GPU or whole-protocol128-bit qualification. Raw measurements,
artifact hashes, source pins and the ABI audit accompany the receipt in
`vectors/reports/rv64-gkr-packed-gates-20261102/`.
