# Bounded product-tree checkpoints

The allocator phase probe on262,144 OM multiplicity facts measures9,437,184B raw
input,26,216,104B when all product trees are built and26,217,128B over the complete
numerical prover. The approximately100B/fact product tree dominates; merely
consuming the original input cannot deliver a peak-memory multiplier.

The additive numerical `proveBatchCheckpointed` API retains even product-tree
levels and the output, regenerating each missing odd level once from the retained
lower checkpoint during top-down proving. The original `proveBatch` and production
child selection remain unchanged. There is no transcript/configuration change.
Original adjacent-pair arithmetic builds and regenerates every value. Caller input
ownership remains borrowed and immutable, including through every allocation error.

Mixed-height, all-kind Q/OM tests compare the entire proof, terminal artifact and
next transcript draw; independent numerical verification checks every terminal
MLE against the original inputs. Exhaustive allocation failures exercise partial
construction and regeneration cleanup. Safe/Fast pass. Initial non-fused mixed OM
peak7,706,304→6,063,465B (1.271×); Q3,986,672→3,163,497B (1.260×). These are requested
live allocations of numerical fixtures, not process RSS or whole-prover claims.
Further fused-build and consuming-leaf experiments require separate measurements
and parity/ownership gates before any production selection changes.

The fused builder now applies the original adjacent-pair fraction addition twice
per output quartet, with the same base-numerator specialization. No odd N/2
matrix is materialized during construction. Dense high-coordinate Q/OM inputs,
signed/zero weights and zero denominators compare exactly against two original
reductions. Mixed all-kind peak is now OM7,706,304→5,598,015B (1.377×),
Q3,986,672→2,934,527B (1.359×). Small numerical timing is effectively similar and
not a throughput qualification. Safe/Fast numerical parity/fresh/OOM gates pass.

`STWO_ZIG_GKR_TREE_CHECKPOINTS=2` explicitly selects the alternative in the local
child. Unset/empty keeps the original dense tree; any other nonempty value fails
with `InvalidGkrTreeCheckpointPolicy` before allocating raw input matrices. This
is an operational storage choice only; proof/config/profile bytes do not change.
`STWO_ZIG_GKR_TREE_METRICS=1` additionally logs requested numerical and including-
binding peaks for either path. Existing conservative admission stays unchanged.
Actual services child/lifecycle Safe passes with stride2, Fast with default dense.
Production default is not promoted by these fixtures.

## Real first-shard stride-two experiment

Pinned source efe66efe9; same binary, q70/P26/OM31/fold4,16 workers, one resident
CPU0 shard of4,194,303 instructions. Dense/stride2/stride2/dense fresh processes
used the shared heavy-proof lock; unrelated host workloads were not controlled.
All four durable files (physical proof, child stage-one file, bundle and cells)
are byte-identical across all four runs, and every independent receiver accepts.

| CPU0 measure | Dense | Stride2 |
|---|---:|---:|
| Numerical requested allocation peak |12.616GB |8.847GB |
| Process peak RSS |18.259GB |15.232GB |
| Mean source+prove |8.481s |8.887s |
| Mean numerical phase |1.722s |2.123s |

The numerical peak improves1.426× and whole-process RSS about1.199×. Raw input
planes are still4.542GB in both experiments. Missing-level regeneration costs
about23% more numerical time; total proving is4.8% slower in this sample, within
prior approximately7.5% host variation. This is a measured memory/time tradeoff,
not a whole-prover1.5× gain or a reason to promote the default. Consuming leaves
and metadata-only terminal binding remain a separately qualified next slice.

## Consuming leaves and metadata-only terminal binding

The opt-in stride2 child now transfers the input layer headers and owned MLEs to
`proveBatchOwnedCheckpointed`, which consumes them on success and failure. The
borrowed/default APIs preserve their immutable caller-input contract. The owned
multiplicity denominator uses the separately qualified owned-D fold; it may keep
its original physical backing when the recycler reports a logical shrink.

After numerical proving, terminal binding replays the existing durable native
metadata through the original `RowSink`. An explicit projection mode hoists
lane-Eq times relation coefficients once, then accumulates M31 tuple products
into the exact weighted N+etaD form. No full N/D planes, tuple planes, MAIN copy
or FFT is rebuilt. Row0 discovers the bounded relation roster, and every replayed
row must match that roster and canonical base encoding. Padding still contributes
N=0,D=1. The original Eq generation and logical-prefix/carry kernel is shared.

Safe/Fast tests compare matrix and metadata-derived binding planes exactly,
reject altered final-row metadata, exercise every namespace with signed/zero
weights and padded lanes, and check noncanonical tuples. Consuming mixed-height
Q/OM numerical proofs, artifacts and next draws match the borrowed path; fresh
terminal verification and exhaustive allocation failures pass. Full child Safe/
Fast suites pass with opt-in stride2. No default or admission estimate is changed
by this slice; actual requested peaks and physical RSS require another benchmark.
