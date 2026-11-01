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
