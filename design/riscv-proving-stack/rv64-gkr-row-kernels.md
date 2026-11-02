# Bounded GKR row work on the caller's existing pool

A live two-second sample of the first actual 4,194,303-step OM prefix placed all
181 active-worker samples in GKR sumcheck, mostly OM31 multiplication, while the
existing pool helpers slept. This was the experimental q70/P26/fold4 profile,
not a throughput baseline or a security-qualified production profile. Its
143.34-second proof time exposes a severe serial arithmetic bottleneck.

The row reductions and MLE variable folds now use bounded contiguous partitions
on that same scoped pool. At most16 shards retain stack-local contexts and two
secure partial sums each. Their fixed requested heap growth is zero. Helpers
have no transcript or allocator access; the caller joins them before reducing
partial sums in ordinal order and drawing the next challenge. No global pool is
created, no lease is awaited, and unavailable leases or an active cooperative
queue fall back to scalar execution. Pool-owned stacks and submission slots are
already bounded by the caller's admitted pool.

The OM path also preserves base-field numerators through the leaf projective
cross-products. Previously its helper promoted M31 numerators to OM31 despite
already storing them as M31; the bottom product tree did the same. The exact
cross-product law now uses OM31-by-M31 multiplication. Numerators genuinely
become extension elements after a sumcheck challenge fold; no range or
canonicality claim is dropped.

Qualification compares complete mixed-height, four-gate proofs and the next
transcript draw at1/2/4/8 workers, with full fresh terminal-MLE checks. A separate
capture imports the pre-change prover source and checks identical proof
serialization for QM31 and OM31. Existing exhaustive allocator-failure and owner
lifetime tests remain part of the gate; the row scheduler allocates no heap.
All arithmetic operations remain in the original per-row authority.

Reproduce portable qualification with `zig build test-native-cpu-gkr-rows
-Doptimize=ReleaseSafe` and ReleaseFast. The external capture uses
`src/prover/gkr_parallel_capture_root.zig` with an independently supplied
`baseline` module pointing at pre-change `lookups/gkr_prover.zig`; the receipt
records its exact command and source identity. This optimization changes no
proof protocol or security parameters. Actual Ethereum prefix A/B measurements
are required before making a large-run speed claim.
