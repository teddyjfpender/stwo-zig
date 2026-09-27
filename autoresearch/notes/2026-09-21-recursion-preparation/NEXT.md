# Next experiment boundary

The unchanged final-parent denominator is about 7.06 s Metal. A 10x result
therefore requires about 0.706 s for the complete process, not 0.706 s for a
selected kernel. The current 5.57 s result still needs roughly another 8x.
For the complete eight-segment product, retain separate leaf, parent and total
boundaries; do not report summed parent work as parallel wall latency.

The qualified full-tree comparison is 116.63 to 102.13 s. Leaves now account for
61.77 s and parents 40.36 s. The tenfold **total-product** target requires reducing
both, not just the final parent. Next isolate recursive leaf preparation and
outer proving separately from native ingress before selecting a circuit change.

## Owned selected-lane authority

Current direct PCS/FRI row emission still constructs full multi-lane authority.
Next inspect `FriRowsAuthority.initFromProfiles`: reference authentication,
preprocessing and inactive evaluation costs are not yet individually timed.
A selected-lane owner must derive the same metadata, use counts and parameter
bindings from the independently admitted child; its opaque lifetime must prevent
mutation after admission. Do not cache proof-dependent values, merely trust a
caller-supplied digest, or remove the independent cold reference oracle.
Key-scoped compiled proving plans are a possible reuse boundary: authenticate
immutable geometry once and keep proof-dependent witnesses separate. Count cold
setup in the single-parent metric; if reuse is measured over a complete program,
include initial plan construction in that total. Do not compare a warm cache to
a cold baseline or treat an unbounded global cache as an optimization.
Hypothesis: reduce the remaining approximately 0.93 s authority phase and 0.64 s
row phase. Reject any mismatch for either lane, heterogeneous children, inactive
inputs, wrong geometry, provider events or fresh proof bytes.

## Fused PCS/DEEP verification

Before designing a new component, count events and committed padded columns
for PCS input, QM31 multiply-add, linear operations and opening-accumulate4.
Logical row bytes alone are not an objective. Match the actual verifier graph
to straight-line arithmetic circuit fusion/common-subexpression elimination;
compare larger DEEP quotient blocks against existing four-term accumulation.
Keep transcript and sampled-value bindings, query positions, denominator checks,
Merkle roots and final FRI equality explicit. A fused arithmetic equation without
those bindings would not verify the same statement.

This is a separate circuit-changing research lane: new authenticated component
identities, keys and AOT manifests; unchanged security parameters; fresh soundness,
mutation and CPU/GPU parity checks. It cannot claim the host lane's byte-identity
contract or reuse old admission pins. Start with one component and a complete
parent, then promote through both recursive leaf and parent products.

## Scheduling

The qualification gate intentionally serializes heavy producers with the build
lock. Do not simply put its calls in a thread pool and claim parallel proving.
A separate resource-bounded scheduler needs explicit concurrent producer
admission, per-process Metal state, peak aggregate memory measurements, complete
failure cancellation and wall/work accounting. Measure it after work reduction;
parallelism does not remove total circuit work.

## Development loop

Use `autoresearch/benchmarks/recursion/parent_pair.py` on pinned children for
complete-parent comparisons. Compile both arms before timing, one warmup per arm,
ABBA rounds and fresh standalone verification. Keep focused tests attached to
changed owners. Full trees run on promotion, not every edit. Preserve rejected
attempts and failures as evidence; never score archived timings as a live arm.
