# CUDA managed-arena capacity experiment

The canonical Cairo CUDA prover ordinarily allocates one request arena from
the CUDA device pool. Admission rejects a plan larger than free device memory
minus the safety reserve. `STWO_CUDA_MANAGED_ARENA=1` enables a narrowly scoped
fallback: when the plan would fail that admission, its request arena is
allocated with `cudaMallocManaged`. Plans that fit still use the original
device-pool path. Cached and one-shot proof transactions use the same rule.

The native allocation is registered in the same proof-context ownership
ledger as ordinary device allocations, and the request still uses the same
resident slots, GPU kernels, transcript, proof output, and verifier. No host
read API or new witness authority is exposed. The fallback requires CUDA's
`concurrentManagedAccess` capability; otherwise allocation fails. It also
requires enough host memory for pages evicted from the GPU. The managed arena
is freed after the proof stream has completed.

This is an **out-of-core capacity experiment, not a claim of lower logical
memory or faster proving**. Page faults and migration can make it much slower,
especially when a kernel repeatedly touches more data than VRAM can hold. The
planner's `allocated_bytes` and `peak_live_bytes` remain unchanged. Report
sampled whole-device peak, host RSS, page migration (where available), proof
time, full-command time, proof hash, and independent verification separately.

`STWO_CUDA_MANAGED_PREFETCH=1` additionally tests an ordered residency policy
for managed arenas. It moves main/interaction coefficients toward the host at
constraint evaluation, then prefers coefficients for OODS and evaluations for
quotient. These are stream-ordered migration hints on the authenticated arena
slots. They do not copy witness data into host application code or change the
proof. Measure this separately from the plain managed fallback: on a dense
PIE the extra transfers may outweigh avoided page faults.

`STWO_CUDA_MANAGED_PLACEMENT=throughput` or `capacity` selects a separate
research placement policy for an oversubscribed managed arena. Both place
committed coefficients on the host until OODS. `throughput` moves lookup
inputs after the writers finish and host-places the main evaluations after
commitment. `capacity` places lookup inputs on the host **before** the writers
begin and places both evaluation arrays on the host **before** their
commitments. The latter can slow trace generation or commitment but lowers the
observed device peak on Pedersen-dense PIEs. A policy cannot be combined with
`STWO_CUDA_MANAGED_PREFETCH=1`. Every placement change synchronizes the proof
stream before reusing an aliased span; the barriers appear in
`managed_policy_sync_calls`. These policies do not change the 103.367 GB
dense-PIE arena reservation, proof bytes, or source authority.

On one 80 GiB H100 SXM, the `capacity` policy lowered the sampled GPU peak
from 79.177 to 56.487 GiB for `15590913_15590913` and from 79.177 to
48.362 GiB for `15582797_15582797`. Both proofs matched the managed baseline
byte for byte and passed the independent Rust verifier. The observed peaks
are 250 ms samples, and these are single diagnostic trials, not latency
rankings. The selected receipts and full experiment comparison are under
[`vectors/reports/cairo-cuda-h100-managed-20261007`](../vectors/reports/cairo-cuda-h100-managed-20261007/README.md).

The dense PIE still exceeds a 48 GiB budget; the second case is also just
above that line, before allowing for other device users or reserve. The
dense PIE's lookup slab is 27.87 GiB,
and `partial_ec_mul_window_bits_18` alone accounts for 15.59 GiB of lookup
output. Retiring lookup data after each whole component did not lower the
peak: that one writer still fills too much memory before it can be retired.
Further reduction needs bounded row chunks in that writer, plus streaming or
replaying the main and interaction LDE evaluations during constraint,
quotient, and decommitment. Host placement is a useful capacity fallback,
not a substitute for those shorter live ranges.

Initial discriminating cases are the exact canonical inputs
`15582797_15582797` (88.627 GB planned arena, 109,817 distinct Pedersen
keys) and `15590913_15590913` (103.367 GB, 193,076 keys). On an 80 GB H100,
the first should fail the ordinary capacity gate. The managed trial counts
only if it produces the same proof bytes as the native H200 lane and an
independent verifier accepts them. If it finishes but is prohibitively slow,
the next architectural target is the simultaneously live main and interaction
coefficient/evaluation arrays at constraint evaluation, followed by quotient
and decommitment. Replaying only retained lookup inputs cannot remove this
later peak.

The upstream PIE producer should also run the registry-bound
`cairo-trace-geometry` and `cairo-pie-construction-plan` tools before admitting
already baked candidates to an H100 queue. They can avoid a Pedersen padding
cliff by choosing different complete-block boundaries; a single oversized
block still needs an out-of-core backend or a future sound execution split.
