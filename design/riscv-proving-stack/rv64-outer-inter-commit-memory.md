# Joined INTER ingress retirement

The largest production outer leaf observed on block 26,235,159 has 53,477,376
variables and component logs 18,24,20,21,23,16,20,8,14,18,16. It completed resident
MAIN and INTER generation, then failed while committing INTER under the 28GiB
native context cap. Accepted native proofs and earlier recursive nodes remain
reusable; this failure does not require restarting native proving.

At that geometry the old source-only overlap was:

| Allocation | GiB |
|---|---:|
| Retained MAIN coefficients | 2.553|
| Raw INTER evaluations, including per-component prefix plane | 5.790|
| New independent INTER coefficients | 4.895|
| 2n INTER LDE, twiddles and descriptors | 10.040|
| Merkle tree and prefix-state scratch | 5.000|
| Total before immutable/runtime storage | 28.278|

These are source-derived allocation sizes, not sampled device memory. Even
without immutable fixed/schedule storage the old overlap exceeds 28GiB.

An optional typed `TraceInputRetirement` now lets INTER's owner retire consumed
input buffers after coefficient ingress has joined, before LDE/tree allocation.
The compact coefficient lease has separate ownership. Source range/scope/token/
generation validation and all D2D copies happen before retirement; no input
pointer is read afterwards. Scalar column headers stay live until commitment
metadata is complete. The source-only overlap falls to 22.488GiB, leaving room
for the fixed/schedule cache and runtime. The context cap stays 28GiB.

The callback is scoped, owner-thread-only and restricted to INTER with the
established separate-coefficient beta 1 path. MAIN retains its evaluations for
INTER readers. Other callers keep the same default path. A failed ingress join
never invokes retirement; a callback failure aborts commitment and cleans the
untransferred coefficient lease. Partial source releases retain their remaining
custody for failure cleanup, without releasing a successful lease twice.

Host qualification checks joined ordering, sync/callback failure propagation,
wrong-scope refusal and partial-release cleanup while preserving headers.
Production recursion semantic checking passes. Real proof-byte and largest-leaf
qualification is a separate gate; this change introduces no AIR, transcript,
kernel or proof-profile change.
