# Persistent native recursive request lane

The canonical native recursive setup cache now starts one coordinator thread
lazily and reuses it until cache destruction. Previously every prepared proof
request started and joined a new thread even when the authenticated setup worker
was already cached. Each request still returns synchronously after its callback
finishes; it retains the existing exclusive cache and worker leases.

The lane borrows caller-owned request storage only until that completion barrier.
Callbacks run outside the lane state lock. Concurrent or reentrant requests fail
without waiting behind their own callback. Busy shutdown leaves the lane live;
idle shutdown wakes and joins the thread before the cache destroys its worker,
schedule or shared budget. An unused cache starts no thread. The lane and cache
must remain at stable addresses after the first request.

The actual cache retains its existing admission, profile, schedule and dynamic
public-value checks. The worker's scoped helper-pool binding remains responsible
for each request; the caller's thread binding is unchanged. This change introduces
no additional proof concurrency within one cache. A live cache requests an 8 MiB
thread stack, which is separate from the logical heap budget.

Six focused checks pass: four concurrency/lifetime contracts, compilation of the
actual canonical cached/consuming proof and destruction bodies without invocation,
and one import check. The reuse fixture completes nineteen callbacks on one
thread, including a failed callback followed by a successful request. Other
fixtures cover in-flight borrows, busy destruction, reentrancy and closed lanes.

Evidence: `cpu-performance-gates-v1/native-recursive-request-lane-production-v2.log`
and `native-recursive-request-lane-qualified-v1.json` under the Ethereum block
delivery notes. No segment, STARK or recursive proof was run. Authenticated setup
cache hits during a real proof, complete forest overlap and end-to-end speedup
remain unqualified.
