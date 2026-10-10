# Bounded asynchronous capacity-native leaves

The capacity native callback previously freshly verified native proof bytes,
built recursive rows, proved a leaf, encoded it and freshly verified the leaf
before returning. This source batch separates the native capture boundary from
leaf publication. Root has connected the queue to the canonical capacity CPU
driver, including success finish, failure join and report counts. Source-agent
work ran no tests, STARK, segment, device or benchmark; focused root qualification
results are recorded separately in `capacity-canonical-integration-*` receipts.

`block_v5_native_capacity_recursive_stage_v1.ForBackend` now exposes:

- `captureNative(a, *const Native.Proof, *const Prepared, Options)` returns an
  actual owned `Native.VerifiedCapture` from the original borrowed verifier.
- `publishFromVerifiedCapture(a, *const Native.VerifiedCapture, *const Prepared,
  Options, Sink)` borrows that capture, validates its mutation seal and the full
  independently admitted shape/template/catalog/source seal, prepares genuine
  rows and proves through the same cache/cold path. It encodes and freshly
  verifies the recursive leaf before transferring the artifact to the sink.
- Existing `publish` composes these two functions and retains its old behavior.

The new `block_v5_native_capacity_leaf_queue_v1.ForBackend(Cpu)` exposes
`start(a, pool, prepared, leaf_options, sink, queue_options, external_boundary)`,
`enqueueProof(index, proof)`, `finish`, `abort`, `deinit`, `boundary`,
`requireHealthy` and `snapshot`. A single foreground producer calls enqueue
while the original native proof is live. Backpressure precedes capture
allocation. On successful enqueue only the owned capture moves; the queue
never retains the native proof, replay owner, source PCS or commitment lease.
The ring holds at most `capacity` waiting captures and one ordered active
coordinator. The canonical source default is `capacity=1`. Captures and
recursive allocations use the existing shared hard host-budget allocator.
No guessed capture-byte reservation is added as admission authority.

The generic owned coordinator destroys every transferred payload exactly once
on success, callback error or cancellation. Submit error leaves ownership with
the foreground caller. A callback failure closes publication and queued owners
are destroyed after the coordinator is joined. Abort waits for the active
callback; stage boundaries reject cancellation before subsequent publication.
Exact index order and the independently supplied expected count are enforced.
Whole leaf jobs use one coordinator bound to the driver's existing helper pool,
so they do not occupy helper workers needed for nested structured proof tasks.

The prepared array and every borrowed shape/public/log/catalog/seal array, one
setup cache, pool, leaf sink and forest stream must survive finish/deinit.
Root driver wiring starts the queue after family queue/cache/sink construction,
passes `families.boundary()` as external health authority, checks both queues
at warm and native boundaries, and enqueues at the native proof callback.
Success finishes leaves before family statistics/cache teardown, exact leaf
completeness and manifest writing. Errors abort/join before those lifetimes end.
Only this ordered worker uses the leaf cache and `Leaves.put` publication.

Statistics are actual submitted/completed/cancelled/queued/active jobs plus
`peak_pending` and `peak_owned` queue-owned jobs. They exclude foreground
verification's temporary capture allocations and do not imply block timing or
an RSS bound. Shared host-budget checks remain the allocation authority.

Six nonproving fixtures cover transferred ownership/order/backpressure,
retained rejected ownership, first callback error and queued destruction,
inflight cancellation/join, empty/incomplete counts and option admission,
allocation failures/external cancellation, and retained actual capture/stage/
queue function bodies without invoking them. Root qualification command:

```sh
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/frontends/riscv/block_v5_native_capacity_leaf_queue_test_root.zig 'block-v5 capacity leaf queue'
```

No capacity proof grammar, receipt, template, source seal or bus equation changes.
The existing synchronous API remains available for explicit callers. Canonical
source selection does not establish successful genuine proof execution or runtime
performance; neither may be inferred from the callback fixtures.
