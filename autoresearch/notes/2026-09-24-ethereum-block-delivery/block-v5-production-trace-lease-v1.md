# Production sorted-memory trace lease

`block_v5_memory_compact_replay_v1` now exposes `openTraceSource(sorted)`
for both compact and packed36 replay producers. The owning lease keeps the
sequential reader and partitioner at a stable address and provides the typed
artifact `Source` required by the lightweight block producer. It retains no
returned trace, PCS columns or proof receipt. Collected plan metadata must
outlive the lease; each loaded trace belongs to its consumer.

`requireFinished()` rejects partial consumption. The existing load path still
checks instance order, exact collected claims, partition exhaustion and total
event count, and closes the underlying reader when exhausted. `deinit()` also
closes a partially consumed reader. The ordinary `prove()` method delegates
to this same adapter rather than maintaining a second replay path.

The existing real sorted compact Replay proof/receiver fixture passed 4/4
under ReleaseFast/native, with clean `std.testing` allocator teardown:

```
python3 autoresearch/notes/2026-09-24-ethereum-block-delivery/test_sha_memory_proof.py --root src/frontends/riscv/block_v5_memory_replay_adapter_test_root.zig 'block-v5 compact real Replay'
```

This qualifies the compact instantiation with four real memory accesses and
fresh memory/range proofs under diagnostic q8/PoW0. Its unrelated execution
roster pins are fixture metadata. It does not qualify packed36 orchestration,
global block closure, canonical security or block performance.
