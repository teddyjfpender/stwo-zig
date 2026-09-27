---
title: Merkle layers included in native BLAKE3 worker allocation budget
author: Teddy Pender
created_utc: 2026-09-22T04:59:13Z
---

# Merkle layers honor explicit worker allocation budgets

SharedHostBudget now exposes an identifiable allocator vtable that forwards to
its existing synchronized implementation. The central Merkle layerAllocator
selector recognizes it and preserves that allocator for both small and large
layers. Unbudgeted callers retain the existing small-heap/large-mmap policy.
Budgeted callers use their chosen backing allocator; no thread-local/global
allocator override or second allocation-accounting implementation was added.

Regular and streaming builders already retain the selected allocator for final
teardown. Cached-tree reconstruction uses allocateLayers/freeLayers/fromLayers
with the same original allocator, preserving custody through adoption as well.

The known host Merkle-layer bypass is closed for explicitly budgeted calls.
This remains a routed-allocation cap, not total RSS: allocator overhead, thread
stacks, worker/control objects, borrowed inputs and external backend allocations
remain separate. Arbitrary wrappers around the identifiable budget allocator
are not automatically recognized; the canonical worker passes it directly.

## Validation

```sh
python3 scripts/zig_serial_build.py --cwd src/prover test-pcs-budgeted-merkle -Doptimize=ReleaseSafe --summary all
zig test src/prover/host_budget_allocator.zig -O ReleaseSafe
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

All final runs exit 0:

- Merkle gate: 3/3 tests (including root import), 824 ms / 2 MiB; compile 3 s /
  353 MiB. Small and mmap-threshold allocation denials obey the limit. A real
  tree matches the unbudgeted root, creates openings and frees every tracked
  allocation. The initial 4 KiB whole-tree fixture cap was insufficient for
  construction/opening scratch (OutOfMemory); the successful fixture uses 1 MiB.
- Allocator tests: 5/5 passed, including resize/remap and cross-thread/leased
  ownership with the new forwarding vtable.
- Native gate: 4/4 steps, 3/3 tests, 37 s / 2 GiB; compile 1 min / 5 GiB.
  Two proofs reuse the persistent two-worker plan/workspace; codec, independent
  verification and capture lifetime after worker destruction still pass.
  No allocator leaks reported.

Peak tracked worker allocations are now **1,632,926,982 bytes**, versus the prior
1,502,575,254-byte observation that excluded Merkle layers. The test worker cap
is 4 GiB. This is an accounting/allocator-policy change, not a speed comparison
or a production memory recommendation. Canonical artifacts remain 111,428 bytes
with diagnostic key
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
Child q1/PoW0 and parent q8/PoW0 remain unchanged.

Next: combine active/queued preparation and worker reservations under the existing
execution policy and qualify actual preparation/proving overlap. Production
security/key integration, binary/parent-of-parent and Metal remain unfinished;
the original fused PCS/DEEP and final-layout witness goals remain active.

Logs and source snapshots are pinned by relative SHA256SUMS.
