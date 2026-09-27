---
title: Native preparation allocation budget lifetime problem match
author: Teddy Pender
created_utc: 2026-09-22T04:39:48Z
---

# Native preparation allocation budgets across handoff

Task: enforce a preparation's host-allocation cap before constructing intermediate
witnesses and preserve its allocator owner through queue and consumer destruction.

Canonical mechanism: existing HostBudgetAllocator live-byte admission, composed
with std.heap.ThreadSafeAllocator for synchronization. This is an allocator/lifetime
adaptation, not a new memory scheduling algorithm. Existing source paths are
src/prover/host_budget_allocator.zig and Zig std/heap/ThreadSafeAllocator.zig.

A heap-stable shared budget owner wraps counters and allocator callbacks; all
snapshot reads use the same mutex. Prepared owns this control object after
successful construction and frees row arenas before destroying the budget. On
failure all partial preparation allocations must be released before control
teardown. Limits cover allocations routed through this allocator, excluding the
control object, borrowed captures, thread stacks and other workers. Queue charges
can use exact remaining live allocation bytes for budgeted owners.

Prediction: over-budget preparation fails before the denied allocation, with no
leaks or loss of queue ownership. Existing canonical preparation remains the sole
implementation. No speed prediction; this is needed for correct admission.

Validation: exact limit, failed allocation, cross-thread free and snapshots;
real native preparation rejects a tiny budget then succeeds under a stated host
cap and crosses the handoff before parent proving/independent verification.
Total multi-job reservation and CPU scope integration remain subsequent work.
