---
title: Native BLAKE3 preparation allocation caps and partial failure cleanup qualified
author: Teddy Pender
created_utc: 2026-09-22T04:46:04Z
---

# Native preparation host-allocation admission

SharedHostBudget composes the existing live-byte HostBudgetAllocator with Zig's
ThreadSafeAllocator. Its heap-stable control object owns counters and callbacks;
snapshots take the same lock as allocation/free. It is destroyed only after all
routed allocations are released and allocator users are joined. The control
object itself is outside the cap, and its child allocator must support other
concurrent users that bypass this mutex.

Canonical preparation exposes prepareBounded. It runs the existing prepare path
through this allocator, including intermediate graphs, evaluations and row
materialization. On success Prepared owns the budget until row destruction; on
failure partial preparation teardown precedes budget destruction. Budget denial
is reported as PreparationHostBudgetExceeded. Ordinary child allocator exhaustion
retains OutOfMemory. prepareAndSend now requires an explicit host byte limit and
uses this bounded path before transferring its owner through the existing queue.

Budgeted Prepared.retainedBytes uses remaining tracked allocations plus control
and Prepared metadata. This includes arena backing headers, unlike queryCapacity
alone. Borrowed child captures, thread stacks, allocator overhead, queue slots,
other jobs, retained proving plans and proof allocations remain separate. This
is an enforced cap on routed host allocations, not a process RSS ceiling or
complete multi-job scheduler admission.

## Qualification

```sh
zig test src/prover/host_budget_allocator.zig -O ReleaseSafe
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Unit tests: 4/4 passed, including exact live-byte boundaries, child allocator
failure, resize/remap and freeing a budgeted allocation on another thread.
Initial native run passed with an immediate one-byte rejection. The final gate
adds partial-construction denials at 64 MiB and 512 MiB before the successful
2 GiB path: exit 0, 4/4 steps, 3/3 tests, 42 s / 2 GiB; compile 1 min / 5 GiB.
No allocator leaks. Destroying a budget also checks that tracked live bytes are
zero, covering teardown on these failed and successful paths.

Observed successful canonical preparation:

| Measurement | Bytes |
| --- | ---: |
| Preparation allocation cap | 2,147,483,648 |
| Peak tracked preparation allocations | 1,242,103,479 |
| Charged retained prepared owner | 461,491,879 |
| One-slot ready queue byte limit | 536,870,912 |

These are diagnostic workload measurements, not production sizing guidance.
The owner crosses the worker/consumer boundary and feeds two independently
verified parent proofs with the existing reusable plan/workspace. Both artifacts
remain 111,428 bytes; key remains
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
Child q1/PoW0 and parent q8/PoW0 remain unchanged. No speed benchmark ran.

## Next

Combine per-preparation caps and ready retention with total reservations for
active proving, retained plans and workspaces; bind explicit proof worker pools
and qualify actual preparation/proving overlap. Existing WorkPool supports a
one-worker scoped pool; the older ProofExecutionPool convenience helper skips
binding for one worker, so it cannot alone establish a serial global-pool bound
outside tests. Use the explicit scope when integrating BLAKE3 worker admission.
The existing execution-key-bound level policy remains the scheduling authority.

Production security/key integration, binary/parent-of-parent and Metal remain
unfinished, as do the original fused PCS/DEEP and final-layout witness goals.
Logs and source snapshots are pinned by relative SHA256SUMS.
