---
title: Bounded native BLAKE3 preparation handoff qualified across threads
author: Teddy Pender
created_utc: 2026-09-22T04:37:05Z
---

# Bounded owned native preparation handoff

Canonical preparation now exposes prepareAndSend and an owned Handoff type.
The handoff is a mutex/condition-variable FIFO with fixed item capacity and a
retained-payload byte limit. Full queues block producers; failed sends preserve
their optional owner. Successful sends clear it. Receivers take exclusive
ownership. Graceful close drains queued work. Cancellation closes the channel,
wakes waiters and destroys queued owners outside its mutex. Already received work
belongs to its consumer. All users must be joined before queue destruction.

Prepared.retainedBytes charges sizeof(Prepared) plus row arena queryCapacity.
This is payload capacity accounting, excluding arena linked-list headers and
allocator overhead. Queue slot allocation is separate. It is not process RSS.
Preparation intermediates, blocked producers, active proving, retained plans and
worker scratch require separate scheduler admission. Allocators must support
cross-thread destruction for threaded handoffs.

## Evidence

```sh
zig test src/frontends/riscv/recursion/owned_handoff.zig -O ReleaseSafe
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Unit tests: 3/3 passed, covering FIFO/ring wrapping, byte admission and oversized
ownership preservation, graceful draining, concurrent sender cancellation and
queued cleanup, invalid limits and allocation failure.

Final native gate: exit 0, 4/4 steps, 3/3 tests, 41 s / 2 GiB; compile 1 min /
5 GiB. Canonical preparation runs on a worker thread, transfers its owned rows
through a one-slot handoff, then the receiving thread compares all rows and
context against independent State.finish and proves twice with the persistent
plan/workspace. Both artifacts traverse the codec and independent verifier.
The final artifact survives plan/workspace destruction. No allocator leaks.

Initial native gate rejected the prepared item with HandoffValueTooLarge under
a guessed 256 MiB queue limit. Re-running that same terminal test binary without
the build listener exposed the error name. The final test derives its limit from
the independently assembled reference parent: **461,491,639 bytes (~440 MiB)**.
This is observed diagnostic retained payload capacity, not a production budget.
The original rejected limit was not weakened in the queue implementation.

Artifact size remains 111,428 bytes; key remains
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
The child is q1/PoW0 and parent q8/PoW0. No speed benchmark ran.

## Remaining integration

This proves threaded ownership transfer, not simultaneous preparation/proving or
complete scheduler memory admission. Next wire this handoff to the existing
level/CPU/RSS policy and per-worker workspace, reserving queued and active memory
separately. Existing prover work_pool has a thread-local scoped_pool and prevents
unbound helpers from creating another global pool while explicit scoped pools
are active; retain that worker-budget discipline.

The diagnostic prepared-owner size is also evidence for the original direct
final-layout witness-generation priority. Binary/parent-of-parent, production
security profile/key integration and Metal qualification remain unfinished.

Logs, source snapshots and relative SHA256SUMS accompany this report.
