---
title: Shared bounded scheduler qualifies BLAKE3 tree preparation and persistent proving overlap
author: Teddy Pender
created_utc: 2026-09-22T18:47:40Z
---

# Shared bounded BLAKE3 tree pipeline

The existing native-child pipeline's queue, cancellation, timing, resource
admission and producer/consumer loop now live in one adapter-driven implementation.
The native API delegates to that implementation; the tree adapter supplies
verified-node pair preparation and caller-admitted execution-parent proving.
There is one queue/worker mechanism rather than a second scheduler copy.

Tree jobs borrow two independently verified nodes and an admitted output key.
Preparation runs through the canonical tree fold under a reference-counted host
allocation budget. Its returned owner keeps the budget alive across the queue,
charges retained payload to the queue limit, and destroys columns before its
allocator lease. A context mismatch with the caller's admitted key rejects.
The worker independently authenticates fixed columns/root against that key.

The shared worker accepts an explicit protocol type, retaining its pool and
workspace across jobs. Identical keys reuse the immutable proving plan and
fixed commitment. Different keys build a replacement plan under the same host
budget and only swap after success; a failed replacement leaves the old plan
usable. A worker lease covers key replacement and proving together. Artifacts
retain allocator leases and survive worker destruction.

CPU admission reserves the proving workers plus one preparation worker. Memory
admission reserves preparation, the worker, a queued and an active prepared value,
external captures/owners, stacks and control storage. Actual routed allocations
are capped during both preparation and proving. These are routed-host budgets;
allocator overhead and backend allocations remain separate reservations, not an
OS-enforced process RSS limit. Production callers still provide their sealed
execution policy; the frontend qualification fixture supplies a local CPU/RSS
policy and checks the same shared admission equations.

## Qualification

Tree command:
`python3 scripts/zig_serial_build.py --cwd . test-riscv-blake3-aggregation -Driscv-test-filter=four-leaf -Doptimize=ReleaseSafe --summary all`

The tree command passed: 6 minutes build/test, 9 GiB peak RSS. Measured
preparation/proving overlap was 11,142,619,042 ns. Worker routed peak was
6,036,200,199 bytes under its 8,589,934,592-byte cap; combined admission reserved
25,794,988,912 bytes and three CPU tokens. Root artifacts remain 131,497 bytes.
These figures qualify resource control and overlap, not a comparative speedup.

The four-leaf fixture first verifies its two intermediate aggregates, then submits
two copies of the same root job to measure same-key plan reuse and actual overlap.
It rejects CPU/RSS overcommit, a one-byte preparation budget, an overlapping worker
lease and a wrong-root replacement key. Both produced roots and an independent
codec copy are verified after worker destruction. Their captures retain allocator
custody. This repeats one root workload; it is not two different production jobs
or a comparative speedup benchmark. Successful different-key replacement is not
yet covered by this fixture.

Production activation, complete tree/padding orchestration, precompile migration,
canonical recursion parameters, Metal parity and default Poseidon replacement
remain incomplete. The full original performance objective remains active.

Native adapter regression command:
`python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all`

Passed 3/3 tests: 1 minute compile / 6 GiB compile peak; 50 seconds execution /
1 GiB run peak. This includes native/default-suite segment parity, the old BLAKE3
parent's real bounded handoff and two-job pipeline, cancellation/failure checks,
persistent plan/workspace checks and output verification after worker destruction.
Native overlap is 2,403,698,791 ns and routed worker peak 982,008,191 bytes under
its 4,294,967,296-byte cap. This confirms that extracting the shared loop preserved
the native adapter's existing behavior.
