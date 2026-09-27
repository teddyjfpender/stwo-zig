---
title: Native BLAKE3 reusable worker workspace qualified
author: Teddy Pender
created_utc: 2026-09-22T04:27:42Z
---

# Reusable native BLAKE3 parent worker workspace

The standalone producer now exposes proveWithWorkspace. The original prove API
creates a zero-retention workspace and delegates to that same implementation.
A persistent worker can retain host witness/interaction staging allocations
between requests while sharing the existing authenticated fixed commitment.

Workspace begin uses an exclusive mutex lease; overlapping requests fail before
scratch allocation. Every admitted request resets scratch and releases its lease
on success or failure. Arena reset retains no more than the caller's configured
idle byte limit; unsuccessful shrinking falls back to freeing all storage.
This bounds idle retained scratch, not peak proof memory. PCS allocations and
proof outputs remain on the independent caller allocator. Direct use of the
workspace arena as output allocator is rejected. Plans, inputs and workspaces
must outlive synchronous proving; destruction requires exclusive ownership.

## Evidence

```sh
zig test src/frontends/riscv/recursion/blake3_native_parent_workspace.zig -O ReleaseSafe
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Both terminal exit 0. Workspace unit tests: 2/2 passed. Complete native gate:
4/4 steps, 3/3 tests, 41 s / 2 GiB; compile 1 min / 5 GiB. No allocator leaks
reported. Unit tests cover bounded retention, zero-retention release, overlapping
leases and recovery after allocation failure. The complete gate additionally
forces scratch allocation failure through the real producer, checks lease
release, rejects output/scratch allocator aliasing and proves twice with one
64 MiB idle-retention workspace. Both artifacts pass the canonical codec and
independent verifier. The final artifact is verified after destroying workspace
and plan; fixed commitment identity and plan arena extent remain unchanged.

Artifact size remains 111,428 bytes; key remains
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
Child q1/PoW0 and parent q8/PoW0 are diagnostic. No performance benchmark ran.
No production-default, binary/parent-of-parent, or Metal qualification claim.

## Next integration boundary

The existing recursive_pipeline_level_scheduler_v2 and
recursive_pipeline_worker_execution_policy_v2 already calculate ready-node
admission from CPU tokens and RSS reservations. They are integration-owned,
process-local policies and do not own proof leases. Their production activation
flag remains false. Reuse their admission rules when wiring BLAKE3 jobs; a new
unbounded worker pool would bypass the existing policy.

Still missing: a bounded prepared-row handoff, ownership transfer and cancellation
cleanup, explicit memory accounting for retained plans/workspaces and queued
preparations, and a real overlap qualification. Statement-specialized diagnostic
keys also mean a worker must match/admit each plan's exact key; shape alone is not
a valid cache identity. Idle scratch retention is not sufficient memory admission.

Sources and logs are preserved with relative SHA256SUMS. Full migration and the
original fused PCS/DEEP and direct final-layout witness objectives remain active.
