---
title: Persistent native parent worker resource ownership problem match
author: Teddy Pender
created_utc: 2026-09-22T04:49:02Z
---

# Persistent BLAKE3 proving worker

Task: bind one immutable plan, reusable workspace, explicit proof pool and host
allocation budget into one exclusive worker; permit returned proofs/captures to
outlive worker destruction safely.

Transfer: reuse WorkPool/ScopedPoolBinding (including a one-worker binding),
SharedHostBudget and the existing Plan.proveWithWorkspace. Extend budget ownership
with atomic reference-counted leases, following the already recorded shared fixed
commitment design. No new proof implementation, allocator algorithm or scheduler.

Lifetime mapping: worker owns the initial budget lease; returned artifact retains
one; successful verification transfers that lease to the resulting capture.
Artifact rejection frees proof allocations before releasing its lease. Last budget
release checks zero live allocations. All allocator-backed owners remain move-only.

Limits: routed allocations for plan/workspace/proof/pool metadata share one cap.
Large Merkle layers can use the existing mmap allocator independently, and thread
stacks, worker/control metadata, input preparations and allocator overhead are
separate reservations. This is not total RSS admission. Caller serializes worker
use; busy workers reject overlap rather than sharing mutable scratch/pool state.

Tests: budget lease survival across owner release, invalid/tiny worker limits,
two real proofs on one worker with explicit CPU budget, artifact and verifier
capture survival after worker destruction, independent codec/mutation verification.
Total multi-job CPU/RSS admission and actual stage overlap remain next.
