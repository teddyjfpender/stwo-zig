---
title: Budgeted Merkle allocation routing problem match
author: Teddy Pender
created_utc: 2026-09-22T04:54:31Z
---

# Honor explicit allocation budgets for Merkle layers

Task: stop the default size-routed Merkle allocator from bypassing an explicit
SharedHostBudget supplied by a proving worker. Preserve hashes and lifetime rules.

Transfer: allocator dependency injection, using an identifiable budget allocator
vtable and returning that allocator at the existing layerAllocator selection point.
All current Merkle builders already use this function and retain the selected
allocator for teardown. The standard synchronized budget remains the single
allocation/counter author; forwarding methods only identify the wrapper.

Alternatives: thread-local override can miss helper-thread allocations; a global
override conflates simultaneous workers; parallel backing-route contexts add
lifetime complexity without measured need. Select explicit budget allocator
recognition. Unbudgeted callers keep current small-heap/large-mmap routing.
Budgeted calls use their chosen child allocator for layers; specialized mmap
routing within a budget can be researched later if profiling justifies it.

Guarantee: allocations routed through a recognizable budget, including Merkle
layers, share one enforced live-byte cap. This is still not total RSS: allocator
metadata, stacks and other bypass allocations require separate accounting.
No performance claim; this changes budgeted backing policy, not proof semantics.

Validation: exact small/large allocation denial through layerAllocator, real
Merkle tree construction/decommitment and teardown under a budget, existing
full native BLAKE3 worker/codec/verification gate. Scan all layerAllocator callers
for use of the original caller allocator and retained deallocation identity.
