---
title: Individually owned native final row buffers
author: Teddy Pender
created_utc: 2026-09-22T06:13:01Z
---

# Native final buffers with individual ownership

Task: avoid retaining abandoned ArrayList growth allocations and temporary lowering
storage in a returned arena. After exact hash-cohort sizing, 118.2 MB live rows
still occupy 254.2 MB retained arena capacity. Earlier separate arenas alone failed.

Selected transfer: final Builder arrays use the supplied allocator directly, so
reallocation releases old buffers. The scratch arena stays local and is destroyed
at return. toOwnedSlice transfers exact arrays without a final copy when shrinking
is supported; otherwise stdlib handles it. Prepared owns the allocator plus typed
row/fixed slices and frees them individually. Builder cleanup owns unfinished lists;
final-slice cleanup owns transferred slices on errors. No borrowed graph data or
scratch pointers escape. Non-budget retainedBytes sums owned logical byte lengths;
budgeted accounting continues using exact allocator tracking.

This changes ownership, not AIR layout or key identity. Keep pre-sizing and all
canonical admission checks. Full native gate covers budget failures, handoff,
row parity, destruction order, proof codec and independent verification. Measure
retention and peak. No latency claim or parameter changes.
