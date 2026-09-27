---
title: Native BLAKE3 query batch construction
author: Teddy Pender
created_utc: 2026-09-21T20:50:39Z
---

# Native query batches from authenticated state

Exact transfer: compile core/queries.zig's raw draw loop. Each eight-word block
uses the same authenticated state and next consecutive u64 counter; a partial
final block consumes one complete draw but exposes only its requested prefix.
Zero queries consume no draws. There is no field rejection or M31 reduction.
Use shared routed frame hashing and the pinned bytewise query-mask AIR. Unused
root words have zero consumer counts; requested words feed one mask each.
Sum state producer counts across blocks, with checked namespaces and counters.

Validate counts 0,1,7,8,9,17 against native drawQueries, exact trusted fixed columns,
invalid output ranges and overflow, allocation cleanup, and a complete private
state producer plus nine-query proof. Preserve raw order and duplicates; sorting,
deduplication and folded path admission are later stages, not silently performed
here. No new AIR or performance claim.
