---
title: Share canonical BLAKE3 paths with native captures
author: Teddy Pender
created_utc: 2026-09-22T02:29:45Z
---

# Native BLAKE3 authenticated paths

Task: prepare all native trace/FRI openings and exact query-bit consumption.
Transfer existing qualified full-STARK path builder to a canonical module used
by fixtures and native captures. Remove test-only allocators/assertions and
fixture imports; preserve the same Merkle plans, root ports, readonly alias
constraints and scalar bindings. No new hashing algorithm or AIR.
Complexity: existing total path hash work and graph input joins; bit fanout is
O(queries*31). Query path accounting must roll back on failure. Final arena
ownership must transfer after row-list finalization allocations.
Validation: real verified BLAKE3 capture, all roots recomputed and checked,
path selection/projection counts applied to native query scalar rows; wrong
sibling rejected with query counts unchanged. Same fixture parent gate remains
required because its path implementation becomes shared. Full native parent
roster/public-boundary proof closure remains outstanding.
