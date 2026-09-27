---
title: Metal BLAKE3 parents reuse resident reduction with full digest parity
author: Teddy Pender
created_utc: 2026-09-22T10:20:42Z
---

# Metal BLAKE3 resident parent reduction

Task: reduce full 256-bit child digests with the canonical BLAKE3 node frame,
retaining every intermediate layer and the existing arena-offset contract.
The node frame is 28 prefix bytes plus 64 child bytes: two compression blocks
inside one chunk, flags CHUNK_START then CHUNK_END|ROOT. Derive prefix words from
the pinned protocol ID/domain; compare every digest with the canonical core owner.

Reuse existing ordered resident parent-chain scheduling, sparse offsets and
threadgroup reduction barriers. Add distinct BLAKE3 parent pipelines and a typed
parent-family entry point; do not admit BLAKE3 leaf/FRI hashing before it exists.
Share the seven-round MSL compression owner with PoW instead of duplicating it.
O(nodes) hash work and the existing bounded threadgroup scratch; no host hashing
fallback and no new all-layer host materialization in production execution.

Tests: all-layer parity at several depths including multi-group reduction,
full-bit child patterns, nonzero arena offsets, untouched guards and repeated
plan reuse; shader ABI/initialization authority and existing Metal PoW regression.
No performance multiplier predicted without measurement.
