---
title: Query frames write directly through transcript destinations
author: Teddy Pender
created_utc: 2026-09-22T07:44:51Z
---

# Query frames write through into transcript hash destinations

A raw query batch uses ceil(query_count/8) equal-length draw frames. Their canonical
hash plan therefore has identical row geometry and local output wires. Allocate
(or borrow) exact total G/XOR storage, reuse one canonical output plan across blocks,
and lend per-block ranges to frame writers. Keep partial-block output multiplicities,
counter carry/read counts and query masks unchanged. Transcript reserves its final
unused G/XOR ranges and uses the borrowed batch API, avoiding both frame-to-batch
and batch-to-transcript copies. Existing owning APIs share the same builder.

This is exact destination allocation and immutable plan reuse. Input/count arithmetic
is checked; builder validates supplied destination shape independently. All temporary
frame results are destroyed through bounded backing after smaller rows are copied.
Failure may leave unpublished destination contents but ownership stays with caller.

Validate owned/borrowed live/fixed parity for empty, partial and multiple blocks,
invalid destination admission, ownership/failure cleanup, then full native parent
verification and recorded memory. No security changes or latency claim.
