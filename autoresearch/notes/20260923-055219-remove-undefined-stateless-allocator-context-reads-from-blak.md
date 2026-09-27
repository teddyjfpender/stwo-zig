---
title: Remove undefined stateless allocator context reads from BLAKE3 parent ownership admission
author: Teddy Pender
created_utc: 2026-09-23T05:52:19Z
---

# BLAKE3 allocator ownership admission

Status: implemented, focused regression pending; canonical Metal retry remains live.

Zig 0.15.2 defines the SMP and page allocators with undefined context pointers.
The parent row-transfer admission compared allocator context pointers. Reading
these contexts is undefined behavior. The first failed Metal binary omitted
row assembly between preparation-state initialization and cleanup, consistent
with this defect; no successful fixed stateless-allocator parent run is claimed.

Row transfer now takes its allocation authority directly from the transferred
hash-column owner. Both preparation paths use this interface. The scratch-alias
guard compares the known arena vtable before reading its context. A focused
regression covers SMP/page allocators, malformed metadata rejection, and same
versus different arena identities. It still needs compilation and execution.

The checked-allocator Metal retry predates these fixes and cannot validate them.
A live sample at 09:51 local time shows that retry past row preparation and key
admission, inside parent lookup registration. Its sampled physical footprint was
15.3 GiB, with a 25.1 GiB process peak so far. These are partial-run observations,
not a completed gate or the bounded worker's peak accounting.
