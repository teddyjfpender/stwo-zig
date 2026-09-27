---
title: BLAKE3 full-digest byte-memory commitment primitive
author: Teddy Pender
created_utc: 2026-09-22T13:31:27Z
---

# Full-digest BLAKE3 byte-memory tree

Production continuation roots currently reduce each Poseidon pair to one M31
value. Added a distinct full-256-bit BLAKE3 byte-tree commitment primitive; no
scalar root is reinterpreted or padded into a digest. The fixed 30-level byte
address topology is extracted unchanged and reused by legacy continuation and
new BLAKE3 traversal. Sorted byte input is validated before allocation-free
traversal; default roots are cached in a reusable TreeHasher.

The frame uses a zero-padded 32-byte domain, LE u32 version=1, node tag (leaf=1,
internal=2), and kind (memory=1, program=2, io=3), followed by one byte or two
full digests. Explicit zero bytes equal implicit zero memory. No tree AIR or
production statement claim changes are made by this primitive.

The focused ReleaseSafe gate passed (24 seconds, 1 GB reported peak RSS).
Checks cover explicit zero at both address extremes, an independently folded
single-leaf path, address sensitivity, program/memory separation and invalid byte,
address and duplicate input rejection. Broader test inventories include the new
test. Legacy traversal extraction changes no hashing or topology semantics.

Remaining: pin and constrain the new memory frame in typed AIR, migrate full-width
public roots and continuation claims, integrate native retained snapshots and
production artifact/key admission, then qualify multi-level recursion. Ordinary
production memory roots still use the legacy protocol. No speedup is claimed.

Qualification correction: the original focused root omitted the memory test import.
Its earlier green run did not qualify the memory tests. The corrected root now
imports them explicitly; the 2026-09-22 memory-path qualification reran byte-tree,
node, leaf and path checks successfully. See 2026-09-22-blake3-memory-path/README.md.
