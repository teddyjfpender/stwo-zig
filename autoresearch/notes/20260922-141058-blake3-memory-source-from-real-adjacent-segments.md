---
title: BLAKE3 memory source from real adjacent segments
author: Teddy Pender
created_utc: 2026-09-22T14:10:58Z
---

# BLAKE3 memory source from real adjacent segments

Added a typed base-profile runner test executing an eight-instruction program
across two segments. Segment one stores 0x55. Segment two loads it, increments
the value and stores 0x56 before completion. Both retained snapshots feed the
owned BLAKE3 projection. The existing minimal ELF fixture is shared rather than
copied.

The focused ReleaseSafe gate passed in 36 seconds (1 GB reported peak RSS).
It checks exact native snapshot continuity, equality of first-exit/second-entry
BLAKE3 continuation roots, changed final root, actual retained initial/final words
and nonzero final clock. The final ordinary boundary is prepared from the real
snapshot; byte/clock fields match it and all four paths compute its root.

This qualifies the adapter against execution-produced snapshots, not an end-to-end
RISC-V STARK with BLAKE3 memory commitments. Production proofs still use legacy
memory roots. Joined memory-access proofs, continuation format/key admission,
clock provenance and full recursive publication remain unfinished.
