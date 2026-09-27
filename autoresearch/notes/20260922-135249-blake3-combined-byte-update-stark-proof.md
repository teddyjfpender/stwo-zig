---
title: BLAKE3 combined byte-update STARK proof
author: Teddy Pender
created_utc: 2026-09-22T13:52:49Z
---

# Combined BLAKE3 byte-update STARK proof

The dedicated test-riscv-blake3-memory-update gate now proves both 30-level root
paths with one shared private sibling producer, byte input bridges and lookup
tables. A three-entry snapshot changes byte 42 to 255 at address 12. The before
and after roots are independently computed from snapshots. Both byte sources
are public fixtures in this gate.

ReleaseSafe qualification passed in 29 seconds build/run (1 GB reported peak
RSS). The shared gate checks combined lookup claims, independently generated
trusted fixed columns, BLAKE3 PCS/transcript proof verification and rejection of
preprocessing with a changed after-root. Diagnostic parameters are 8 queries and
0 PoW bits; this is not a canonical-security performance benchmark.

This qualifies the combined update proof component. Production memory relation
admission, address/root/clock binding, continuation state claims and artifact/key
integration remain unfinished. The proof fixture does not establish execution
of a RISC-V store or authenticate runner-owned snapshots. Production memory
roots still use the legacy Poseidon protocol.
