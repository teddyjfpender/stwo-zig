---
title: BLAKE3 full-depth memory path and corrected qualification
author: Teddy Pender
created_utc: 2026-09-22T13:41:26Z
---

# Full-depth BLAKE3 memory path witness

Added a private byte source through 30 memory-node hashes with private siblings,
public address/kind/root and distinct circuit namespaces. Every intermediate
digest drops its public sink and emits exact parent fanout. The full root remains
a public digest claim. Arena ownership retains all rows and is finalized only
after output allocations complete.

The corrected focused ReleaseSafe gate passed in 30 seconds (1 GB reported peak
RSS). Native sparse-tree root agreement, all fixed columns against witness-free
construction, 240 sibling word rows, full recursion-wire closure, sibling
substitution and namespace overlap rejection are covered. The full ledger uses
one explicit byte-source fixture; production memory-source admission is pending.

A registration gap was found: prior edits looked for a comptime block, while the
focused root uses a test block. The memory tests and intended frame regressions
were therefore absent from earlier focused runs. This run explicitly imports all
of them. Earlier memory evidence notes have been corrected. One tuple-inference
compile error in the new ledger was fixed before this successful run.

This is path witness/lookup qualification, not a full path STARK proof or production
memory migration. Full-width public/continuation claims, snapshot integration,
production artifact/key admission and recursive tree qualification remain pending.
