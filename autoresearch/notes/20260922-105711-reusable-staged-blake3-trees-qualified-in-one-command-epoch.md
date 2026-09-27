---
title: Reusable staged BLAKE3 trees qualified in one command epoch
author: Teddy Pender
created_utc: 2026-09-22T10:57:11Z
---

# Reusable staged BLAKE3 trees in one command epoch

2026-09-22. Connected compact BLAKE3 stages to the existing retained resident
Merkle plan and command epoch. The plan owns sorted column metadata, layer
offsets and two scratch offsets. Encoding sizes state from total column width,
groups equal-log columns into batches of at most 16, alternates scratch buffers,
and writes the final stage directly into the leaf layer. The existing parent
encoder then builds all retained layers in the same command buffer.

The standalone staged operation and full-tree scheduler share one extracted
encoder. Bounds/overlap checks cover both scratch buffers, all source columns
and all retained layers before work is submitted. Root-first/nonmonotonic layer
storage is supported. Explicit BLAKE3 staged admission uses zero seeds and the
canonical domain; global hash-domain admission and production defaults remain
unchanged. No new shader or hash construction was introduced in this step.

ReleaseSafe focused gates: 28/28 tests, 6/6 build steps. Eight complete trees
(widths 17,250,762,2042; 16 leaf rows; four parent levels; two changed inputs per
reused plan) match CPU for all 248 leaf/parent digests. Whole-arena comparisons
exclude only the two declared mutable scratch regions and preserve source,
layer and inter-region guards. The prior compact-stage gate independently
checks poisoned unused scratch slots and every intermediate prefix.

Measured command receipts assert, for every tree:
- command_buffers=1
- wait_count=1
- intermediate_wait_count=0
- dispatches=number of leaf stages+4 parent layers

Leaf stage counts: 4,16,48,128. Thus the widest tree has 132 device dispatches in
one submission, not 132 submissions. GPU times retained in qualification.log
are small-grid diagnostics (widest 5.31ms/3.46ms), not CSP or production recursion
measurements or an end-to-end speedup claim.

Command:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-staged-tree test-blake3-staged-leaves -Doptimize=ReleaseSafe --summary all
```

Remaining: completed-arena tree adoption currently admits wide/Poseidon staging
only and must be extended with matching BLAKE3 provenance. Frontend/backend
commitment selection still needs the new width-sized scratch layout, followed
by wide arenas, transcript/cascade/decommit and full Metal proof qualification.
Prover-owned Poseidon statement identities and production recursion requirements
remain. The retained plan is reusable but the production prover is not yet
switched to this path. Tests use source JIT; no AOT execution claim.

Algorithm mapping follows 20260922-metal-blake3-staged-state-match.md: existing
bounded sequential absorption, with two-buffer scheduling and no cryptographic
change. Logs, source snapshots and relative SHA256SUMS are retained.
