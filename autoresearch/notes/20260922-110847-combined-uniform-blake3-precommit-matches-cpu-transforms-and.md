---
title: Combined uniform BLAKE3 precommit matches CPU transforms and roots
author: Teddy Pender
created_utc: 2026-09-22T11:08:47Z
---

# Combined uniform BLAKE3 transform and commitment

2026-09-22. Connected canonical direct-domain admission to both combined uniform
precommit routes: owned evaluations (IFFT then LDE/commit) and coefficient-form
polynomials (LDE/commit). Zig and C admission accept BLAKE3 only with its canonical
zero seeds/prefix. Existing transform and BLAKE3 leaf/parent dispatch are reused;
no shader, hash protocol or production default changed.

The uniform receipt test is shared by BLAKE2s and BLAKE3 and strengthened with
independent CPU transform/root comparisons. Each suite uses eight columns at
base log 16, extended log 17, retention always and blowup one, exercising the
production admission shape without a forced small-fixture override.
For evaluation input, all coefficients and extended values match CPU IFFT/LDE.
For polynomial input, source/retained coefficients and all extended values match
CPU LDE. Both resulting roots match canonical CPU Merkle construction. Existing
recorded transform-work and parent-operation receipt assertions remain intact.
The receipt's merkle_compressions metric counts parent operations here; this is
not a new measurement of individual BLAKE3 compression-function invocations.

Final ReleaseSafe focused gate: 3/3 tests, 3/3 steps (two actual suite tests plus
import root), 672ms test runtime, 84MiB MaxRSS. Four combined commitments in total
are checked. This is correctness/work-receipt qualification, not a performance
benchmark or full STARK proof. Device execution uses source JIT, not AOT.

Command:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-uniform-commit -Doptimize=ReleaseSafe --summary all
```

Remaining: resident transcript and FRI cascade integration, full BLAKE3 Metal
proof qualification and canonical CSP timing, then production suite promotion
when its migration gates pass. Prover-owned Poseidon identities and production
recursion requirements remain in scope. The generic full hash-domain admission
is still distinct from qualified commitment-only paths.
