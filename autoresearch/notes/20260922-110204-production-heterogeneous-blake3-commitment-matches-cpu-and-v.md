---
title: Production heterogeneous BLAKE3 commitment matches CPU and verifies openings
author: Teddy Pender
created_utc: 2026-09-22T11:02:04Z
---

# BLAKE3 production heterogeneous commitment path

2026-09-22. The backed mixed-log commitment implementation now admits the exact
canonical core BLAKE3 MerkleHasher, allocates two width-sized state slabs and
selects the reusable staged BLAKE3 resident-tree plan. IFFT, LDE, staged leaves,
parents and completed-arena ownership use the existing pipeline and command
epoch. Other hasher paths retain their existing admission; unfinished device
transcript/cascade interfaces are not globally enabled.

This extends runtime/heterogeneous_commit.zig, reached through the actual
MetalCommitBackend.prepareAndCommitOwned entry point. Admission otherwise stays
limited to a materialized page-aligned single owned arena, mixed column logs,
retained coefficients and blowup one. The canonical BLAKE3 type is checked
exactly rather than accepting a caller-supplied family tag.

The canonical CPU-comparison test is now shared by BLAKE2s and BLAKE3, removing
the need for a parallel test implementation. Final ReleaseSafe gate passes
3/3 tests and 3/3 steps: two actual backend tests plus their import root.
For each suite the test compares all transformed coefficients and extended
column values, root, six query openings, hash witnesses and auxiliary nodes;
it verifies the openings with the canonical independent Merkle verifier.
It also checks one epoch/submission/wait, device dispatch, expected staging
avoidance, resized-arena reservation and return to prior resource counts on
cleanup. This is the ordinary commitment/opening interface, not a full STARK.

The synthetic fixture has five columns at logs 8,6,8,7,6. The existing test-only
heterogeneous admission override bypasses the production cost threshold for this
small shape; it does not replace hashing or the actual backend execution. The
prior staged-state/tree gates cover wider multi-chunk leaves independently.
No CSP timing, default-suite promotion, unforced large-shape admission or full
Metal proof is claimed by this gate. Device execution used source JIT.

Command:
```sh
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-heterogeneous-commit -Doptimize=ReleaseSafe --summary all
```

Remaining: generic/uniform/wide commitment paths, resident BLAKE3 transcript and
FRI cascade, full Metal proof qualification, prover-owned Poseidon statement
identities and production recursion requirements. Production suite defaults
remain unchanged. Narrow-path BLAKE3 admission deliberately does not imply
complete Metal backend admission.
