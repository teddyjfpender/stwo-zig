---
title: Native hash cohorts project without concatenation; full proofs pass
author: Teddy Pender
created_utc: 2026-09-22T07:13:13Z
---

# Direct projection of native hash source cohorts

Parent assembly no longer concatenates live G, XOR or byte-route rows. It retains
the independently checked fixed metadata and projects the exact transcript/path
source pair into final committed columns. These cohorts have no intervening row
consumers or fusion rewrites. The shared projection path supports ordered chunks,
including empty chunks, checks aggregate geometry before allocation and preserves
zero padding. Single-slice projection delegates to the same implementation.

ReleaseSafe hash/native gates pass 8/8 steps, 7/7 tests. Chunk tests compare every
main coordinate to logical rows at the committed permutation, including padding,
empty chunks, invalid logs and oversized input. Both full parent proofs verify;
handoff column/fixed parity and ownership checks pass. Key remains
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`, codec 116,382 bytes.

Measured overall preparation peak remains **600,657,997 bytes** and handoff
retention remains **130,557,704 bytes**. Worker peak remains **982,008,191 bytes**.
The removed concatenation buffers did not determine this fixture's overall peak;
do not claim peak-memory or timing gains from this change. Native tests run 42 s /
1 GiB reported MaxRSS; hash tests 784 ms /32 MiB. No timing A/B verdict.

This advances final-layout assembly but upstream transcript/path adapters still
materialize logical rows. Direct adapter/hash emission and the remaining smaller
cohorts are unfinished, as are production recursion profiles, reusable keys,
distinct-child and parent-of-parent proof qualification, and Metal migration.
