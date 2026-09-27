---
title: Native table counts and interactions share column ingress
author: Teddy Pender
created_utc: 2026-09-22T06:48:50Z
---

# Native lookup counters consume committed-column views

ColumnRows now shares explicit shape validation between interaction generation and
lookup-table registration. row_columns.columnView builds the native main-column /
authenticated-metadata view; registerColumns reads one stack row at a time and
reuses canonical registerRepeated. The producer uses this path for bitwise/range
table counts as well as interactions. Typed padding registration is unchanged.

No main columns are reallocated or copied for the view. This removes live-row reads
from producer counters/interactions, but prepared rows remain for admission and main
projection. It is an integration prerequisite, not a memory or speed improvement.

## Qualification

ReleaseSafe test-blake3-native-segment plus test-recursive-fused-pcs-opening pass
14/14 tests (native 42 s / 2 GiB; framework/PCS 731 ms / 137 MiB). The added
complete counter-array comparison on actual G/XOR/boundary hash output then passes
with test-blake3-hash, 4/4 tests, 829 ms / 27 MiB. The latter checks nonzero column
source offsets and compares both lookup tables against row-based registration.
No full suite was repeated for the test-only addition.

Preparation peak remains 600,657,997 tracked bytes; handoff retention 118,185,496;
worker peak 1,567,077,617. Key and 116,382-byte artifact remain unchanged. Full
independent verification, codec, padding, failure and ownership checks pass.

Next generate final main columns during preparation and remove their logical-row
storage while retaining authenticated fixed metadata. Production reusable keys,
security profiles, distinct-child and parent-of-parent recursion, Metal and reviewed
parameter experiments remain unfinished. No subsecond/tenfold result is claimed.
