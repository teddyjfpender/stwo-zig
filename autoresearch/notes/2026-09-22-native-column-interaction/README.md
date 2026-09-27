# Native producer interactions read committed-order main columns

The native producer records component main-column ranges and supplies the existing
columns to the canonical interaction runtime. Fixed metadata and proof-kind
parameters come from the authenticated persistent plan's fixed rows. ColumnRows
now supports this metadata suffix with an explicit main-coordinate count; full
column callers retain the default behavior. Shape, metadata length and alias
checks precede output mutation. One stack Row is assembled per logical access;
no new projected arrays or second interaction implementation are introduced.

Typed virtual padding and repeated-padding lookup counters remain unchanged.
Original prepared rows still serve preparation admission, main projection and
counter registration; this stage does not yet remove their storage.

## Qualification

ReleaseSafe test-blake3-native-segment plus test-recursive-fused-pcs-opening passed
8/8 steps and 14/14 tests. Full native: 3 tests, 42 s / 2 GiB. Framework/PCS:
11 tests, 611 ms / 137 MiB. Complete proof production, codec, independent verifier,
source/metadata mutation, padding, failure and ownership checks pass.

Key remains `0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`;
artifact remains 116,382 bytes. Preparation peak 600,657,997 bytes, handoff
retention 118,185,496 bytes and worker peak 1,567,077,617 bytes are unchanged.
No measured speedup or memory improvement is claimed for the view integration.

Next: generate main columns during preparation, keep trusted metadata separately,
and retire the corresponding live-row storage/counter dependence. Direct adapter
and column integration, production keys and security profiles, multi-level recursion,
Metal and reviewed parameter experiments remain unfinished.
