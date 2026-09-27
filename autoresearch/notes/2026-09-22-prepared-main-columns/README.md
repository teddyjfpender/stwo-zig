# Native preparation owns main columns instead of live row arrays

For all 20 AIRs, canonical preparation now projects main columns into their final
committed order and releases each live-row buffer. Prepared owns column payloads,
column descriptors and fixed logical metadata. Its checked retention accounting
includes all three. Producer validates column count/domain lengths and metadata
against its admitted plan, then borrows main columns for commitment, lookup counters
and interaction generation. Producer-side main projection is removed.

The shared projection helper now cleans newly appended column allocations on error
while preserving prior list entries. Preparation cleanup covers partial main/fixed
transfers. Full handoff parity checks compare main columns and fixed metadata;
metadata mutations continue to reject against the persistent plan.

## Qualification and observed tradeoff

ReleaseSafe test-blake3-native-segment: exit 0, 4/4 steps, 3/3 tests; run 42 s /
1 GiB reported maximum RSS, compile 1 min / 6 GiB. Both pipeline proofs independently
verify, including codec and ownership after worker destruction. No allocator leaks
reported. A dedicated malformed Prepared main-column test has not yet been added;
existing column-view geometry tests cover its shared view validation, not every
new producer rejection branch.

| Measurement | Before | After |
| --- | ---: | ---: |
| Handoff retained tracked bytes | 118,185,496 | 130,557,704 |
| Preparation peak tracked bytes | 600,657,997 | 600,657,997 |
| Worker peak tracked bytes | 1,567,077,617 | 1,667,299,422 |
| Artifact bytes | 116,382 | 116,382 |

The handoff grows 12,372,208 bytes because final columns include domain padding.
Worker peak unexpectedly grows 100,221,805 bytes despite removing projection;
workspace allocation ordering/arena capacity is a hypothesis needing measurement.
Do not claim a memory or timing win. The implementation advances the requested
final-layout ownership model, but the worker regression must be investigated.
Key remains `0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.

Preparation still builds temporary live rows before projection. Direct adapter
emission, compact fixed metadata, worker allocation diagnosis, production reusable
keys/security profiles, multi-level recursion, Metal and reviewed parameter
experiments remain unfinished. This is not completed direct witness generation.
