# Routed frame uses caller-owned hash destinations

Live routed-frame preparation now reserves exact G/XOR/boundary slices in its
returned arena and calls hash.prepareInto with separately owned backing scratch.
The frame shape is also backing-owned and released on every path. Returned frame
rows no longer retain the live hash plan and wire workspace in their arena.
Trusted fixed generation remains independent; route schedules, payload/digest
multiplicities and private-boundary removal remain unchanged.

Inspection found that the private hash wrapper already transfers its G/XOR arrays;
routed frames were the first useful integration boundary. This stage does not
remove the later frame-to-transcript/group append or generate committed columns.
Shape is still built for caller sizing and again for kernel admission; no plan
reuse or speed claim is made.

## Qualification

ReleaseSafe test-blake3-frame-witness plus test-blake3-native-segment completed
8/8 steps, 4/4 tests. Frame ownership/partial-allocation check: 646 ms / 2 MiB.
Full native gate: 3 tests, 43 s / 2 GiB. Independent proofs, codec, source mutation,
row parity, allocation-denial and handoff lifetime checks pass.

Preparation peak tracked bytes: 612,480,383 -> 600,657,997, down 11,822,386 (1.93%).
Handoff retention stays 118,185,496 bytes and worker peak stays 1,567,077,617 bytes.
Artifact size remains 116,382 bytes and key remains
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.
No controlled timing measurement or production-profile/Metal qualification follows.

Next: directly target outer adapter/final-column reservations while preserving
source schedules and complete interaction equivalence. The broader four-part goal,
production keys, multi-level recursion and Metal remain unfinished.
