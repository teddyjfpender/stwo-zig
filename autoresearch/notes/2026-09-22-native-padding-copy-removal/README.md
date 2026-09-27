# Native padded logical-row copies removed

The producer now borrows owned prepared rows during the synchronous proof call.
Final main columns are zero-initialized and projected directly from the live prefix.
A typed padding row retains segment selector parameters. The canonical interaction
runtime repeats its authenticated lookup pairs for absent rows, while table counter
registration scales the same signed numerators by the omitted-row count.

This preserves BLAKE3 G's 56 live padding events. Other native components have inert
padding. Existing register delegates to the same repeated-row implementation at
count one. Count zero is inert. No second arithmetic or lookup compiler was added.
Prepared input and independent proof-output lifetimes remain unchanged.

## Qualification

Focused ReleaseSafe test-recursive-fused-pcs-opening passed 11/11 tests (771 ms).
Across all 20 AIRs, full table-counter arrays match explicit padded rows for every
prefix length zero through four. Interaction columns/claims match for prefixes
zero through three. Existing mutation, closure, allocation, failure and alias gates
remain included. Full test-blake3-native-segment then passed 3/3 tests (42 s / 2 GiB).
Both pipeline proofs independently verify, including codec transport and ownership
after worker destruction. No production security-profile or Metal claim is made.

| Measurement | Before | After |
| --- | ---: | ---: |
| Peak tracked worker bytes | 1,626,590,262 | 1,567,077,617 |
| Preparation peak tracked bytes | 1,242,103,479 | 1,242,103,479 |
| Prepared retained bytes | 461,491,951 | 461,491,951 |
| Artifact bytes | 116,382 | 116,382 |

Tracked worker peak falls 59,512,645 bytes (3.66%). These are allocator snapshots,
not total process RSS. No controlled timing-speedup measurement was performed.
The diagnostic key remains
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.
Stage overlap was 1,350,996,709 ns, not an end-to-end latency reduction.

This removes one full padded-row staging layer. Canonical adapter materialization,
owned prepared live/fixed rows, and output column allocation still exist. Further
direct final-layout preparation, production keys, multi-level recursion, Metal and
separately reviewed parameter experiments remain unfinished.
