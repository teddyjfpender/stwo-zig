---
title: Native path ownership reduces preparation peak below 800 MB
author: Teddy Pender
created_utc: 2026-09-22T06:20:34Z
---

# Native Merkle-path adapter frees row-growth storage

The six live/fixed row cohorts in blake3_stark_paths now allocate through the
backing allocator instead of the retained link/geometry arena. Their typed slices
transfer directly into Prepared, which owns their allocator and frees each array.
Temporary Merkle groups still validate their root and payload-use agreement before
canonical append. No hash equations, namespace, input routing or proof layout changed.

Unfinished lists are cleaned by Builder defers; finish initializes empty output
slots and cleans transferred arrays on failure. If fixed-row finalization fails,
the already transferred live rows are released. Link/geometry storage remains
arena-owned and is released separately. No second final copy was introduced.

## Qualification

Full ReleaseSafe test-blake3-native-segment passed 4/4 steps and 3/3 tests, 42 s /
2 GiB; compile 1 min / 6 GiB. This exercises existing Merkle/source mutation gates,
budget-denial cleanup, canonical row parity, threaded handoff, proof codec and
independent verification after worker destruction. No allocator leaks reported.

| Measurement | Before | After |
| --- | ---: | ---: |
| Preparation peak tracked bytes | 1,044,442,891 | 799,302,496 |
| Handoff retained tracked bytes | 118,185,496 | 118,185,496 |
| Worker peak tracked bytes | 1,567,077,617 | 1,567,077,617 |
| Artifact bytes | 116,382 | 116,382 |

Peak preparation drops 245,140,395 bytes (23.47%). Relative to the earlier
1,242,103,479-byte peak, cumulative preparation reduction is 35.65%. These are
tracked allocator bytes, not process RSS or a controlled timing comparison.
Key remains `0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.
The pipeline overlap observation is 1,356,669,333 ns, not a claimed speedup.

Still unfinished: per-group witness copying, transcript staging, direct committed
column generation, production reusable keys and security profiles, distinct-child
and parent-of-parent recursion, Metal and separately reviewed parameter experiments.
This stage improves allocation lifetime, not evidence of subsecond proving.
