# Native final buffers transfer directly into prepared ownership

Native preparation now uses the supplied allocator for final Builder arrays and
a local arena only for scratch. Old ArrayList allocations can be released during
growth; toOwnedSlice transfers final rows/fixed rows into Prepared. Prepared stores
the allocator and frees each typed array individually. No final arena copy is added.
The scratch arena is destroyed before return, so no transient lowering/fusion data
is retained by the handoff. Builder cleanup handles unfinished lists; initialized
empty output slots and error cleanup cover partially transferred output arrays.

Non-budget retainedBytes sums exact owned row/fixed lengths with checked arithmetic;
budgeted handoff accounting continues using tracked live allocation. Proof input
borrows remain synchronous and artifacts remain independently owned.

## Qualification and memory

ReleaseSafe test-blake3-native-segment passed 4/4 steps and 3/3 tests, 41 s / 2 GiB;
compile 1 min / 6 GiB. This includes budget-denial cleanup, canonical row parity,
threaded owned handoff, pipeline, codec and independent proof verification after
worker destruction. No allocator leaks reported.

| Measurement | Previous pre-sized arena | Individually owned buffers |
| --- | ---: | ---: |
| Handoff retained tracked bytes | 254,205,405 | 118,185,496 |
| Preparation peak tracked bytes | 1,044,442,891 | 1,044,442,891 |
| Worker peak tracked bytes | 1,567,077,617 | 1,567,077,617 |
| Artifact bytes | 116,382 | 116,382 |

Retention falls 136,019,909 bytes (53.51%), and now tracks the 118,184,432-byte
logical row payload plus bookkeeping. Relative to the earlier 461,491,951-byte
handoff, cumulative reduction is 74.39%. Peak preparation is unchanged: transient
adapters and final buffers still coexist. These figures are not process RSS or a
controlled latency result. Key remains
`0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.

This completes scratch release and final-buffer ownership transfer, not all direct
witness generation. Adapter staging, separate main/fixed row storage, final column
projection, production reusable keys, distinct-child/parent-of-parent recursion,
Metal and reviewed parameter experiments remain unfinished.
