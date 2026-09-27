# Transcript witness rows release growth storage

Eight transcript row lists now use the backing allocator and transfer their exact
slices into Prepared. The owning allocator frees them individually. Payload read,
root read and output metadata remain in the retained metadata arena. Both live and
trusted replay use the same build implementation and preserve all transcript state,
retry-capacity, caller-binding and row-authentication semantics.

Each unfinished list has cleanup, and every transferred row slice has error cleanup
until the final Prepared is returned. This removes row-growth retention without a
new final copy. Per-operation witness construction and copying still exist.

## Qualification and measurements

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-transcript-plan test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Exit 0, 8/8 steps, 4/4 tests. Transcript-plan test: 511 ms / 11 MiB. Native gate:
3 tests, 42 s / 2 GiB. Existing budget-denial, row parity, owned handoff, independent
verification and codec checks pass with no allocator leaks reported.

| Measurement | Before | After |
| --- | ---: | ---: |
| Preparation peak tracked bytes | 799,302,496 | 612,480,383 |
| Handoff retained tracked bytes | 118,185,496 | 118,185,496 |
| Worker peak tracked bytes | 1,567,077,617 | 1,567,077,617 |
| Artifact bytes | 116,382 | 116,382 |

Preparation peak falls 186,822,113 bytes (23.37%). Relative to the earlier
1,242,103,479-byte peak, cumulative reduction is 50.69%. These are tracked
allocation measurements, not process RSS or a controlled timing improvement.
Key remains `0fa2bf60222d4e62cf05dbed0c8892a8c8ba39a62b960d22abc2e65975f9fc46`.

The full goal is incomplete. Direct generation from per-operation/group witnesses
into final buffers/columns, production security profiles and reusable keys,
distinct-child and parent-of-parent recursion, Metal and separately reviewed
parameter experiments remain unfinished. No subsecond or tenfold claim is made.
