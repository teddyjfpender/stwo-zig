# Native BLAKE3 arithmetic fusion census

The native parent currently lowers its five graphs through the basic shared
multiply/inverse/linear compiler. The detached-parent path already has typed
four-term accumulation and multiply-add components with authenticated matching.
Before adding new fused equations, this census applies those same matchers to
real native graph lanes, with canonical graph/output use counts and dot4-first
reservation. It never changes graphs, witness rows, key identities or proofs.

| Lane | Arithmetic rows | Dot4 matches | FMA matches | Removable rows |
| --- | ---: | ---: | ---: | ---: |
| VM composition (1500) | 10,613 | 64 | 3,464 | 3,912 |
| PCS/DEEP (1502) | 12,502 | 574 | 904 | 4,922 |
| FRI (1504) | 3,279 | 45 | 891 | 1,206 |
| Public boundary (1506) | 2,982 | 94 | 584 | 1,242 |
| Aggregate sum (1508) | 112 | 0 | 0 | 0 |
| Total | 29,488 | 777 | 5,843 | 11,282 |

A dot4 replaces eight operation rows with one; an FMA replaces two with one.
Thus the structural opportunity is 18,206 remaining arithmetic rows (38.26%
fewer) and 22,564 fewer internal consume/emit relation events. These are matched
opportunities, **not implemented savings or an end-to-end speedup**. Padded domains,
component widths, hash/XOR tables and other work determine the eventual benefit.

## Focused measurement

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-arithmetic-census -Doptimize=ReleaseSafe --summary all
```

Exit 0: 4/4 steps, 1/1 tests, 10 s / 1 GiB; compile 1 min / 4 GiB. It obtains a
real verified native BLAKE3 capture and prepares the canonical graph adapters,
then stops before parent row assembly/proving. The existing full native entrypoint
continues through the unchanged non-audit branch. No full parent suite or speed
benchmark was repeated for this read-only census. No allocator leaks reported.

## Selected next implementation

Reuse the existing dot4/FMA matching and typed AIR definitions in the native
assembler before designing a novel larger fused PCS component. Required changes:

- Share the canonical fusion lowering rather than copying the detached loop.
  Preserve every public term, graph output and cross-circuit use count; only
  internal single-use products/accumulators may disappear.
- Update the native roster, producer, independent verifier and key identity
  together. Current producer/component setup assumes selector parameters at
  indices 3..5; existing fused AIRs have no such parameters, so this assumption
  cannot be carried over blindly. The verifier component owner also has a fixed
  18-log array that must follow the roster. Keep key/version rejection explicit.
- Requalify codec shape, mutation rejection, input coverage, independent proof
  verification and pipeline/lifetime behavior. The codec header already derives
  its claim area from artifact.CLAIM_COUNT; avoid a separate constant rewrite.

The diagnostic child q1/PoW0 and parent q8/PoW0 have not changed. Production
profile/key integration, distinct-child aggregation, parent-of-parent and Metal
remain unfinished. Original fused PCS/DEEP work beyond these existing patterns,
final-layout witness generation and parameter experiments remain in scope.

Logs and source snapshots are pinned by relative SHA256SUMS.
