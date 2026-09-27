# Native quotient accumulation — 2026-09-24

**Status: removed from the production path after the [two-level comparison](../2026-09-24-canonical-parent-chain/README.md).** The implementation, tests and binaries below are retained as an experiment.

## Implemented

The preceding goal turn was progress: its residual census located 210 eligible
quotient accumulations in the current canonical DEEP lane. This checkpoint implements
and integrates the positive-add case into native BLAKE3 parent lowering.

The new typed degree-two component constrains both `denominator * reciprocal = 1`
and `denominator * (output - accumulator) = numerator` on enabled rows. The
nonzero-denominator constraint remains explicit, including for zero numerators.
Padding uses the fixed enabler and admits the all-zero row. Its pinned semantic
identity is `4546ad4a7d14d5e7143930e6538d53faf4e8948431f3e443e8d54579e157ce75`.
It has 21 main columns, seven preprocessing columns, nine direct constraints and
four lookup events (eight interaction base columns).

The matcher runs after dot4 and before FMA reservation, selecting only positive
quotient accumulation with single-use reciprocal/product intermediates. Shared,
exported, reserved and signed-subtraction patterns retain their existing lowering.
The materializer verifies the hidden reciprocal, product and output against the
supplied evaluation before emitting the fused row. Other/detached rosters continue
to use the existing dot4/FMA-only entry point.

Native row ownership and proving/verifying roster projection now consume the same
canonical component list. An old hand-maintained twenty-component projection was
removed when integration exposed its mismatch with the new twenty-one-component
roster. Independently derived parent keys bind the new roster and preprocessing;
this is a proof/key-shape change, not byte-compatible output under the previous key.
Canonical q70/PoW26 parameters are unchanged.

## Verified result

For the current tiny canonical typed execution fixture:

| Metric | Previous | Quotient fusion |
|---|---:|---:|
| Inverse live rows | 2,154 | 1,944 |
| Inverse padded height | 4,096 | 2,048 |
| Quotient rows / padded height | — | 210 / 256 |
| FMA matches | 59,551 | 59,341 |
| Total arithmetic rows | 171,628 | 171,418 |
| Dot4 matches | 19,613 | 19,613 |
| Native query-fusion groups | 9,170 | 9,170 |
| Parent proof bytes | 857,591 | 866,453 |
| Parent transcript replay G rows | 40,432 | 40,992 |

Replacing an inverse row plus an already-fused multiply-add row with one quotient
row removes **210 arithmetic rows and 420 relation events**. The new component and
roster increase proof size by 8,862 bytes and transcript replay by 560 G rows.
These costs matter for the next recursive level and are not hidden by the row count.
The new component uses the existing CPU composition route within the Metal parent;
no new authenticated Metal kernel or AOT ABI change was introduced.

## Tests and failure history

- Five ReleaseSafe quotient tests pass: semantic identity/degree, all main-coordinate
  mutations, zero-denominator rejection, exact signed external lookup multiset,
  shared/exported/reserved/signed-pattern protection, hidden-evaluation rejection and
  exhaustive allocation-failure cleanup of the materializer.
- Twelve existing PCS fusion/padding checks pass with the expanded roster.
- Seven canonical Metal parent checks pass: independent verification, fresh codec
  verification, transcript replay, independently admitted key/rekey, fixed-plan reuse,
  outputs surviving worker destruction and bounded worker allocations.

The initial component run intentionally exposed the freshly computed digest while
the placeholder identity rejected admission. After pinning that digest, all component
checks pass. The first complete build exposed the duplicate twenty-component roster;
its replacement by the canonical projection is included here. Initial logs are retained,
not counted as passing checks. The final additional materializer test changes only test
wiring after canonical qualification; the production source is unchanged.

## Matched measurement

M5 Max, ReleaseFast, SMP allocator, eight workers, authenticated Metal AOT bundle.
Frozen control/candidate/candidate/control order, two observations per variant;
compilation excluded. Each process proves the canonical CPU child and Metal parent
and performs independent verification. Both binaries run with census disabled and
identical parent profiling. All observations are retained.

| Metric | Control | Candidate |
|---|---:|---:|
| Complete fixture median | 14.244609 s | 14.159272 s |
| Maximum physical footprint | 27,767,468,512 B | 27,765,928,296 B |

The median difference is only **0.6%**, within the observed variation. **No reliable
end-to-end speedup or meaningful process-memory reduction is established.** This checkpoint demonstrated the admitted fusion and smaller inverse domain;
it was not an autoresearch speed win. Subsequent two-level testing led to removing
the component from production, as noted above. Further acceptance must consider the larger
proof/next-level transcript, especially in a canonical recursive tree. No ordinary
CSP benchmark was rerun or relabeled.

## Reproduce and evidence

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-quotient-accumulation test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-quotient-accumulation/measure.py
```

`binary.json` pins the frozen executables. The control is the preceding residual-census
checkpoint; the driver uses the archived canonical-pipeline AOT bundle. Source snapshots
record changed files, not a complete clean-checkout reproduction of the dirty workspace.
Raw build/test failures, successful qualification, matched logs and results are retained
and checksummed. The candidate proof size is explicitly asserted by the measurement
script; the old artifact SHA is not treated as applicable to the new roster.

Full canonical tree qualification, heterogeneous persistent reuse, scheduling policy,
further fusion/direct emission, full CPU/Metal CSP recovery, and the separately reviewed
parameter experiment remain open. Subsecond recursion and 10x total speedup remain
unproven. Next-level cost must be measured before calling this fusion a performance gain.
