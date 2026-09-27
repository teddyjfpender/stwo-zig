# Canonical two-level native recursion — 2026-09-24

## Decision

The preceding goal turn was progress: quotient fusion was implemented and qualified,
but its single-parent timings were flat and its proof grew. This checkpoint extends
qualification through an actual second dependent parent, measures both variants,
and **removes quotient fusion from the production path**. The sound component and
its tests remain archived in the preceding experiment's source snapshots. There is
no runtime fusion toggle or unused quotient component in the retained production roster.

The shared canonical roster projection is retained, eliminating the old duplicated
component list. The new `test-blake3-native-parent-chain-aot` target is also retained.
It clears the unrelated pipeline environment switch and explicitly exercises two
dependent native parent proofs on the authenticated Metal backend.

## What is qualified

A real CPU child proof with q70/PoW26 is verified and captured. A first Metal parent
proves that capture with q70/PoW26. Its independently verified capture is used to
prepare and prove a second Metal parent, also q70/PoW26. Both levels exercise original
and fresh-codec verification, admitted-key rekey, fixed-plan reuse, post-worker output
lifetime, transcript replay and tracked allocation limits.

The optional preparation probe uses a 24 GiB allocation budget, checks the expected
child key and canonical parameters, and reports every next-level cohort's live/padded
rows. Preparation and proving each have their own limits; these are not process RSS
limits. The full-chain branch runs exactly one additional level, so environment flags
cannot cause unbounded recursive qualification.

This is a linear chain over the tiny typed execution fixture. It is **not a canonical
binary aggregation tree**, heterogeneous production workload, Ethereum block benchmark
or a proof of a stable recursive fixed point. Both parent verifiers are native typed
AIR constructions; this test does not execute the verifier as a RISC-V guest.

## Exact next-level cost

| Second-parent quantity | No quotient fusion | Quotient fusion |
|---|---:|---:|
| G rows | 3,407,712 | 3,420,032 |
| G padded height | 4,194,304 | 4,194,304 |
| Inverse rows | 2,534 | 2,464 |
| Inverse padded height | 4,096 | 4,096 |
| Total arithmetic rows | 231,177 | 232,372 |
| Main-column bytes | 2,071,346,176 | 2,071,488,000 |
| Retained preparation bytes | 2,509,616,520 | 2,511,482,140 |
| Preparation tracked peak | 4,407,197,502 | 4,422,412,019 |
| Second-parent proof bytes | 864,438 | 875,010 |

The first-level inverse-domain halving does not repeat at level two. The added
component increases the next-level verifier's total arithmetic and hash work despite
70 local quotient fusions there. The second proof grows 10,572 bytes. These are exact
geometry/proof-size observations, independent of wall-clock noise.

## Matched timing

M5 Max, ReleaseFast, SMP allocator, eight proving workers. Frozen control/candidate/
candidate/control process order, compilation excluded, two processes per arm. Four
canonical child proofs and eight timed parent proofs independently verify, with fresh
codec verification too. Both parent artifact hashes in every process match their
variant's qualification hashes. All samples are retained.

| Median | No quotient fusion | Quotient fusion |
|---|---:|---:|
| Complete child + two-parent fixture | 23.381630 s | 23.378441 s |
| Second-parent preparation | 3.014061 s | 2.983871 s |
| Second-parent proving and checks | 5.809309 s | 5.871820 s |
| Maximum process physical footprint | 30,692,212,216 B | 30,695,439,792 B |

The complete fixture is flat (0.014% median difference). Second-parent proving/checks
are about 1.1% slower with fusion in this small sample. The fixture includes the CPU
child, both preparations, key/worker construction, negative checks, both parent proofs,
verification and replay. The second-parent window includes key derivation, worker setup,
proof and qualification checks; it is not bare proving time. None is a CSP prove-only
measurement. No order-of-magnitude, subsecond or memory improvement is established.

The experiment is rejected for production because it adds next-level work and proof
size without a demonstrated total-time benefit. Future fusion needs to account for
component/column costs through dependent levels, potentially sharing an existing cohort,
rather than accepting a first-level row reduction as a sufficient result.

## Retained source and evidence

The final production path uses the original dot4/FMA/native-query fusion and
20-component roster, projected from one canonical component list. Its new chain
qualification is rerun after removing the experimental component and dead test wiring.
The retained focused PCS guard passes 12 checks. Final chain qualification and exact
artifact hashes are recorded in `retained-qualified.log`.

The control was constructed by removing quotient emission and its roster entry while
keeping the same new chain harness. `build-control.py` records that temporary source
construction and restores candidate source bytes in a `finally` block. Its shape guards
prevent it from applying to the now-restored production source: it is a historical driver,
not the recommended reproduction command. The experiment's candidate component/test
sources remain under `../2026-09-24-quotient-accumulation/source`; `candidate-source`
here records the chain harness and other candidate changes. `control-source` records
the two control overrides. `retained-source` records final changed files.

The first preparation probe attempted a name field absent from older AIRs; it was
changed to the type name before successful qualification. `probe-initial.log` retains
that compile failure. Both successfully qualified variants and the matched measurements
are separate logs. Frozen executables, hashes, raw results and source snapshots are
checksummed. These snapshots are not a complete clean-checkout reproduction of the
dirty workspace; the driver references the previously archived authenticated AOT bundle.

```sh
STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-chain-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
python3 autoresearch/notes/2026-09-24-canonical-parent-chain/measure.py
```

The full objective remains open: canonical aggregation trees and heterogeneous reuse,
reliable bounded scheduling benefit, materially effective fusion/direct emission,
full CPU/Metal CSP baseline recovery, and the separately reviewed parameter experiment.
