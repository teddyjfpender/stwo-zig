# Compact trusted transcript storage — 2026-09-24

The previous turn produced evidence: repeated graph construction was removed,
qualified, measured and rejected because it did not materially improve preparation
or end-to-end time. Its source was restored. This checkpoint addresses actual
materialized storage in objective 3, with no hash/AIR/parameter change.

Native transcript planning now independently derives only G/XOR fixed tails for
trusted preprocessing. Full main-word placeholders are never allocated on this
path. Bounded retry and query emitters propagate validated compact destinations
through the existing canonical frame producer; consumer multiplicities are updated
in the compact tails. Transcript absorption and PoW share the same storage mode.
The existing full-row trusted producer remains an independent reference path.

Ownership is explicit: direct-column live metadata remains borrowed; compact trusted
metadata is owned by its Prepared value. Success transfers both compact allocations,
while all partial-allocation failures free them. Plan.intoFixed transfers ownership
without copying. Count queries account for both representations. Native replay uses
the compact plan; plan identity hashes exactly the same fixed fields and receipts.

Parent row assembly independently checks generated fields against trusted compact
fields for both full-row oracle and direct-column live witnesses. The full-row
append API remains typed; appendCompact supplies an explicitly typed fixed-tail
slice for G/XOR. Mixed full-row/compact plan storage is rejected. Main-column output,
interaction schedules, canonical parameters, proof keys and framing are unchanged.
No metadata from the live witness is accepted as its own preprocessing authority.

## Qualification

Initial frame/transcript/retry/query ReleaseSafe gates passed 5/5. Expanded plan
checks compare compact and full preprocessing identity across absorption, PoW,
queries and bounded draws; mutate every field of a G and XOR fixed tail; check
wrong capacity/roles and malformed destinations; and inject every allocation failure
through ownership transfer and column emission. Both compact and full-row live
admission paths reject mutated fixed fields without appending partial output.
The final transcript/native ReleaseSafe gate passed **5/5** (two transcript checks
and three native segment proof checks). It independently verifies two pipeline
parents after worker destruction and checks full-row oracle/direct-column parity.
Canonical Metal pipeline qualification passed **7/7**. The two independently
verified q70/PoW26 artifacts are byte-for-byte identical to the control: 839,853 bytes,
SHA256 `33b85e0a6519962ca53511b4dc06cecc0f2f5d0e06f299f95a8868efd10744dd`.
Each measured transcript contains 36,568 G and 10,448 XOR rows. Logical trusted hash
storage falls **16,257,088 → 2,591,104 bytes**, removing **13,665,984 bytes (84.1%)**
per plan. This is stored payload, not process peak or cumulative allocation traffic.
Canonical two-level tree qualification passed **7/7**, with exact Metal
interaction/composition coverage for all eight hash components. Four actual leaves
and two aggregate levels bind six guest cycles. All three aggregates independently
verify at q70/PoW26; artifact sizes remain **845,993 / 849,496 / 889,364 bytes**.
Each root-child transcript's logical trusted hash storage falls
**17,725,952 → 2,825,216 bytes**, removing **14,900,736 bytes**. The full tree retains
4,199,425,192 bytes of final root rows and peaks at 26,459,992,736 routed bytes,
unchanged from the prior qualified tree. This run qualifies semantics and ownership,
not a matched tree speed improvement. The first native build
caught an anonymous-tuple coercion issue in a generic append argument; the corrected
API preserves the original typed append and adds typed appendCompact.

## Reproduce

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-frame-witness test-blake3-transcript-plan test-blake3-bounded-draw test-blake3-query-batch -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-transcript-plan test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

The worktree is dirty; control and final source snapshots plus a relative patch
isolate this checkpoint. Physical-memory and speed claims require measured evidence;
logical removed bytes alone do not imply a smaller process peak. Broader goals remain
open: canonical multi-job tree throughput, effective PCS/DEEP fusion, remaining final
column staging, and the separately reviewed parameter experiment.

## Matched pipeline observations

The driver uses frozen control/candidate/candidate/control binaries, the same ABI24
bundle, eight proof workers plus one preparation worker, SMP allocation and identical
jobs. It checks exact artifact identities, canonical parameters, independent
verification, plan reuse, overlap and worker budgets in each process. All eight
timed artifacts independently verify.

| Arm | Complete fixture (s) | Two-job window (s) |
| --- | ---: | ---: |
| control | 20.809 | 9.628 |
| candidate | 21.810 | 9.682 |
| candidate | 21.188 | 9.720 |
| control | 21.193 | 9.709 |

Median preparation sum **3.53517 → 3.53644 s** is effectively flat. Complete fixture
median **21.00108 → 21.49896 s (2.37% higher)**; two-job window
**9.66809 → 9.70086 s (0.34% higher)**. Peak physical memory
**28,178,365,056 → 28,364,030,488 bytes (+185.7 MB)**. With two samples per arm,
these do not establish an end-to-end speed or physical-memory improvement, and the
logical storage saving must not be presented as either. No samples were discarded.

This implements the requested removal of full-row materialization in trusted
transcript planning. It is a representation/ownership improvement with a measured
84.1% lower retained payload in that component; it is not a demonstrated prover
speed optimization. The larger main-column joins and proof work remain.

```sh
STWO_RISCV_PARENT_PREPARATION_PROFILE=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-pipeline-aot -Dmetal-core-aot-bundle="$PWD/autoresearch/notes/2026-09-24-blake3-rotate7-limbs/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-compact-trusted-transcript/measure.py
```

```sh
STWO_RISCV_PARENT_PREPARATION_PROFILE=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-tree-aot -Dmetal-core-aot-bundle="$PWD/autoresearch/notes/2026-09-24-blake3-rotate7-limbs/core" -Doptimize=ReleaseFast --summary all
```

The compact representation is retained as the native transcript planning default;
full-row standalone preprocessing remains a differential reference. The rejected
graph-reuse experiment is not reintroduced. ABI24 shaders are unchanged. No CSP
benchmark timings are updated by these recursion-only fixture observations.
