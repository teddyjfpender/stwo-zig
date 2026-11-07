# p-truth-split: plan all 15 basket blocks under the D2 coalesced-truth profile

Branch `codex/rv64-m8-p-truth-split` (from `codex/rv64-m7-integrate @ 95e3d7e15`). Labels: [M] measured, [D] derived, [E] estimate.

## Change

Flag `STWO_RV64_M8_TRUTH_SPLIT=1`, **default off**. File: `ethereum/plan.zig` only (`coalesceTruthFamilies`,
new `nonKeccakLogs` / `admittedSingle` / `appendSplitFamily` / `topRungLog`; `oneTruthPerFamily` refactored to call
`nonKeccakLogs`, same output).

Under `--coalesce-truth-families` (the D2 profile), for each non-Keccak family in family order:

1. if the family's single coalesced truth is admitted today (its source log fits the roster `MAX_LOG`, it passes
   `service_scope.truthDeclaration` = `truth_v3_catalog.descriptorForDeclaration`, and when the producer pads to
   canonical rungs (strict roster or `STWO_RV64_CANON_RUNGS=1`) its log is at most the family's top rung), emit
   exactly that declaration: the one `oneTruthPerFamily` emits;
2. otherwise emit consecutive spans `first_id = 1, 1 + c, 1 + 2c, ...` of `c = 2^cap - 1` calls (one padding row
   each), `cap = min(roster MAX_LOG, top rung if rung-bounded)`, then the remainder at its own smallest log. Each
   span is validated by the same `truthDeclaration` before it is emitted.

Keccak is untouched (it was already sharded). With the flag on, every plan the profile admits today is unchanged
(unit-tested on the dev counts, the admitted 24697070 totals and synthetic boundary cases, with and without the rung
bound), so proof bytes are unchanged wherever the profile already proves (gates below).

| refusal today | where | blocks | split |
|---|---|---|---|
| `OneTruthPerFamilySourceCapacity` | sha256 > 8191 calls (log13 cap) | 24626900, 24697073, 26235168, 25229955, 25229951 | sha256 spans of 8191 |
| `V3TruthShapeExceeded` | secp row add/double > 65535 calls (`truth_v3_catalog.zig:139`, row MAX_LOG 16) | 24628590, 24628595, 24628611, 26235159 | add/double spans of 65535 (+ sha256 spans) |

Family totals (from the M3 bundles, `runs/integrate/<block>-2gpu-*/.../bundle.json`) are pinned in the unit test
`truth split plans the M3 basket family totals the coalesced profile refuses`: flag off refuses all 9 and admits
24697070; flag on plans all 10 with receiver-valid spans, and 24697070's plan is byte-equal to flag off.

## Soundness

The split adds no new AIR, transcript word or receiver rule; it only chooses a different, already-admitted roster.

- **Span authority is the receiver's, not the planner's.** `services/protocol.zig` (admit, lines ~227-276) requires
  truths in non-decreasing family order, each non-empty with `first_id == next[family]`, and at the end
  `next[family] == total[family] + 1` for every family, where `total` is the CPU-side call count bound by the CPU
  proofs' claims. A split roster that skipped, repeated or reordered a call is rejected (`InvalidCombinedTruthSpan`;
  covered by the gap/swap cases in `services/execution_test.zig`).
- **Each span is an ordinary admitted geometry.** The truth AIRs bind call IDs as `first_id + ROW`
  (`rv64-sha256-service.md` §call ID; row truths `rv64-secp-row-truth.md`), with `first_id`/`calls` public and mixed
  into the truth transcript (`mixU32s([.., family, first_id, calls, ..])`, `rv64-v3-services-recursion.md` §60),
  and the leaf statement equals the receiver's roster span (`checkStatement`). Geometry, padding-row and lookup-mass
  bounds are the per-span `validateGeometry` checks the single truth already passed (log <= MAX_LOG).
- **The multiset is unchanged.** The LogUp sum over the split spans of a family is the sum over the same call IDs
  as one span; the global Wire/KIO bus balance (`protocol.admit` wire mass < p) is computed per call, not per truth.
- **Precedent.** Multi-span families are the designed case: `row_roster.zig` ("larger blocks use several spans"),
  `rv64-sha256-service.md` ("the same calls split over two truth spans also verify ... the largest basket blocks
  need 4 spans"), the legacy v3 planner (`truthsWithOptions` non-coalesced path) and the M3 profile that proved and
  fresh-verified all 15 blocks with split rosters (`vectors/reports/rv64-m3-20261104/`).
- **Canonical rungs.** When padding to rungs, spans are capped at the family's top rung, so every span maps to an
  existing class (`canonicalTruths` admits them; tested); no rung/receiver table is widened.

Only the producer's roster choice changes; proofs of split blocks are different bytes from any single-truth roster
(there is none for them today).

## Result: the 9 refused blocks prove with the flag; fresh CPU receivers accept every proof [M]

Driver/receiver built from `8e830d904` (= the flag commits; the rebased landing commits change only their parents):
`rv64-word16-ethereum-gpu-combined` sha256 `8043428d…`, receiver `f53896cd…`, pinned under
`/workspace/m3/build/m8-p-truth-split/pinned-ef/`. Runtime: the source-built opt-combined image (lib `25d0e62f`, now
the integrate default runtime). Preset: the frozen `baseline` arm + `--coalesce-truth-families`, security profile
`d2_native_b4_q54_p20_fold4`, auto arena (the bench15-1 default arm) + `STWO_RV64_M8_TRUTH_SPLIT=1`; blocks with
>= 40 segments also get `STWO_RV64_PCS_IDLE_CACHE_BYTES=0` (bench15 rule). Runner: bench15 (`rv64_m8_bench15.py`
from `codex/rv64-m8-gpu`, used as an uncommitted pod overlay with a `split` arm and a `--diagnostic-quiet` switch).
One service per block = one cold request then one warm request, then 2 fresh CPU-only receivers on those proofs.

| block | seg | refusal without the flag | leaves | cold s | warm s | warm / M3 [D] | warm capture / native / recursion s | cold = warm bytes | fresh receivers |
|---|---:|---|---:|---:|---:|---:|---|---|---|
| 24626900 | 12 | OneTruthPerFamilySourceCapacity | 20 | 46.76 | **20.47** | 0.300 | 3.34 / 8.99 / 7.88 | yes | 2/2 (62.6, 61.2 s) |
| 24697073 | 15 | OneTruthPerFamilySourceCapacity | 27 | 58.57 | **26.24** | 0.310 | 4.22 / 11.18 / 10.57 | yes | 2/2 (78.6, 78.4 s) |
| 26235168 | 28 | OneTruthPerFamilySourceCapacity | 45 | 98.93 | **44.47** | 0.306 | 6.17 / 20.69 / 17.20 | yes | 2/2 (133.1, 136.4 s) |
| 25229955 | 30 | OneTruthPerFamilySourceCapacity | 45 | 103.96 | **45.47** | 0.308 | 6.48 / 21.71 / 16.85 | yes | 2/2 (141.3, 143.9 s) |
| 25229951 | 40 | OneTruthPerFamilySourceCapacity | 58 | 136.94 | **62.44** | 0.349 | 9.44 / 29.75 / 22.59 | yes | 2/2 (186.8, 185.6 s) |
| 24628590 | 38 | V3TruthShapeExceeded | 55 | 132.05 | **60.38** | 0.325 | 8.47 / 30.05 / 21.32 | yes | 2/2 (196.9, 199.5 s) |
| 24628595 | 42 | V3TruthShapeExceeded | 64 | 144.62 | **68.45** | 0.321 | 9.25 / 34.14 / 24.51 | yes | 2/2 (220.0, 220.2 s) |
| 24628611 | 45 | V3TruthShapeExceeded | 67 | 160.07 | **73.81** | 0.315 | 9.98 / 37.67 / 25.47 | yes | 2/2 (257.2, 244.0 s) |
| 26235159 | 49 | V3TruthShapeExceeded | 73 | 167.00 | **72.82** | 0.291 | 9.79 / 35.92 / 26.43 | yes | 2/2 (256.1, 263.9 s) |

- Times are client request walls [M], one service each (n = 1, no median). Warm stage split is from the bench15
  critical-path row [M]; warm / M3 divides by the M3 request wall of the same block [D].
- **Unqualified walls.** The shared pod (≈9 streams) had sibling `zig build`s running; the cgroup quiet gate refused
  3/3 admissions on the first attempt, so these services ran in diagnostic quiet mode. Treat the walls as [M]
  single observations under load, not canonical 3+3 numbers.
- Together with bench15-1's 6 default-arm blocks (unchanged by the flag), **all 15 basket blocks now prove under
  the D2 coalesced profile** [M]. Warm sum of the 9: 474.5 s [D]; with bench15-1's 6 (87.46 s): 562.0 s for 15
  vs 1,843 s at M3 (0.305x) [D].
- **24628595 needed `STWO_RV64_DEVICE_ARENA_RESERVE=1073741824`** (arm `split-r1g`). With the default 2 GiB reserve its
  cold request failed in native stage one with `CudaAllocationFailed` -> `CudaFamilyWitnessFailed`: a **CPU** segment's
  GKR traversal workspace (ordinal 38, 13.96 GB) overran the auto arena by 0.24 GB (`mapped_free_bytes=13.72 GB`, live
  13.05 GB on device 0). Not a truth issue; the arena reserve is proof-neutral (scheduling/memory only). Proper fix
  is host memory-plan work (below).
- Bytes: cold and warm proofs are byte-identical per block (2/2). No golden exists for these blocks.

## Gates (flag landed default off) [M] (`gates.json`)

| gate | block | flag | source | result |
|---|---|---|---|---|
| gate-1 | 26235156 | on | 8e830d904 | **PASS**: 32/32 artifacts byte-identical to frozen D2 (cold + warm), 2/2 fresh receivers, corpus |
| gate-3 | 24628607 | on | 008ec0e6a (rebased on 786429aca) | **PASS**: 39/39 byte-identical to frozen D2, 2/2 receivers, corpus |
| gate-4 | 26235156 | off | 008ec0e6a | **PASS**: 32/32 byte-identical to frozen D2, 2/2 receivers, corpus |
| gate-2 | 26235156 | off | 008ec0e6a | FAIL, not ours: service exited before READY (`GpuPcsInitializationFailed`, 1.3 GB free per GPU) while pid 526130 (`m8-gn-node` combined-serve) held ~30 GB on both GPUs; rerun as gate-4 |

Gates use the integrate default runtime (lib `25d0e62f`). Unit tests: `test-riscv64-truth-gkr -Driscv-test-filter=truth`
(ReleaseSafe; includes the three new `plan.zig` split tests) PASS on the pod [M].

## Remaining host work

1. **Big-block device memory (CPU GKR workspace).** 24628595 needs a 1 GiB arena reserve; ordinals 0/37/38/39 ask
   10.5-14.2 GB of GKR traversal workspace while other segments hold ~12-13 GB of leases. The GKR stage should admit
   its workspace against the arena (or the memory plan should serialize >10 GB GKR workspaces per device) so the
   auto arena proves every block; owner: memory/runtime streams.
2. **Qualified timing.** Re-run the 9 blocks with 3 headline services each under the enforced quiet gate when the pod
   is quiet (the flag plus `split-r1g` for 24628595); the numbers above are single diagnostic observations.
3. **Default flip.** The flag only changes plans that are refused today, so flipping it on is proof-neutral for
   every currently-proving request (gates 1 and 3 run with it on). Flip once the integrator agrees.
4. **GPU-native path.** `gpu_native` shape hooks must accept several truths per non-Keccak family (the split emits
   e.g. 4 sha256 + 2 add + 2 double spans on 26235159); the CPU/legacy-owner path already does.
5. The bench15 harness (`rv64_m8_bench15.py`, `--bench-basket-block`) lives on `codex/rv64-m8-gpu`, not on integrate;
   the `split`/`split-r1g` arms and `--diagnostic-quiet` were a local pod overlay only.
