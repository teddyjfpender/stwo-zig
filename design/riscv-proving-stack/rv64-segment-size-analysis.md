# RV64 segment size: 2^22 versus 2^23 and 2^24 steps per CPU proof

Status: analysis only. No prover, AIR or schedule code was changed and no proof
was produced for this note. All costs are derived from the pinned controlled
baseline and from code reading. The machine-readable receipt is
`vectors/reports/rv64-ethereum-20261101/segment-size-analysis-v1.json`.

Source read: branch `codex/rv64-cmp-segment-size` at `9dba9705d`. Baseline
evidence: `vectors/reports/rv64-word16-execution-20261101/optimization-current-baseline-v1.json`
(source `259f49ff8`, three runs). The baseline's retained artifacts
(`/tmp/rv64-opt-current-baseline-v1/runs/baseline-2x8-r0/{roster,cost,schedule}.json`,
`physical-*.stages.json`, `cpu-*.bin`) were read without modification.

## 0. Summary

* **What stops a larger segment today.** One family of limits: the 24-bit
  clock. A CPU row's register/OWNER tick is `4*row+slot+1`. Its 24-bit
  `gap16 + 65536*gap8` and `tick_lo16 + 65536*tick_hi8` decompositions are
  range-checked with the 256-row U8 table. That table caps a proof at 2^22 rows.
  About 25 `<= 22` / `< 2^22` guards repeat this cap. Raising the guards is a
  constant change. Widening the clock is an AIR, transcript-identity and
  recursion-verifier change. Its soundness re-argument is short: tick plus gap
  stays below 2^27, far below the M31 modulus. LogUp masses, epoch16, the PCS,
  the twiddles and the lifted committer do not bind at 2^23 or 2^24.
* **Padding is not a cost here.** The last CPU proof already uses a minimal
  `cpu_log`. So 25x2^22, 12x2^23+2^22 and 6x2^24+2^22 all pad to exactly
  104,857,600 CPU rows.
* **Wall time is a wash.** Fewer proofs save about 0.67 lane-s each in fixed
  work (PoW 0.185, trace decommit 0.473), plus the shared ROM and table chips.
  Larger FFTs add about 4.5% per doubling to the roughly 38% of CPU time that
  is FFT work. The model gives:
  * 2^23: about -3.3 s of proving and about -3.4 s of setup, against +1 to +4 s
    of extra lane tail. Net is roughly -2% to -4% of the 157 s median.
  * 2^24: about -4.2 s of proving and -5.1 s of setup, against +3 to +8 s of
    tail.

  Both estimates sit inside the baseline's 7.5% run-to-run spread.
* **Clear wins.** Proof bytes fall from 24.5 MB to about 13.3-15.7 MB of CPU
  proofs at 2^23 (-36% to -46%), or about 7.4-8.6 MB at 2^24. Recursion work
  falls by about 41% (2^23) or 61% (2^24). Leaves go from 30 to 18 or 12, folds
  from 29 to 17 or 11, and the binary fold depth from 5 to 5 or 4. Setup keys go
  from 30 to 18 or 12.
* **Memory.** The modelled peak private footprint is about 35 GB (range 35-45)
  for 2x2^23 in flight, and about 35 GB (35-45) for 1x2^24. Both fit in 64 GB.
  2x2^24 (about 48-65 GB) does not fit safely. The file-backed retained MAIN
  stays about 41 GB at every segment size, so page-cache pressure, and with it
  major faults, rises at the larger footprint.
* **Recommendation.** After the lane sweep, test 2^23, not 2^24. First prototype
  the clock-widening schema as a separate encoding identity. Run three arms:
  current schema at 2^22, new schema at 2^22, new schema at 2^23. Judge by fresh
  receiver acceptance plus wall, cells, bytes and memory, not byte identity.
  Adopt it for recursion and GPU-pipeline reasons, not CPU wall time, unless
  the measurement beats the noise.

## 1. Hard limits on segment size

"Constant" means only a guard changes. "AIR" means constraints, relation
shapes, transcript identity and the in-circuit verifier change. "Soundness"
means a written re-argument is needed.

### 1.1 Step and row caps (all constant changes)

| Limit | Location | At 2^23 / 2^24 | Lift |
| --- | --- | --- | --- |
| `batch_steps < 2^22` | `src/integrations/riscv_cpu/rv64_ethereum_request.zig:120` | rejects | constant |
| Compact tape `MAX_STEPS = 2^22-1` | `src/frontends/riscv/rv64/compact_tape.zig:14` | rejects | constant (tape storage doubles) |
| Boundary capture `max_steps < 2^22` | `src/frontends/riscv/rv64/boundary_capture.zig:18` | rejects | constant |
| Access census `MAX_BATCH_STEPS` | `src/frontends/riscv/rv64/access_census.zig:6` | rejects (diagnostic path) | constant |
| Prefix budget `< 2^22` | `src/integrations/riscv_cpu/word16_global_execution/protocol.zig:106`, `word16_execution/execution.zig:21-23` | rejects | constant |
| `minimalLog` / `minimalPrefixLog` `< 2^22` | `src/integrations/riscv_cpu/word16_execution/coverage.zig:44-58` | rejects | constant |
| CPU `MAX_LOG = 22` | `src/frontends/riscv/rv64/air/word16_execution/layout.zig:50` (used by `row.zig:12,37`) | rejects | constant, but see clocks (1.2) |
| Execution inputs `log > 22` | `src/frontends/riscv/rv64/air/word16_execution/types.zig:14` | rejects | constant |
| Geometry: every role `<= 22` (multiplication `<= 23`) | `src/integrations/riscv_cpu/word16_execution/geometry.zig:39-42,55,59,188,192`; `delegations/multiplication/degree3_layout.zig:16` | CPU rejects; ladders fit at 2^23 | constant |
| Planner ladder `full <= 22` (two instances, head = full-1) | `src/integrations/riscv_cpu/word16_global_execution/ethereum/plan.zig:9-19` | 2^23 fits (max LS 3.17M, log 22); **2^24 LS needs log 23** (6.21M) | constant, plus a third instance or a log-23 head |
| LS count `< 2^22` per proof | `src/integrations/riscv_cpu/word16_execution/memory/statement.zig:42`, `memory/collector.zig:24`, `memory/global_manifest.zig:65-66`, `air/memory/load_store_v2/source.zig:52` | 2^23 fits this block (3.17M); 2^24 rejects | constant |
| Division `<= 22` | `air/delegations/division/word16_product/source.zig:16`, `.../native.zig:7` and siblings | not binding (largest is 2,641 rows at 2^24) | constant |
| Keccak/secp CPU bus `steps < 2^22` | `air/delegations/keccak/cpu_bus.zig:22,65`, `air/delegations/secp256k1/cpu_bus.zig:27,100` | rejects | constant |
| Word16 bridges `log <= 22` | `air/delegations/keccak/word16_bridge/packed_rows.zig:14`, `air/delegations/secp256k1/word16_bridge/packed_rows.zig:14` | not binding (Keccak bridge log 19 at 2^24) | constant |
| Legacy bridges `call.clock < 2^22` | `air/delegations/keccak/bridge/trace.zig:85,158`, `air/delegations/secp256k1/bridge/trace.zig:98,174` | legacy, not on the Word16 path | n/a |

Under the larger-segment groupings below, ladder headroom comes from summing
consecutive baseline rosters. Maximum active rows per segment, with the
`ceil(log2)` the ladder needs:

| Family | 2^22 | 2^23 | 2^24 |
| --- | ---: | ---: | ---: |
| LS (+tail) | 1,606,233 (21) | 3,165,957 (22) | 6,206,386 (**23**) |
| BINARY (+tail) | 1,159,797 (21) | 2,030,872 (21) | 3,852,107 (22) |
| SHIFT (+tail) | 899,678 (20) | 1,633,065 (21) | 3,254,946 (22) |
| ALU (+tail) | 919,132 (20) | 1,831,080 (21) | 2,603,890 (22) |
| MUL | 330,070 | 656,653 | 862,675 |
| Keccak bridge | 245,575 | 280,375 | 287,225 |

The ladder caps are liveness limits, not soundness limits. With 100% LS density
a 2^23 segment would also need LS log 23. The current two-instance ladder caps
total capacity just below 2^22.

### 1.2 Clocks (AIR change plus a short soundness re-argument)

These are the real limits.

* **Register clock.** `tick = 4*row+slot+1` and
  `gap = tick - previous - 1 = gap16 + 65536*gap8`
  (`air/word16_execution/row.zig:21-25`, `tuples.zig:6-13`).
  * The three `gap8` columns go through the CPU's U8 lookups. In
    `layout.zig:44-45` the "affine" block is OWNER + U16x3 + U8x3.
  * The README states the 24-bit cap: "Gap16/U8 lookups prove the 24-bit
    nonnegative gap" and "the 24-bit clock cap" (`air/word16_execution/README.md`).
  * Register clocks reset per batch. The batch is the clock window.
* **OWNER/RAM time.** OWNER19 carries `epoch16, tick24` with `tick = 4*row+4`
  (`tuples.zig:52-61`).
  * The LS after-tick is `lo16 + 65536*hi8` (`air/memory/load_store_v2/equations.zig:75`).
    Its U8 queries include logical columns 13 and 26, the tick and gap highs
    (`load_store_v2/layout.zig:24-25`).
  * Closed RAM orders `(epoch, tick)` lexicographically, with
    `before_low + gap_low + 1 = after_low + 65536*carry` and
    `before_high + gap_high + carry = after_high`
    (`air/memory/closed_ram/equations.zig:136-139`).
  * The U8-ranged highs are `T_U8 = {11,13,26}` and `B_U8 = {11}`
    (`closed_ram/layout.zig:25,41`). The schema is pinned "epoch16/tick24"
    (`closed_ram/layout.zig:1`).
  * Native types are `tick: u24`: `closed_ram/types.zig:5,7`,
    `load_store_v2/native.zig:9`, `keccak/word16_bridge/types.zig:8`,
    `secp256k1/word16_bridge/types.zig:9`.
  * The bridges range-check `tick >> 16` with U8: `keccak/word16_bridge/lookup.zig:24-25`
    and `secp256k1/word16_bridge/source.zig:45`.
  * Other guards: `word16_execution/cells_wire.zig:66`
    (`tick >= 1<<24` rejected; the wire field is already 4 bytes),
    `air/memory/openings.zig:22`, `batch.zig:45`, `cell_air.zig:206`.
* **Soundness basis.** `air/encoding.zig:224-225` ("a 24-bit integer clock and
  gap have sum below 2^25 < M31") and
  `design/riscv-proving-stack/rv64-state-range-review.md:25,204` (the clock is
  "strictly below 2^24 for CPU log at most 22").
* **Identity strings to bump.** `air/word16_execution/features.zig:138` and the
  LS/RAM schema hashes, for example `air/memory/load_store_v1/types.zig:41`.

At 2^23 the tick reaches about 2^25 and the high limb needs 9 bits. At 2^24 it
reaches 2^26 and needs 10 bits. A U8 lookup on a 9-bit value fails the LogUp,
so no honest proof exists. Neither does a "cost-only" proof without the AIR
change.

Two ways to lift:

* **A. Widen the high limb.** This is the smallest change.
  * Range-check every clock/gap high limb with a new preprocessed range
    relation of 2^10 rows. Or use two range16 lookups `{x, x*2^6}`: for x below
    2^16, `x*2^6 < 2^22 < p`, so membership of both proves x below 2^10.
  * Byte U8 queries (LS logical 73/74, multiplication bytes) stay on U8.
  * Soundness: `prev + gap + 1 = tick` with both terms below 2^26 sums to
    below 2^27, far below p. Strict integer order and the REG/RAM chronology
    induction carry over unchanged. Unit-mass bounds are unaffected.
  * Cost: a new relation or one extra range16 fraction per clock limb
    (3 per CPU row, 2 per LS row, 2 per bridge row).
  * Recursion: the transcript and the in-circuit verifier component set
    change.
* **B. ZisK-style windows (see 5).** Keep tick24 and split a proof into
  2^22-row windows.
  * Each window gets its own epoch: `epoch = public_base + window(row)`,
    affine in a new fixed column, with `tick = 4*(row mod 2^22)+slot+1`.
  * The 32-row register boundary chip re-anchors registers at each window
    boundary. The REG tuple gains a window coordinate.
  * No range tables or u24 types change. The OWNER epoch becomes row-dependent,
    the register boundary doubles, and receiver epoch accounting changes
    (`protocol.zig:117` requires `epoch == index + 1`).
  * Soundness: the per-window argument is unchanged, but the window seam needs
    its own linkage proof.

Option A is less plumbing. Option B keeps every existing native/wire bound.

### 1.3 Limits that do not bind

* **Epoch16.** `0 < epoch <= 65535` (`word16_execution/types.zig:14`) and
  `epoch == index+1` (`word16_global_execution/protocol.zig:117`). Fewer
  segments only help.
* **LogUp masses below p.**
  * Per proof, positive range16/range8/FUNCTION/JALR/BINARY/SHIFT masses are
    checked below M31 (`geometry.zig:44-49`, `word16_v1/function_bus.zig:21-28`).
  * At `cpu_log = 24` with every family at its ladder maximum, range16 mass is
    about 3*2^24 + 12*2^23 + 5*2^23 + 4*2^23 + 23*2^22 ≈ 0.33*10^9, still about
    6x below p. These bounds stop binding only around 2^27 rows.
  * Global RAM mass is `2*LS + |init| + |term|` ≈ 70M
    (`word16_global_execution/protocol.zig:131-138`), independent of segmenting.
* **Range tables.** Fixed sizes: range16 log 16, range8 log 8, and/shift tables
  log 16 (`geometry.zig:142-143`). Multiplicities grow, but stay under the mass
  bounds above.
* **PCS, twiddles and FRI.**
  * Geometry cells allow log up to 30 (`geometry.zig:160`). The quotient domain
    walk allows 31 (`src/prover/pcs/quotient_domain_walk.zig:34`).
  * Twiddles are built per domain on the M31 circle of order 2^31
    (`src/prover/poly/twiddle_tower.zig:28-50`).
  * At blowup 1, LDE log 24 (2^23) or 25 (2^24) is fine. FRI fold 1 gains one
    layer per doubling (21 inner layers today, per `word16-recursion-readiness-shape-v1.json`).
  * `src/prover/native/resource_admission.zig:5` (`MAX_LOG_ROWS = 22`) only
    serves the generic `prove` CLI (`src/tools/prove/cli.zig`), not this path.
* **Fixed and preprocessed columns.**
  * The ROM is program-sized (log 20, 32 fixed + 1 main + 8 interaction
    columns). The program metadata cap `count <= 2^22`
    (`word16_execution/program_metadata.zig:64`, `program.zig:13`) is a program
    size, not a step count.
  * CPU fixed columns (index, first, last) scale with the segment.
* **Keccak/secp truth proofs.** These are block-global and segment-independent
  (`keccak/shared/roster.zig:117`: log `<= 21`).
* **Lifted committer.**
  * Every tree commits at its largest column's LDE height. Today that is 23 for
    CPU proofs (`src/prover/pcs/revision_lifting.zig`).
  * The streaming committer absorbs each column at its own domain and
    replicates hasher states upward (`src/prover/vcs_lifted/expand.zig:1-9`).
    The state array is 136 B per leaf: 1.14 GB at height 23, 2.3 GB at 24,
    4.6 GB at 25.
  * Per proof, replication grows with 2^height while the proof count halves,
    so the block total is roughly constant.
  * The telemetry "lifted leaf cells" (`ethereum/telemetry.zig:24`) is an
    exposure count, not a time.
* **Wire limits** (`word16_global_execution/services/wire.zig:15`). With 64 MB
  per proof, 2^30 total steps and a 2^32 native row sum, none binds.

## 2. Memory per proof

Measured, median of 3 runs (2 lanes x 8 workers): peak private footprint
28.50 GB, max RSS 48.38 GB, retained-MAIN mapped total 40.92 GB (all 30 proofs),
end-of-run footprint 6.69 GB.

Per-proof `process_footprint_bytes_at_end` traces (`physical-*.stages.json`)
show the structure:

* **Stage 1** (all 30 MAIN commits, about 32 s) climbs from 16-17 GB to about
  22-24 GB.
* **Stage 2** (about 94 s) falls almost linearly, from about 25 GB to about
  10 GB, as proofs complete. The slope is **about 0.55 GB released per CPU
  proof**. That matches one height-23 Merkle tree's layers (2^24 x 32 B ≈ 0.54
  GB) retained per proof across the global draw barrier.
* Calibration: 28.5 ≈ 6.7 (base) + 15.3 (retained per-proof state: 25 x 0.55 +
  truths about 1.5) + 2 x W. That gives an **in-flight transient W ≈ 3.3 GB per
  lane** at 2^22. This includes the 64-column streaming batch (64 x 2^23 x 4 B =
  2.1 GB) and the 1.14 GB hasher-state array.

Per-proof native data at 2^22 (CPU proof 0, `cost.json`): 62.8M fixed, 413M
main and 321M interaction cells (3.2 GB at 4 B/cell). The composition
accumulator at 2n is 2^23 x 16 B = 134 MB per log size. The composition tree is
8 x 2^23 x 4 B = 268 MB.

Extrapolation, assuming transient scales with the LDE and retained state with
tree height x proof count:

| Configuration | Retained (block total) | In flight | Modelled peak footprint |
| --- | ---: | ---: | ---: |
| 2 x 2^22 (measured) | 15.3 GB | 2 x 3.3 GB | 28.5 GB |
| 2 x 2^23 | 12x1.1+0.55+1.5 ≈ 15.3 GB | 2 x 6.5 GB | **≈ 35 GB (range 35-45)** |
| 1 x 2^24 | 6x2.2+0.55+1.5 ≈ 15.3 GB | 13 GB | **≈ 35 GB (range 35-45)** |
| 2 x 2^24 | 15.3 GB | 2 x 13 GB | ≈ 48 GB (range 48-65) |

The upper ends assume the MAIN read-back (2.9 GB per CPU proof at 2^23) and the
interaction native data are anonymous and resident together with the streaming
scratch.

**Fit in 64 GB.**

* 2x2^23 and 1x2^24 fit by footprint.
* 2x2^24 does not leave safe headroom.
* In every case the file-backed retained MAIN stays about 41 GB, since it is
  total main cells x 4 B and independent of segmenting. On a 64 GB host the
  page cache for it shrinks from about 35 GB to about 29 GB, so expect more
  than the baseline's 3.8M major faults.
* `commit_batch_columns` 64 → 32 halves the streaming scratch, if needed.

## 3. Fixed per-proof cost that larger segments amortise

Per CPU proof, as lane-wall seconds with 8 workers (median of 3 runs over the
25 CPU proofs):

| Item | Per proof | Basis |
| --- | ---: | --- |
| Proof of work (P26) | 0.185 s | 4.62 s / 25 |
| Trace decommit (70 queries x ~1,600-2,500 columns) | 0.473 s | 11.82 s / 25 |
| FRI decommit, OODS, mixing, assembly | 0.010 s | |
| **Constant subtotal** | **0.667 s** | |
| Shared ROM/shift/and/range/selection chips | 2.2% of committed cells and 64% of fixed cells per proof | `roster.json` |
| Setup per key | 11.0 s for 30 keys; fixed cells/key 35.7M table + 19.7M segment-proportional | `roster.json`; assumes setup ∝ fixed cells |

Proof bytes:

* Today 24,522,672 B in CPU proofs (mean 980,907; range 796,800-1,183,824)
  plus 5,179,000 B in truth proofs.
* A proof's opened values are column-bound, so per-proof bytes are roughly
  constant. Depth adds about 280 PCS and about 1,190 FRI hash witnesses per
  doubling (+47 KB, about +5%).
* 2^23: 12 x (0.98-1.18 + 0.05) MB + 0.91 MB = **13.3-15.7 MB** (-36% to -46%).
* 2^24: **7.4-8.6 MB** (-65% to -70%).
* Whole bundle: 29.7 → 18.5-20.9 → 12.6-13.8 MB.

Register boundary rows are 32 per proof. They are amortised but negligible.
RAM INIT/TEARDOWN appear only in the first and last proofs under global RAM, so
segmenting does not change them. Ladder padding is scale-free (power-of-two
quantisation) and does not systematically improve.

Recursion (`rv64-recursion-leaf-wrap-fold.md` §4-6; per-leaf work from
`word16-recursion-readiness-shape-v1.json`):

* Leaves are padded to a fixed canonical target, so each wrap costs about 9 s
  on CPU and under 1 s on GPU regardless of leaf width. A fold costs about 10 s
  on CPU.
* The raw leaf (about 38,000 Blake2s compressions; about 37% of the target)
  grows by about 2,030 compressions (+5.3%) per doubling: FRI +1,750, paths
  +280. It still fits the target.
* Leaves 30 → 18 → 12. Reductions 29 → 17 → 11. Binary fold depth 5 → 5 → 4.
* CPU recursion work ≈ 560 s → 332 s (-41%) → 218 s (-61%).
* Root size and root receiver cost are unchanged.

Estimated block-level amortisation (CPU proofs, lane-seconds; total 218.9):

| | 2^22 | 2^23 | 2^24 |
| --- | ---: | ---: | ---: |
| CPU proofs (last proof log 22) | 25 | 13 | 7 |
| Padded CPU rows | 104,857,600 | 104,857,600 | 104,857,600 |
| Constant work saved | - | -8.0 | -12.0 |
| Table work saved | - | -2.7 | -4.1 |
| FFT log growth | - | +3.7 | +7.4 |
| Deeper decommit | - | +0.4 | +0.4 |
| **Net CPU lane-s** | 218.9 | **212.2 (-6.7)** | **210.6 (-8.3)** |
| Wall, 2 lanes | - | -3.3 s | -4.2 s |
| Setup (∝ fixed cells) | 11.0 s | 7.6 s | 5.9 s |

## 4. Costs that grow

* **FFT log factor.** Kernel receipts put the FFT share at 58% of composition
  helper time (`composition-kernel-timing-v1.json`) and 64% of streaming commit
  (transform versus leaf hash, `commit-kernel-timing-v1.json`). That is about
  82.8 of 218.9 CPU lane-s (38%). Per-element cost rises by about 1/22.5 per
  doubling. Cache effects at LDE 2^24/2^25 are unmodelled and could add a few
  percent; measure before claiming.
* **Merkle and FRI depth.** One more level per tree and one more FRI layer per
  doubling: +5% proof bytes and +5% raw leaf. Hashing volume is linear in
  cells, so it is unchanged.
* **Granularity.**
  * Today the lane tails are about 1.2 s in stage 2 and 0.8 s in stage 1
    (`schedule.json`).
  * Stage-2 CPU proofs take about 6 s at 2^22. At 2^23 they take about 12 s,
    so the expected extra tail is +1 to +4 s. At 2^24 they take about 24 s, so
    +3 to +8 s.
  * Stage 1 (about 2 s, 4 s or 8 s per proof) adds a smaller tail before the
    global barrier.
  * 13 or 7 CPU proofs plus 5 truths give coarse bins for 2 lanes. Wider
    machines (more lanes or GPUs) run out of parallel work: 7 proofs cannot
    fill 8 devices.
* **Latency.** Per-proof latency is about 8.8 s at 2^22, 17 s at 2^23 and 35 s
  at 2^24 on CPU, and the last segment gates the root. For a GPU pipeline that
  proves segments as execution produces them, 2^22 segments give earlier
  starts, finer load balance and a smaller device working set. 2^24 needs about
  13+ GB transient per proof on device.
* **Memory.** See section 2. Transient roughly doubles per doubling.
  Retained state and spilled MAIN are roughly constant.

## 5. ZisK comparison (read-only source, treated as data)

* **Segment size.** ZisK declares `Main(N: 2**22, lanes_x_row: 4)`
  (`pil/zisk.pil:91`). A segment holds `STEPS = N*lanes_x_row` = 2^24 steps
  (`state-machines/main/pil/main.pil:31-35`).
* **Timestamps.** Each lane's step is global:
  `segment_initial_step + SEGMENT_STEP*lanes + lane` (`main.pil:114-117`).
  The memory timestamp is `mem_step = 1 + 4*step + slot` (`main.pil:242`), in a
  64-bit field with `MAIN_STEP_BITS = 36` and `REG_STEP_BITS = 38`
  (`pil/config.pil:1-4`). So ZisK never needs an epoch.
* **Registers in Main.** Registers are a memory region driven by a linked list.
  Each access proves the previous tuple and assumes the current one. Order is
  enforced only on deltas: `range_check(mem_step - prev - 1, 0, MAX_RANGE)` with
  `MAX_RANGE = 2^24-1` (`main.pil:11,404-406`). The strict `-1` excludes
  self-cycles (`main.pil:296-310`).
* **Avoiding the delta cap.** Registers are reloaded every flush window of at
  most 2^22 steps. Each window publishes airvals `last_reg_value` and
  `last_reg_mem_step` per register and re-proves/assumes them at a special step,
  so every delta stays below 4*2^22 = 2^24 regardless of segment size
  (`main.pil:596-642`). The segment index is range-checked against
  `2^MAIN_STEP_BITS / STEPS` (`main.pil:703`).
* **What maps to us.**
  * Our per-batch register reset plus the public register boundary is exactly
    a ZisK flush window, but our window is tied to the proof.
  * ZisK's lesson is to **decouple the clock window from the proof size**. That
    is option B above, with epoch as the window id, because M31 cannot hold
    global timestamps.
  * ZisK's 4 lanes per row also keep Main at 2^22 rows while proving 2^24
    steps: the FFT log stays 22 and the width grows 4x. For us, two steps per
    CPU row would avoid the CPU `MAX_LOG` and FFT-log growth. It would still
    need clock widening or windows, because the tick would reach 2^25.
  * Their delta-only range checks match our `gap16/gap8` scheme. The difference
    is field size, not design.

## 6. Recommendation and experiment design

1. **Do not change anything during the lane sweep.** Geometry interacts with
   lane/worker choices.
2. **Test 2^23 after the sweep.** Do not test 2^24: it additionally needs the
   LS ladder at log 23 (`plan.zig:11`, `memory/statement.zig:42`). It loses
   more to tails and does not fit 2 lanes in 64 GB.
3. **Minimal 2^23 change set.** All in a new encoding identity; never reuse old
   proof fixtures.
   * Constants from 1.1. For this block only the CPU needs log 23; the ladders
     already fit.
   * Option A clock widening:
     * 9-bit (or 10-bit, to be 2^24-ready) high-limb range for the CPU `gap8` x3,
       LS tick/gap highs, closed-RAM `T_U8 {11,13,26}`/`B_U8 {11}`, and the
       Keccak/secp bridge tick highs.
     * u24 → u32 native types and the `1<<24` guards.
     * Feature/schema identity strings.
     * Receiver checks.
   * A short soundness note superseding the 2^24 clause in
     `rv64-state-range-review.md:25,204` and `encoding.zig:224`.
   * The recursion in-circuit verifier can follow later. The native experiment
     does not need it.
4. **Arms.** Each arm runs three times in ABBA order, with team load suspended
   as in the baseline.
   * A: current schema at 2^22, the pinned control.
   * B: new schema at 2^22, to isolate the widened-range cost.
   * C: new schema at 2^23, same 2x8 lanes.
   * Optional D: new schema at 2^24, 1x16, only after LS ladder support.
5. **Acceptance.** Byte identity is impossible because the geometry changes.
   Require:
   * A fresh completed-block receiver accepts.
   * The 43-byte output is identical.
   * Total steps are 104,253,913, with 13 CPU proofs and 5 truth proofs.
   * Final PC/registers and RAM terminal values/rights in `cells.bin` are
     semantically equal to A.
   * Negative tests: a high limb at or above 2^9 is rejected, a gap at or above
     2^25 is rejected, and a forged cross-window predecessor is rejected.
6. **Measure.**
   * wall, prove, setup
   * per-stage lane-s (`physical-*.stages.json`)
   * native and lifted cells (`cost.json`)
   * proof bytes
   * peak footprint, max RSS, major faults
   * stage1/stage2 lane tails (`schedule.json`)
   * per-proof latency

   Decision rule: adopt for CPU throughput only if C beats B by more than the
   7.5% spread. Otherwise adopt only if the recursion/proof-size savings (-41%
   leaves, about -40% bytes) are the priority, and keep 2^22 as the GPU
   pipelining granule.

## Verification status

The soundness statements in 1.2 and 1.3 (clock widening bounds, mass bounds)
and the FRI/union-bound remarks are engineering analysis. They need review
before any schema change. Fewer proofs slightly improve the union bound over
per-proof soundness errors (log2 25 ≈ 4.6 bits versus log2 13 ≈ 3.7 bits); the
per-proof FRI proximity terms over QM31 change negligibly with domain size.
This needs verification against the security-policy receipt. Every timing and
memory projection in sections 2-4 is a model calibrated on one baseline, not a
measurement.
