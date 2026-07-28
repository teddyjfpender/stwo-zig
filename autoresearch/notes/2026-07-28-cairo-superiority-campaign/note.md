# Cairo superiority campaign

## Status

Open campaign on branch `autoresearch/cairo-native-throughput-10x`, based on
head `ad2d3ac5`. The objective is to make the Zig Cairo prover faster than the
pinned Rust `stwo-cairo` prover on the same host. This is not a Native-board
promotion: the autoresearch manifest does not score the Cairo frontend.

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.

Every increment must preserve exact proof bytes, statement validation,
protocol parameters, and backend capability declarations. Admission of any
fast path must follow structural properties — byte volume, run counts,
fragmentation — never a workload name, input path, fixture digest, or target
shape.

## Increment 1: CPU FRI quotient fragmentation

**Outcome: negative audit. No defect found, no source change.**

### Motivation

The accepted Metal quotient candidate in
`autoresearch/notes/2026-07-27-cairo-system-throughput/note.md` fixed a real
fragmentation defect: arithmetic-2m supplies 1.821 GB of raw quotient columns
in 361 physical source runs, and a historical `raw_bytes >= 64 MiB` predicate
launched one full-domain numerator pass **per run**. Gathering those inputs
once into a flat private arena took the stage from 1,350 ms to 212 ms, a 6.37x
win.

The CPU lane was described as retaining the proven flat pack only for *small*
fragmented inputs, which suggested the same byte-keyed exclusion might be
starving large Cairo workloads. CPU `fri_quotient_build_and_commit` is a real
cost centre — 601 ms on memory-7m and 278 ms on arithmetic-2m in the head
profiles at `/private/tmp/cairo-direct-feed-portfolio-v1/cpu-*.stages.json` —
so the hypothesis was worth testing.

### Mechanism as actually implemented

The CPU quotient path is structurally different from the Metal path and does
not have the defect.

A CPU quotient input is not a segmented buffer. `ColumnEvaluation`
(`src/prover/pcs/quotient_column_geometry.zig:19`) is one contiguous
`[]const M31` per column with a `log_size`; there are no physical source runs
to gather. What the Metal lane calls fragmentation appears on the CPU as
*implicit lifting*: a column smaller than the lifting domain repeats each
even/odd source pair across a `2^shift_amt`-row run.

For any lifting domain of `2^13` rows or more
(`src/prover/pcs/quotient_tile_executor.zig:27`), the provider selects
`.bounded_cpu` and builds two plans
(`src/prover/pcs/quotients/lazy_provider.zig:219-241`):

- `planning.buildCompactContributionPlan`
  (`src/prover/pcs/quotients/planning.zig:388`) folds every implicitly lifted
  contribution (`shift_amt >= 2`) into groups keyed by
  `(sample batch, source value count, shift)`.
- `quotient_direct_plan.build` (`src/prover/pcs/quotient_direct_plan.zig:17`)
  keeps only the remaining full-domain columns as direct views.

Execution makes exactly **one** fused, tiled pass over the domain
(`src/prover/pcs/quotient_tile_executor.zig:182` `executeBatched`). Inside each
256-row tile, `accumulateTile`
(`src/prover/pcs/quotient_tile_executor.zig:240`) walks compact groups and
direct views into output-stationary numerator planes.
`quotient_compact_groups.zig:35` reduces all members of a group to one even/odd
pair per lifted run and broadcasts that pair once across the run;
`quotient_direct_groups.zig:33` fuses four direct columns per pass when they
share a sample batch and have a single contribution each.

So the per-row work already scales with *groups*, not with source columns or
source runs. There is no per-run domain walk, no repeated denominator
inversion per source run, and no segmented gather.

### Audit measurements

Temporary instrumentation was added to
`src/prover/pcs/quotients/lazy_provider.zig` and
`src/prover/pcs/quotient_tile_executor.zig`, gated behind a
`STWO_QUOTIENT_AUDIT` environment probe, then reverted before commit. It
counted plan shape and summed per-phase worker time.

| Quantity | arithmetic-2m | memory-7m |
| --- | ---: | ---: |
| Lifting log size / domain rows | 22 / 4,194,304 | 23 / 8,388,608 |
| Flattened columns | 761 | 882 |
| Active columns | 646 | 768 |
| Active non-zero columns | 472 | 611 |
| Raw quotient column volume | 1,166.298 MiB | 4,139.296 MiB |
| Sample batches | 14 | 16 |
| Compact plan admitted | yes | yes |
| Compact groups | 26 | 36 |
| Compact members | 550 | 704 |
| Direct views | 50 | 59 |
| Tiles (256 rows each) | 16,398 | 32,778 |
| Full-domain passes | 1 | 1 |
| Numerator streams per tile | 43 | 56 |
| Four-way fused direct passes per tile | 11 of 17 | 13 of 20 |

Two facts close the hypothesis.

First, the compact plan is admitted at both sizes. The
`MAX_COMPACT_GROUP_BYTES = 1 MiB` budget
(`src/prover/pcs/quotients/lazy_provider.zig:34`) bounds **plan metadata
only** — `CompactContributionMember` is 32 bytes, so 550 members cost 17.6 KiB
and 704 members cost 22.0 KiB, 1.7% and 2.2% of the budget. The budget is not
a function of raw column volume and does not exclude large inputs. There is no
CPU analog of the Metal `raw_bytes >= 64 MiB` predicate.

Second, the collapse ratio is already near the achievable floor: 472 active
non-zero source columns reduce to 43 numerator-plane read-modify-write streams
per tile on arithmetic-2m, and 611 reduce to 56 on memory-7m. Total domain
passes equal one in both cases (tiles x 256 rows exactly equals the domain
size).

Phase split, worker-summed, arithmetic-2m, single cold process, wall stage
277.1 ms in the same process:

| Phase | Worker-summed ms | Share |
| --- | ---: | ---: |
| Numerator accumulation (`accumulateTile`) | 474.8 | 44.4% |
| Finalize + tile emit (includes fused Merkle) | 370.3 | 34.6% |
| Denominator batch inversion (`prepareBatchMajor`) | 182.5 | 17.1% |
| Bit-reversed domain walk | 28.7 | 2.7% |
| Numerator plane clear | 12.8 | 1.2% |

memory-7m, same instrumentation build, wall stage 630.3 ms: accumulation
1,994.7 ms, finalize + emit 845.3 ms, denominator inversion 459.0 ms, domain
walk 62.4 ms, clear 36.4 ms.

These phase timings carry instrumentation overhead (five `Instant.now()` calls
and five atomic accumulations per tile) and were taken under a shared host, so
treat them as shares rather than absolute costs. The plan-shape counts are
exact.

### Verdict

R7 closes negative. The CPU FRI quotient path is run-ceiling-bounded already:
one fused domain pass, group-collapsed accumulation, and a compact-plan
predicate that admits the largest measured Cairo inputs. Porting the Metal
remedy would be a no-op because the condition it repairs never occurs here.

### Paired measurement and noise floor

Because the increment ships no source change, the A-B-B-A run compares two
builds of the same sources: the pristine predecessor tree copied to
`/private/tmp/campaign-inc1-pred/zig-out` before any edit, and a fresh rebuild
after the instrumentation was reverted. Its value is not a treatment effect —
there is none — but a calibration of this host's noise floor, which every
later increment in the campaign must clear.

Cold processes, interleaved pred/cand/cand/pred, `--verify` on every run, no
sample discarded.

| Workload | Arm | Prove ms | Quotient stage ms |
| --- | --- | ---: | ---: |
| arithmetic-2m | pred 1 | 3,142.939 | 300.489 |
| arithmetic-2m | cand 1 | 3,296.576 | 342.335 |
| arithmetic-2m | cand 2 | 3,202.980 | 331.860 |
| arithmetic-2m | pred 2 | 3,178.248 | 300.461 |
| memory-7m | pred 1 | 7,392.830 | 617.102 |
| memory-7m | cand 1 | 7,584.830 | 623.093 |
| memory-7m | cand 2 | 7,591.878 | 607.022 |
| memory-7m | pred 2 | 7,437.917 | 602.469 |
| all-opcodes | pred 1 | 1,643.247 | 138.474 |
| all-opcodes | cand 1 | 1,603.982 | 137.453 |

| Workload | Pred mean prove ms | Cand mean prove ms | Ratio | Pred mean quotient ms | Cand mean quotient ms | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| arithmetic-2m | 3,160.594 | 3,249.778 | 1.028x | 300.475 | 337.098 | 1.122x |
| memory-7m | 7,415.374 | 7,588.354 | 1.023x | 609.786 | 615.058 | 1.009x |
| all-opcodes | 1,643.247 | 1,603.982 | 0.976x | 138.474 | 137.453 | 0.993x |

Identical sources therefore produced spreads of -2.4% to +2.8% on complete
prove time and up to +12.2% on the quotient stage alone. **Any future
single-digit-percent claim on this host is inside the noise and must not be
accepted without more samples or a quieter machine.**

Host load: the block opened at load average 4.57 and closed at 10.86.
Contamination was real and is reported rather than hidden. An unrelated
`test-riscv-release-exhaustive` suite ran in another checkout for the entire
session, and the Metal product build overlapped the first arithmetic-2m
samples. A-B-B-A adjacency is the only defence applied.

### Verification

- Proof bytes byte-identical across arms on every workload:
  arithmetic-2m `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`,
  memory-7m `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`,
  all-opcodes `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`.
- Metal arithmetic-2m proof digest equals the CPU digest
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`, with
  `classification: accelerated_without_fallbacks`, 74 Metal dispatches and
  `cpu_fallbacks: 0`.
- Pinned official Rust verifier accepted the candidate arithmetic-2m proof:
  `verified: true`, channel `blake2s`, proof digest
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.
- `zig build test-cairo-cpu-product test-cairo-frontend -Doptimize=ReleaseFast`
  passed; product closure PASS over 326 transitive Zig sources; identity
  reported `dirty: false`.
- Harness note for later increments: a copied product binary needs its whole
  `zig-out` tree. `execution_adapter.zig:116` resolves `stwo-cairo-vm-adapter`
  beside the executable and `profile.zig:140` resolves the params manifest at
  `<exe_dir>/../share/stwo-zig/cairo/official/all_opcodes.params.json`.

### Rejected alternatives

- **Port the Metal flat-arena gather to the CPU.** Rejected: CPU columns are
  already contiguous. A gather would copy 1.17 GB (arithmetic-2m) or 4.14 GB
  (memory-7m) to produce data the tile executor can already read in place.
- **Raise `MAX_COMPACT_GROUP_BYTES`.** Rejected: measured metadata use is 1.7%
  and 2.2% of the existing budget, so the constant is not binding on any
  measured workload. Changing it would be an unmeasurable no-op.
- **Merge compact groups that share a sample batch but differ in shift.**
  Would cut arithmetic-2m from 26 compact streams to at most 14, about 12 of
  43 numerator streams. M31 addition is associative and commutative so exact
  bytes would survive, but the projected saving is roughly 28% of 44% of a
  277 ms stage — under 1% of a 5.3 s proof — against a real correctness risk
  in merging runs with different block boundaries. Not worth this increment's
  budget; recorded for the roadmap.
- **Widen the direct-column fusion beyond four.** The existing four-way fusion
  already fires on 11 of 17 direct passes (arithmetic-2m) and 13 of 20
  (memory-7m); the residue is a tail of odd counts, not a systematic miss.

## Increment 2: direct interaction coordinate emission

**Outcome: accepted candidate.** Source change on
`src/frontends/cairo/witness/interaction_source.zig`,
`src/frontends/cairo/witness/interaction_trace.zig`,
`src/frontends/cairo/conformance/recorded_interaction.zig`,
`src/frontends/cairo/proving/interaction_trace.zig`, plus one unchecked
constructor in `src/core/fields/m31.zig`. Exact proof bytes preserved on every
measured workload.

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.

### Audit

One cold predecessor profile of arithmetic-2m attributes
`Interaction trace build` = 362.083 ms as:

| Bucket | ms | Share |
| --- | ---: | ---: |
| Relation fraction construction + batch inversion + consumption | 278.533 | 76.9% |
| QM31 → four-coordinate lowering | 40.665 | 11.2% |
| Memory multiplicity collection | 16.008 | 4.4% |
| Fixed-table multiplicity collection | 11.141 | 3.1% |
| Source construction, topology compile, allocation | 15.736 | 4.3% |

`add_opcode_small` alone is 143.572 ms of the total; `range_check_20` 36.308,
`memory_address_to_id` 23.567, `range_check_9_9` 21.590.

Two redundant materializations were found between component emission and the
four `SecureColumnByCoords` coordinate columns.

1. **Per-element layout dispatch.** The predecessor `Reference.evaluateRange`
   walked row-major and called `SourceView.relationWord(kind, arg, word, row)`
   once per relation word per row. That accessor re-executes the complete
   layout dispatch every call — a `rows()` union switch, a row bound, a
   `word == 0` guard, a storage-tag switch, a kind check, overflow-checked
   index arithmetic, then two more bounds checks and a canonicality branch
   inside `LookupColumns.value` / `SparseColumns.value`. None of it depends on
   `row`. `SourceView.multiplicity` had the same shape, and the combine's
   word-0 term `-z + alpha^0 * use[3]` is a per-use constant that was rebuilt
   on every row.
2. **The interleaved secure trace.** `materializeTrace` allocated a complete
   `column_count × row_count` QM31 trace, and
   `proving/interaction_trace.zig` then ran `lowerCoordinates` over it — a
   second complete pass that reads every QM31 and writes
   `value.toM31Array()[coordinate]` into four freshly allocated M31 planes.
   Every committed value was written twice with one read in between, purely
   because the intermediate existed. That is the 40.665 ms bucket.

### Mechanism as implemented

`SourceView.resolveWord` and `SourceView.resolveMultiplicity`
(`src/frontends/cairo/witness/interaction_source.zig:288`, `:333`) are hoisted
forms of `relationWord` and `multiplicity`. They perform the layout dispatch,
index arithmetic and bounds validation once per use and return a `WordAccess` /
`MultiplicityAccess` whose common arm is a bare `[*]const u32` over the
borrowed column. The element accessors remain for `evaluateRow` and the fixture
oracles, and a new test walks seven source layouts × every word × every row
asserting the resolved reader equals the element accessor.

`Reference.init` (`src/frontends/cairo/witness/interaction_trace.zig:156`) now
builds a plan — `terms`, `uses`, `column_plans` — once per component per
worker. `combineUse` (`:414`) folds one use across a whole row run, four rows
per iteration, because the accumulator is a serial `add` chain and the loop is
latency-bound. Canonicality of dense words is validated with a running
lane-wise `@max` over the run rather than a branch per element, which is why
`M31.fromU32Unchecked` was added alongside the existing `CM31`/`QM31` unchecked
constructors.

Consumption (`evaluateRangeInto`, `:326`) is tiled at 1,024 rows and
**column-major**: one running cumulative tile is folded through every relation
column in order and each finished column leaves as a contiguous run.
`CoordinateSink` splits that run directly into the four committed `[]M31`
planes. Only the last interaction column is still staged as QM31, because its
committed values are `scanLastColumnInPlace`'s circle-order rewrite of the row
totals and that scan needs the claimed sum. `lowerCoordinates` is deleted from
the prover path; `SecureSink` keeps the column-major QM31 form for conformance
so both sinks share one evaluator and cannot drift.

`allocateCoordinateColumns` leaves the planes uninitialized: the straight-line
writer provably covers every destination row, the same predicate the
direct-feed change established for base-trace feeds.

Nothing dispatches on program name, path, digest, or shape. The plan is derived
from the relation descriptors and the source layout tag only.

Exactness: the only reorderings are summation order (claimed sum accumulated
per tile, not per row) and batch-inversion grouping (use-major, not row-major,
within the same batch). M31/QM31 addition is exact modular arithmetic and
therefore associative, and a field inverse is unique, so neither can move a
bit. Byte parity below confirms it.

### S1 counter evidence

Two `stwo-prof zig` harnesses wired against live repo sources. The generated
`build.zig` in each scratch dir was edited to give the Cairo module its real
`stwo_core` dependency, since the default wiring is flat and cannot express a
dep-of-a-dep. Both arms call the same live `SourceView` accessors, the same
live QM31 arithmetic and the same live `batchInverseInPlace`; the predecessor
arm reproduces only the traversal shape, which is the thing under test. Shape:
32,768 rows (the real parallel batch), 64 source columns, 16 relation columns ×
2 uses × 6 words.

| Counter | elementwise (pred) | planned (cand) | Ratio |
| --- | ---: | ---: | ---: |
| instructions/op | 13,300 | 9,226 | **1.442x fewer** |
| cycles/op | 2,368 | 2,008 | 1.179x fewer |
| ns/op (median) | 550.1 | 466.7 | 1.179x |
| IPC | 5.618 | 4.595 | — |

`stwo-prof zig compare cairo-combine-elementwise cairo-combine-planned
--iters 8 --rounds 7`: wall B/A `0.8466`, CI95 `[0.841828, 0.85203]`, verdict
"B faster"; instr B/A `0.6937`; cycles B/A `0.8504`. The CI excludes 1.0. The
instruction ratio is the mechanism confirmation — 30.6% fewer instructions for
identical output is what removing per-element dispatch predicts. Falling IPC is
expected: the same work in fewer instructions raises per-instruction memory
pressure.

At a smaller shape (8,192 rows, 24 columns, 8 relation columns) the instruction
ratio was 1.374x but wall barely moved (230.9 → 222.6 ns/op) at IPC 6.16 — the
removed instructions were absorbed by superscalar slack in a cache-resident
working set. Recorded because it is the reason the batch-scale numbers are the
ones quoted.

### Paired stage and prove measurement

A-B-B-A cold processes, `--verify` on every run, predecessor = pristine
`zig-out` tree of head `196a679f` copied whole before any edit, no sample
discarded.

| Workload | Arm | Prove ms | Interaction build ms | Materialize ms | Lower ms |
| --- | --- | ---: | ---: | ---: | ---: |
| arithmetic-2m | pred 1 | 6,919.832 | 1,017.570 | 842.358 | 81.246 |
| arithmetic-2m | cand 1 | 7,033.797 | 617.559 | 529.521 | 0.000 |
| arithmetic-2m | cand 2 | 6,883.604 | 613.264 | 491.959 | 0.000 |
| arithmetic-2m | pred 2 | 7,503.166 | 1,105.342 | 868.236 | 119.987 |
| memory-7m | pred 1 | 21,066.615 | 2,879.174 | 2,053.012 | 425.595 |
| memory-7m | cand 1 | 18,364.476 | 1,354.353 | 1,076.835 | 0.000 |
| memory-7m | cand 2 | 16,853.045 | 1,212.093 | 971.855 | 0.000 |
| memory-7m | pred 2 | 16,616.998 | 2,245.247 | 1,705.113 | 286.974 |
| all-opcodes | pred 1 | 3,226.942 | 394.481 | 302.876 | 75.160 |
| all-opcodes | cand 1 | 3,153.885 | 262.170 | 252.277 | 0.000 |
| all-opcodes | cand 2 | 3,124.522 | 285.621 | 273.861 | 0.000 |
| all-opcodes | pred 2 | 3,242.350 | 376.100 | 295.107 | 64.966 |

| Workload | Pred prove | Cand prove | Ratio | Pred build | Cand build | Ratio | Pred materialize | Cand materialize | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| arithmetic-2m | 7,211.499 | 6,958.700 | 1.036x | 1,061.456 | 615.411 | **1.725x** | 855.297 | 510.740 | 1.675x |
| memory-7m | 18,841.807 | 17,608.760 | 1.070x | 2,562.211 | 1,283.223 | **1.997x** | 1,879.062 | 1,024.345 | 1.834x |
| all-opcodes | 3,234.646 | 3,139.203 | 1.030x | 385.291 | 273.896 | **1.407x** | 298.992 | 263.069 | 1.137x |

**Host load must be read with these numbers.** The block opened at load average
10.35 and closed at 57.79: an unrelated `zig clang` build storm in another
checkout ran throughout. Absolute prove times are roughly 2.3x inflated against
increment 1's figures on the same binaries and workloads (arithmetic-2m 7.2 s
here versus 3.16 s there). A-B-B-A adjacency is the only defence applied, and
it is why only *ratios* are claimed. The stage ratios 1.73x / 2.00x / 1.41x are
far outside increment 1's measured ±12% stage-level floor; the prove ratios
1.03-1.07x are *inside* the ±3% prove-level floor and are **not** claimed as a
result — the interaction build is only about a tenth of a proof.

A repeat of the A-B-B-A block on a quiet host was scheduled behind a
load-average gate and abandoned: the interfering build never fell below load 6
inside this increment's budget (57.8 at the block's close, still 25.8 half an
hour later). No partial samples from it exist and none are reported.

An independent quiet-host pair taken during the audit, load average 4.01 to
about 3.8, agrees: arithmetic-2m `Interaction trace build` 362.083 ms
predecessor versus 204.850 ms candidate, `1.767x`, with materialization
278.533 → 168.914 (`1.649x`), lowering 40.665 → 0, and `add_opcode_small`
143.572 → 60.960 (`2.355x`).

Acceptance: stage-level improvement ≥ 1.15x on all three workloads and the S1
instruction ratio confirms the mechanism. Accepted.

### Verification

- Proof bytes byte-identical predecessor versus candidate on every workload and
  every arm: arithmetic-2m
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`,
  memory-7m
  `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`,
  all-opcodes
  `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`. All three
  equal the digests increment 1 recorded.
- Metal arithmetic-2m proof digest equals the CPU digest
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`, with
  `classification: accelerated_without_fallbacks`, 74 Metal dispatches and
  `cpu_fallbacks: 0`. The interaction build is host-shared and Metal inherits
  it cleanly.
- Pinned official Rust verifier accepted the candidate arithmetic-2m proof:
  `verified: true`, channel `blake2s`, `stwo_cairo_revision`
  `82f21252a68ec006d73e299f5bf1ce6d4db0ee78`, proof digest
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.
- `zig build test-cairo-cpu-product test-cairo-frontend -Doptimize=ReleaseFast`
  passed; product closure PASS over 326 transitive Zig sources; source
  conformance reported 5 explained legacy findings and no new violations.

### Rejected alternatives

- **Restructure the combine into a rows-SoA SIMD layout.** This was the
  original hypothesis and it is wrong. `QM31.mulM31`
  (`src/core/fields/qm31.zig:186`) is already a `mulVec4` and `QM31.add`
  (`:105`) an `addVec4`, both filling the 128-bit register with the four secure
  coordinates. A four-rows-per-vector SoA layout executes 4 × (2 multiply + 3
  fold + 2 add) NEON instructions per four rows per word — exactly the same
  count as the existing AoS form. There is no width to gain, only an AoS/SoA
  transposition to pay. The measured win is an instruction-count win from
  deleted dispatch, not a vectorization win, and the `asm` NEON share is
  unchanged by design.
- **Widen the combine unroll beyond four rows.** Four independent accumulator
  chains already cover the `mulVec4` + `addVec4` latency. Wider unrolls add
  live QM31 accumulators against the same 32 vector registers while each extra
  term also needs its alpha resident — the register-pressure regression the
  rejected 8-stream Merkle leaf change demonstrated. Not pursued; four is
  recorded as the tuned constant.
- **Defer the Mersenne reduction across four terms (`dot4Packed` style).**
  Four canonical products fit in `u64`, so one fold could serve four terms.
  Rejected: on AArch64 a `@Vector(4, u64)` multiply has no native NEON
  instruction and lowers to scalar or multi-instruction sequences, which costs
  more than the folds it saves.
- **Lower the last interaction column directly too.** Its committed values are
  the circle-order scan of the row totals, and the scan cannot start until the
  claimed sum is known, which is after every parallel range finishes. Staging
  one column instead of all of them keeps the scan a single sequential QM31
  pass; lowering it into four planes afterwards costs one column's traversal
  rather than the whole trace's.
- **Retune `batch_rows` (32,768) while restructuring.** It is the parallel work
  decomposition landed by `14975401` and changing it would confound this
  increment's treatment with a scheduling change. The consumption tile
  (1,024 rows) was introduced *inside* the batch instead, which gets the cache
  locality without touching the worker split.
- **Also fix the multiplicity collection stages.** `Fixed-table multiplicities`
  and `Memory multiplicities` are 27.1 ms of 362.083 ms on arithmetic-2m and
  live in `fixed_trace` / `cpu_memory`, not in the relation build. Below this
  increment's headroom; recorded for the roadmap.
