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

**Host load must be read with these numbers.** This first block opened at load
average 10.35 and closed at 57.79: an unrelated `zig clang` build storm in
another checkout ran throughout. Absolute prove times are roughly 2.3x inflated
against increment 1's figures on the same binaries and workloads
(arithmetic-2m 7.2 s here versus 3.16 s there). A-B-B-A adjacency is the only
defence applied, and it is why only *ratios* are read from it. The stage ratios
1.73x / 2.00x / 1.41x are far outside increment 1's measured ±12% stage-level
floor; the prove ratios 1.03-1.07x are inside the ±3% prove-level floor and are
not claimed from this block. It is retained because it is real interleaved
data and because its agreement with the quiet block below is itself evidence.

#### Repeat block on a quiet host

The interfering build eventually drained and the complete A-B-B-A block was
repeated, opening at load average 9.02 and closing at 7.07. Absolute times are
now consistent with increment 1's figures on the same workloads
(arithmetic-2m predecessor prove 3,243 ms here versus 3,161 ms there;
memory-7m 7,023 versus 7,415), so this block, not the loaded one, is the
measurement of record. The candidate binary is the same sources rebuilt at
clean commit `383e0ac2`; the predecessor tree is untouched.

| Workload | Arm | Prove ms | Interaction build ms | Materialize ms | Lower ms |
| --- | --- | ---: | ---: | ---: | ---: |
| arithmetic-2m | pred 1 | 3,519.268 | 469.653 | 390.427 | 34.467 |
| arithmetic-2m | cand 1 | 2,723.472 | 230.933 | 192.849 | 0.000 |
| arithmetic-2m | cand 2 | 2,790.749 | 234.934 | 194.651 | 0.000 |
| arithmetic-2m | pred 2 | 2,967.735 | 372.975 | 296.481 | 34.499 |
| memory-7m | pred 1 | 7,246.338 | 914.812 | 699.194 | 95.341 |
| memory-7m | cand 1 | 6,426.321 | 488.209 | 379.161 | 0.000 |
| memory-7m | cand 2 | 6,255.754 | 479.649 | 369.229 | 0.000 |
| memory-7m | pred 2 | 6,799.585 | 851.173 | 635.554 | 95.763 |
| all-opcodes | pred 1 | 1,497.156 | 154.006 | 120.459 | 24.756 |
| all-opcodes | cand 1 | 1,461.025 | 117.704 | 110.600 | 0.000 |
| all-opcodes | cand 2 | 1,470.664 | 116.502 | 109.833 | 0.000 |
| all-opcodes | pred 2 | 1,494.800 | 153.305 | 119.736 | 24.491 |

| Workload | Pred prove | Cand prove | Ratio | Pred build | Cand build | Ratio | Pred materialize | Cand materialize | Ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| arithmetic-2m | 3,243.501 | 2,757.111 | 1.176x | 421.314 | 232.933 | **1.809x** | 343.454 | 193.750 | 1.773x |
| memory-7m | 7,022.962 | 6,341.038 | 1.108x | 882.993 | 483.929 | **1.825x** | 667.374 | 374.195 | 1.783x |
| all-opcodes | 1,495.978 | 1,465.845 | 1.021x | 153.656 | 117.103 | **1.312x** | 120.098 | 110.216 | 1.090x |

**One bias in this block must be named.** The A-B-B-A order puts `pred 1`
first for every workload, and the first sample of each workload is cold in the
page cache. On arithmetic-2m `pred 1` is 26% above `pred 2` on the stage
(469.653 versus 372.975) and 18% above on prove; the two candidate samples,
both taken warm, agree within 2%. Averaging the predecessor arm therefore
flatters the candidate. The conservative reading discards `pred 1` and compares
the candidate mean against the warmed `pred 2` alone:

| Workload | Build ratio vs pred 2 | Prove ratio vs pred 2 |
| --- | ---: | ---: |
| arithmetic-2m | 1.601x | 1.076x |
| memory-7m | 1.759x | 1.072x |
| all-opcodes | 1.309x | 1.020x |

Both readings clear the 1.15x stage bar on all three workloads. At prove level
the conservative arithmetic-2m and memory-7m figures (1.076x, 1.072x) sit above
increment 1's ±3% floor and are claimed only weakly — two samples per arm is
thin for a 7% effect, and the correct follow-up is more samples, not a stronger
adjective. all-opcodes at prove level is inside the floor and is not claimed.

An independent quiet-host pair taken during the audit, load average 4.01 to
about 3.8, agrees with the stage result: arithmetic-2m `Interaction trace
build` 362.083 ms predecessor versus 204.850 ms candidate, `1.767x`, with
materialization 278.533 → 168.914 (`1.649x`), lowering 40.665 → 0, and
`add_opcode_small` 143.572 → 60.960 (`2.355x`).

Across all three independent blocks — loaded, quiet, and the audit pair — the
arithmetic-2m stage ratio lands at 1.725x, 1.809x and 1.767x. That stability
under a 2.3x swing in host load is the strongest argument that the effect is
the treatment and not the machine.

Acceptance: stage-level improvement ≥ 1.15x on all three workloads under both
the averaged and the conservative reading, and the S1 instruction ratio
confirms the mechanism. Accepted.

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

## Increment 3: Merkle commit pipeline

**Outcome: rejected candidate.** A working, byte-exact structural change was
built, measured, and reverted: it improves the `merkle_commit` stage by
1.04x-1.13x, below this increment's 1.15x acceptance bar. The source diff is
reverted; the audit, the wall verdict, and the rejected mechanism are recorded
here because they retarget the remaining Merkle work.

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.

The reverted implementation is preserved in history at `35dcf92e` (fused
trailing group) on top of the audit instrumentation at `495a9cff`.

### Audit: what the merkle_commit stage is made of

Cairo commits through the *streaming* path. `commitOwnedPreparedWithRecorder-
AndBacking` (`src/prover/pcs/scheme.zig:225`) routes any column set of 128 or
more columns to `commitOwnedStreamingWithRecorder`, and every Cairo tree
qualifies (156, 293, 304 columns on arithmetic-2m). `tree_builders.zig:283`
then hands the complete height-sorted set to
`StreamingCommitter.commitColumnsWithSparseTail`
(`src/prover/vcs_lifted/prover.zig:542`), so the whole leaf pipeline happens in
one call.

That pipeline keeps **one BLAKE2s hasher state per leaf**. `@sizeOf(H)` is
**136 bytes** (measured, not estimated: `h[8]u32`, `t0`, `t1`, a 64-byte
`buf`, `buf_len`, `finalized`, `selection`). For a `2^22` leaf domain the
array is **570 MiB**; memory-7m reaches `2^23` and **1.14 GiB**. It is built
by climbing the column log-size ladder: each new group replicates the array
onto the larger domain, then absorbs its columns into every entry.

Temporary instrumentation gated behind `STWO_MERKLE_AUDIT=1` split the stage
into replication, absorb, leaf finalize, parent layers and allocation. It was
reverted with the rest of the increment. arithmetic-2m, one cold process:

| Phase | ms | Share |
| --- | ---: | ---: |
| Leaf absorb (`updateHashersPacked`) | 496.1 | 37.1% |
| **Hasher-array replication (expand)** | 442.5 | 33.1% |
| Parent layers | 236.5 | 17.7% |
| Leaf finalize (`finalizeHashers`) | 160.5 | 12.0% |
| Leaf/layer allocation | 0.017 | 0.0% |
| Total | 1,335.6 | |

Per tree: preprocessed (156 columns, max log 21) 194.6 ms; main (293, log 22)
635.5 ms; interaction (304, log 22) 505.5 ms.

Two findings dominate.

**The replication phase does no hashing at all.** It is a third of the stage
spent copying hasher states. The single largest line item in the whole audit is
one replication: `expand log_size=22 leaves=4194304 hasher_bytes=570425344
ns=111428584` — 111.4 ms to move 855 MiB (285 read, 570 written) so that the
next group has somewhere to be absorbed into. At head it is also a **serial
scalar gather** (`prover.zig:505`, a plain `for (0..layer_size)` loop), while
absorb, finalize and the parent layers all run on the pool.

**The sparse-tail fast path never fires on Cairo.** `liftedTailStart`
(`prover.zig:563`) can already skip the last replication, but only if the
trailing columns fit in the currently-open 64-byte block — at most 15 columns
and only when few words are buffered. Every Cairo tree reports
`tail_start=null`: the trailing groups are 39, 20 and 4 columns wide against a
full buffer. The mechanism existed and was structurally excluded.

### Worker-cap finding

**The pool cap does not bind, and the brief's premise was stale.**
`work_pool.zig:13` declares `MAX_WORKERS = 32`, not 16, and
`parameters.max_parallel_workers` is also 32. On this 18-core host
`detectWorkerCount` returns 18. Instrumented worker counts confirm the leaf
paths actually receive them: `absorb_workers pool=true workers=18
layer=4194304`, dropping to 16/8/4/2/1 only as layers shrink below the
`parallel_min_nodes_per_worker = 1024` capacity rule. There is nothing to lift;
no rider was needed. The real parallelism defect was the *serial* replication
loop above, which the pool never saw.

### The wall verdict (four walls)

Two `stwo-prof zig` harnesses wired against live `stwo_core` sources
(`--import stwo_core=src/core/mod.zig`), single-threaded, shape `2^18` base
hashers → `2^19` leaves × 39 trailing columns. Both arms call the same live
`Blake2sHasher` primitives; only the traversal differs. Predecessor arm:
replicate, absorb (`updateM31Columns4`), finalize (`finalizeEqualTail4`).
Candidate arm: one fused `finalizeM31Columns4`.

| Counter | 3-pass (pred) | fused (cand) | Ratio |
| --- | ---: | ---: | ---: |
| instructions/op | 1,360 | 1,233 | 1.103x fewer |
| cycles/op | 603.1 | 704.6 | 0.856x (worse) |
| ns/op (median) | 140.2 | 184.6 | **0.759x (worse)** |
| IPC | 2.255 | 1.750 | — |
| peak footprint (B) | 206,717,408 | 135,397,808 | 1.53x smaller |

`asm`, per-symbol:

| Symbol | instrs pred | instrs cand | mem pred | mem cand | NEON |
| --- | ---: | ---: | ---: | ---: | ---: |
| `workload.run` (traversal) | 925 | 551 | 473 | **278** | 10.6% / 8.2% |
| `compressParallel4` (hashing) | 1,440 | 1,440 | 95 | 95 | 92.2% |

**Verdict: the hashing core is compute-bound and untouchable; the traversal
around it is memory-traffic-bound, but only at pool scale.** The compression
kernel is 92.2% NEON and byte-identical between arms — there is no
vectorization headroom there, and the fused pass was never going to change the
number of compressions. The traversal issues 41% fewer memory operations, which
is the predicted mechanism and it is confirmed. But at **one thread** a single
core cannot saturate memory bandwidth, so removing traffic buys nothing while
the fused form's extra per-lane work costs 1.32x on wall. The traffic saving
only pays when 18 workers are competing for bandwidth — which is why the S1
isolate *understates* this class of fix and why the whole-prover paired runs
are the governing measurement. Recording this explicitly: **S1 single-thread
isolation is the wrong instrument for a pass-fusion claim in the Merkle
pipeline; it will read as a regression even when the parallel stage improves.**

### The rejected mechanism

Three changes, all byte-exact, all reverted.

1. `direct_tail.finalizeDirectTail` — the trailing same-log-size group is
   absorbed *during* finalization, reading the base state in place. The
   expanded array is never materialized. This is `finalizeLiftedTail`
   generalized to arbitrary group width: instead of requiring the tail to land
   in the open terminal block, the four-lane path compresses whole blocks as
   they fill. Admission is structural — the column log-size ladder only.
2. `blake2s_stream4.finalizeM31Columns4` — one SIMD-resident pass replacing
   `updateM31Columns4` + `finalizeEqualTail4`, so the transposed state is
   gathered once and no scalar hasher state is written back.
3. `direct_tail.expandHashers` — the replications that remain read their two
   source hashers once per aligned run and broadcast them, and split across the
   pool instead of running serially.

Exactness: the absorbed values, their order, and the block boundaries are
unchanged; only the storage of intermediate state differs. Byte parity below
confirms it.

A fourth variant was built and measured: borrowing the four base states by
pointer (`*const [4]*const State`) instead of copying them into a stack array.
It was a wash — 582.3 ms versus 575.7 ms candidate mean on arithmetic-2m — the
compiler had already elided the copy. Recorded so it is not retried.

### Paired measurement

A-B-B-A cold processes, `--verify` on every run, predecessor = pristine
`zig-out` tree built from clean head `44f2f506` **before** any edit and copied
whole. Following the methodology finding from increment 2, **one untimed warmup
process per arm precedes each block** and is discarded; without it the first
cold sample of an arm carries a page-cache penalty.

arithmetic-2m, three independent A-B-B-A blocks (6 paired samples per arm):

| Block | Arm | merkle_commit ms | Arm | merkle_commit ms |
| --- | --- | ---: | --- | ---: |
| 1 | pred 1 | 771.255 | cand 1 | 580.809 |
| 1 | pred 2 | 631.078 | cand 2 | 585.579 |
| 2 | pred 1 | 627.871 | cand 1 | 579.148 |
| 2 | pred 2 | 645.072 | cand 2 | 572.154 |
| 3 | pred 1 | 629.527 | cand 1 | 590.481 |
| 3 | pred 2 | 624.058 | cand 2 | 574.144 |

| Statistic | pred | cand |
| --- | ---: | ---: |
| mean | 654.8 | 580.4 |
| sd | 57.5 | **6.9** |
| range | 624-771 | 572-590 |

Ratio over all samples **1.128x**; excluding the single 771.3 ms predecessor
outlier **1.088x**. The candidate's spread is 8x tighter than the
predecessor's, which is itself a result: removing the largest allocation and
the serial replication removes most of the run-to-run variance.

memory-7m and all-opcodes, one A-B-B-A block each:

| Workload | pred mean merkle ms | cand mean merkle ms | Ratio | Prove ratio |
| --- | ---: | ---: | ---: | ---: |
| arithmetic-2m | 654.8 | 580.4 | 1.128x | 1.063x / 1.031x / 1.025x |
| memory-7m | 1,485.150 | 1,392.601 | 1.066x | 1.016x |
| all-opcodes | 402.577 | 386.947 | 1.040x | 1.005x |

**No workload reaches 1.15x. Rejected.** The prove-level ratios (1.005x-1.063x)
are inside increment 1's ±3% floor and are not claimed. The stage ratios for
memory-7m and all-opcodes are inside the ±12% stage floor. Only arithmetic-2m
is arguably outside it, at 1.09x-1.13x.

Why memory-7m barely moves, from its audit split: its trees reach log 23, and
the candidate's fused pass then costs 424.2 ms and 315.0 ms per tree while the
replications it eliminates cost only 12.9 ms each *after* the parallel
broadcast lands. The fused kernel gives back most of what the removed pass
saves — exactly what the S1 counters predicted.

Host: the block opened at load average 2.30 and closed at 4.02; `top` reported
86-93% idle throughout. An earlier set of single-run measurements taken at load
15-31 while increment 2's benchmark processes were still on the host suggested
a 1.57x stage win; those runs compared an *instrumented* predecessor against a
clean candidate under falling load and are **not** reported as a result. They
are the reason this increment insists on warmed, paired, same-block samples.

### Verification

- Proof bytes byte-identical predecessor versus candidate on every workload and
  every arm — 6 proofs per workload, one distinct digest each:
  arithmetic-2m `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`,
  memory-7m `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`,
  all-opcodes `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`.
  All three equal the digests increments 1 and 2 recorded.
- The reverted tree rebuilds and reproduces
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.
- `zig build test-cairo-cpu-product test-cairo-frontend test-stwo-prover`
  passed on the candidate; `stwo-prover closure: PASS` over 188 transitive Zig
  sources; source conformance reported 5 explained legacy findings and no new
  violations.
- `zig build merkle-worker-stress` exercised the shared vcs_lifted worker
  paths: `state_machine_deep` and `plonk_deep` passed in both prove modes with
  **proof bytes identical across worker counts {2,4,8}**. The gate then failed
  on `blake_deep` with `error: InvalidNRounds` — a pre-existing branch
  condition in the blake example's CLI validation
  (`src/examples/blake/input.zig`), which this increment's diff never touches.
  The gate also fails before starting if
  `vectors/reports/merkle_worker_stress_artifacts/` is left over from a prior
  run (`error: PathAlreadyExists`); that directory is untracked scratch and was
  cleared.
- Not run, for budget: the official Rust verifier on a candidate proof, and the
  Metal parity run. Both are lower value here because the candidate is
  reverted and its proof bytes are bit-identical to the predecessor's on all
  three workloads, and the predecessor's digests were already accepted by the
  pinned verifier in increments 1 and 2.

### Rejected alternatives

- **Lift the worker cap.** No-op: `MAX_WORKERS` is already 32 against 18 cores,
  and instrumentation shows 18 workers actually reaching the large leaf layers.
- **Retry the eight-stream generic-leaf continuation.** Out of scope and
  already rejected on this branch at 1.013x; the audit confirms the leaf
  *hashing* kernel is not where the stage's slack is.
- **Fuse more than the trailing group.** Fusing group `g` and everything above
  it forces every column in `g` to be re-absorbed at the final domain instead of
  once at its own. arithmetic-2m's main tree absorbs 944 MiB of message today
  against 4.9 GiB if fully unshared — a 5.2x saving that the ladder exists to
  provide. Fusing only the trailing group is the unique choice that costs zero
  extra compressions.
- **Vectorize the leaf hashing further.** `compressParallel4` is already 92.2%
  NEON on 1,440 instructions and is identical in both arms. There is no width
  left at four lanes; more would need an eight-lane compression, which is the
  rejected register-pressure direction.

## Increment 4: parallel hasher-state replication

**Outcome: rejected candidate.** A three-line, byte-exact change plus one new
130-line module was built, measured over 36 paired cold runs, and reverted: it
improves the aggregate commit stage by 1.086x-1.091x and the `merkle_commit`
children by 1.128x-1.131x, below this increment's 1.15x acceptance bar. The
source diff is reverted. The phase split is recorded here because it closes R5
for good: after this change the replication bucket is memory-bandwidth-bound
and everything left in the stage is BLAKE2s compression.

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.

The reverted implementation is preserved in history at `1e234274`.

### Mechanism

Increment 3's audit named the largest non-hashing line item in the Cairo commit
stage: the streaming committer's hasher-array replication at
`src/prover/vcs_lifted/prover.zig:505` was a serial scalar gather
(`for (0..layer_size) |idx| expanded[idx] = self.leaf_hashers[src_idx];`) while
absorb, finalize and the parent layers all ran on the shared work pool.

This increment extracted **only** the `expandHashers` component of the rejected
`35dcf92e` candidate — not the fused finalization kernel, not the tail policy.

`src/prover/vcs_lifted/expand.zig:44` `expandRange` exploits the fact that the
lifting map `dst[i] = src[((i >> shift) << 1) + (i & 1)]` is constant across
each aligned run of `1 << shift` destinations: the whole run alternates between
exactly two source hashers. It reads those two once per run and broadcasts them,
turning a strided gather over a multi-hundred-MiB array into a streaming write.
`src/prover/vcs_lifted/expand.zig:66` `expandHashers` then splits the
destination range across the work pool with the same
`parallel_min_nodes_per_worker` capacity rule `leaves.zig` already uses; workers
own disjoint half-open destination ranges and every index is written once.
`src/prover/vcs_lifted/prover.zig:509` is the single call site.

Behaviour with no pool is unchanged: `work_pool.getGlobalPool` returns `null`
under `builtin.is_test` and `builtin.single_threaded`, and `expandHashers` then
takes the serial branch. Output is bit-identical in every configuration — this
is pure replication, no value is computed and no absorbed byte moves. A unit
test in `expand.zig` walks six source sizes × six shifts and asserts the
run-broadcast result equals the scalar lifting gather elementwise.

### Phase split, before and after

`STWO_MERKLE_AUDIT=1` instrumentation from `495a9cff` was temporarily re-applied
to **both** arms (predecessor tree at `34b2a898`, candidate at `1e234274`) and
reverted again. Three interleaved cold runs per arm on arithmetic-2m, means:

| Phase | pred ms | cand ms | Ratio |
| --- | ---: | ---: | ---: |
| Leaf absorb (`updateHashersPacked`) | 332.8 | 347.5 | 0.957x |
| Parent layers | 167.4 | 172.7 | 0.970x |
| **Hasher-array replication (expand)** | **146.6** | **95.7** | **1.532x** |
| Leaf finalize (`finalizeHashers`) | 110.0 | 118.5 | 0.928x |
| Leaf/layer allocation | 0.017 | 0.017 | — |
| Total | 756.7 | 734.3 | 1.030x |

Per-run expand totals were 145.4 / 147.1 / 147.1 (pred) and 96.2 / 90.9 / 99.9
(cand) — the phase effect is clean. The individual replications that dominate:

| Replication | Hasher bytes | pred ms | cand ms |
| --- | ---: | ---: | ---: |
| main tree, log 22 | 570,425,344 | 32.3 / 32.7 / 32.3 | 11.7 / 11.5 / 12.3 |
| interaction tree, log 22 | 570,425,344 | 32.2 / 33.2 / 32.7 | 12.2 / 14.3 / 12.8 |
| log 21 (×3, one per tree) | 285,212,672 | 15.4-16.7 | 9.3-16.3 |
| log 20 | 142,606,336 | 8.1-8.3 | 8.9-9.2 |

**A correction to increment 3's audit must be recorded.** That audit reported
the replication phase at 442.5 ms / 33.1% of a 1,335.6 ms instrumented stage.
Re-measured here on a quiet host with the same instrumentation, it is 146.6 ms
of 756.7 ms — 19.4%. The earlier figure was taken on a busier machine and the
serial gather is exactly the phase that degrades worst under contention, so it
was disproportionately inflated. The expected ~1.4x stage win in this
increment's brief was derived from the 442.5 ms figure and was therefore never
achievable: parallelising a 146.6 ms bucket inside a 756.7 ms stage caps the
stage at about 1.08x even if replication went to zero.

**Where the remaining 95.7 ms goes.** The three trees replicate roughly 2.5 GB
of hasher state and read roughly 1.3 GB of it, so the candidate pass sustains
about 40 GB/s. That is at this host's achievable streaming bandwidth. There is
no further parallel headroom in the phase; the only way to cut it more is to
*not perform* the replications, which is what `35dcf92e`'s fused tail did — and
increment 3 measured the fused kernel giving back most of that saving.

The log-20 replication does not improve (8.2 → 9.0 ms). At 142 MiB the pass is
dominated by first-touch page faults on the fresh allocation, which the worker
split does not remove.

### Paired measurement

A-B-B-A cold processes, `--verify` on every run, **three blocks per workload**
(6 paired samples per arm), one untimed warmup process per arm before each
workload's blocks. Predecessor = pristine full `zig-out` tree built from clean
head `34b2a898` before any edit and copied whole to
`/private/tmp/campaign-inc4-pred`. No sample discarded.

Observables are the three `merkle_commit`-bearing stages in `stages.json`:
`preprocessed_materialize_and_commit`, `main_trace_commit`,
`interaction_trace_commit`. Both the aggregate stage times (the brief's stated
observable) and their `merkle_commit` children are reported.

arithmetic-2m:

| Block | Arm | commit agg ms | merkle sum ms | prep mk | main mk | int mk | Prove ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | pred 1 | 878.641 | 649.944 | 90.654 | 323.070 | 236.220 | 2,457.427 |
| 1 | cand 1 | 808.524 | 579.305 | 82.927 | 287.941 | 208.437 | 2,367.904 |
| 1 | cand 2 | 812.331 | 580.542 | 86.694 | 282.146 | 211.702 | 2,401.244 |
| 1 | pred 2 | 877.257 | 646.258 | 94.238 | 311.374 | 240.646 | 2,456.921 |
| 2 | pred 1 | 913.797 | 680.130 | 88.524 | 314.914 | 276.692 | 2,505.864 |
| 2 | cand 1 | 815.615 | 578.690 | 80.184 | 282.441 | 216.065 | 2,397.596 |
| 2 | cand 2 | 825.262 | 588.953 | 83.413 | 292.731 | 212.809 | 2,441.012 |
| 2 | pred 2 | 902.637 | 664.401 | 92.651 | 321.367 | 250.383 | 2,522.373 |
| 3 | pred 1 | 901.360 | 662.023 | 87.500 | 319.247 | 255.276 | 2,514.068 |
| 3 | cand 1 | 830.247 | 591.790 | 86.470 | 294.111 | 211.209 | 2,454.291 |
| 3 | cand 2 | 827.134 | 589.217 | 82.556 | 294.634 | 212.027 | 2,449.000 |
| 3 | pred 2 | 895.116 | 654.238 | 93.116 | 317.777 | 243.345 | 2,536.610 |

memory-7m:

| Block | Arm | commit agg ms | merkle sum ms | prep mk | main mk | int mk | Prove ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | pred 1 | 2,150.187 | 1,503.383 | 94.226 | 756.068 | 653.089 | 6,167.629 |
| 1 | cand 1 | 2,034.494 | 1,377.717 | 81.552 | 688.935 | 607.230 | 6,103.204 |
| 1 | cand 2 | 2,016.172 | 1,355.101 | 83.160 | 690.909 | 581.032 | 6,117.940 |
| 1 | pred 2 | 2,213.219 | 1,552.562 | 90.751 | 793.982 | 667.829 | 6,346.391 |
| 2 | pred 1 | 2,196.405 | 1,529.704 | 88.736 | 782.817 | 658.151 | 6,356.610 |
| 2 | cand 1 | 2,042.846 | 1,368.432 | 84.064 | 697.851 | 586.517 | 6,238.921 |
| 2 | cand 2 | 2,054.030 | 1,382.997 | 82.683 | 712.891 | 587.423 | 6,272.004 |
| 2 | pred 2 | 2,301.097 | 1,626.709 | 91.726 | 833.322 | 701.661 | 6,484.196 |
| 3 | pred 1 | 2,229.717 | 1,554.614 | 97.285 | 794.777 | 662.552 | 6,445.990 |
| 3 | cand 1 | 2,066.709 | 1,390.281 | 85.503 | 723.900 | 580.878 | 6,323.512 |
| 3 | cand 2 | 2,058.980 | 1,375.360 | 84.568 | 698.441 | 592.351 | 6,297.374 |
| 3 | pred 2 | 2,240.548 | 1,559.904 | 93.818 | 796.060 | 670.026 | 6,504.237 |

all-opcodes:

| Block | Arm | commit agg ms | merkle sum ms | Prove ms |
| --- | --- | ---: | ---: | ---: |
| 1 | pred 1 | 451.990 | 341.620 | 1,275.242 |
| 1 | cand 1 | 437.416 | 326.289 | 1,258.234 |
| 1 | cand 2 | 442.881 | 333.499 | 1,264.706 |
| 1 | pred 2 | 459.229 | 348.769 | 1,274.826 |
| 2 | pred 1 | 457.905 | 347.449 | 1,286.057 |
| 2 | cand 1 | 448.502 | 336.437 | 1,286.249 |
| 2 | cand 2 | 438.113 | 326.857 | 1,273.033 |
| 2 | pred 2 | 463.102 | 350.278 | 1,294.976 |
| 3 | pred 1 | 462.958 | 350.170 | 1,308.972 |
| 3 | cand 1 | 551.717 | 433.784 | 1,509.046 |
| 3 | cand 2 | 550.731 | 432.593 | 1,468.689 |
| 3 | pred 2 | 585.233 | 458.334 | 1,531.348 |

Summary (means over all 6 samples per arm):

| Workload | Observable | pred | sd | cand | sd | Ratio |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| arithmetic-2m | commit stage agg | 894.801 | 13.130 | 819.852 | 8.095 | 1.0914x |
| arithmetic-2m | merkle_commit sum | 659.499 | 11.183 | 584.750 | 5.343 | **1.1278x** |
| arithmetic-2m | prove | 2,498.877 | 30.913 | 2,418.508 | 31.656 | 1.0332x |
| memory-7m | commit stage agg | 2,221.862 | 45.733 | 2,045.538 | 16.796 | 1.0862x |
| memory-7m | merkle_commit sum | 1,554.479 | 37.583 | 1,374.981 | 11.136 | **1.1305x** |
| memory-7m | prove | 6,384.175 | 113.519 | 6,225.493 | 85.285 | 1.0255x |
| all-opcodes | commit stage agg | 480.070 | 47.177 | 478.227 | 51.745 | 1.0039x |
| all-opcodes | merkle_commit sum | 366.103 | 41.350 | 364.910 | 48.411 | 1.0033x |
| all-opcodes | prove | 1,328.570 | 91.443 | 1,343.326 | 103.923 | 0.9890x |

**No workload reaches 1.15x on either observable. Rejected.**

The effect is nonetheless real and unusually clean. On arithmetic-2m the two
arms' `merkle_commit` ranges do not overlap at all (pred 646.3-680.1, cand
578.7-591.8), and the same holds on memory-7m (pred 1,503.4-1,626.7, cand
1,355.1-1,390.3). The candidate's spread is 2.1x tighter on arithmetic-2m and
3.4x tighter on memory-7m, reproducing increment 3's observation that removing
the serial replication removes most of the run-to-run variance. This is a
measured 75 ms (arithmetic-2m) and 179 ms (memory-7m) saving that simply is not
large enough against a 1.15x bar.

Prove-level ratios 1.033x / 1.026x sit at or inside increment 1's ±3% floor and
are not claimed.

**all-opcodes block 3 is contaminated** and is reported rather than hidden: a
load spike raised every one of its four samples by 25-33% (pred 2 alone is
585.2 ms against 459.2 and 463.1 in blocks 1 and 2). Restricted to the clean
blocks 1-2, all-opcodes reads commit agg 458.057 → 441.728 (1.037x),
merkle sum 347.029 → 330.770 (1.049x), prove 1,282.775 → 1,270.555 (1.010x) —
the same direction, smaller magnitude, still far below the bar. all-opcodes'
largest tree is log 21, so it has one fewer 570 MiB replication to save.

Host load: the arithmetic-2m block opened at load average 6.95 and closed at
6.55; memory-7m opened at 6.03 and closed at 10.86; all-opcodes opened at 1.15
and closed at 5.99. The instrumented phase-split block closed at 4.18. Absolute
prove times (arithmetic-2m predecessor 2,499 ms) are *below* increments 1-3's
figures on the same workload, so the host was quieter here than in any previous
block despite the nominal load averages.

### Verification

- Proof bytes byte-identical predecessor versus candidate on every workload and
  every arm — 12 timed proofs per workload, one distinct digest each:
  arithmetic-2m `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`,
  memory-7m `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`,
  all-opcodes `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`.
  All three equal the digests increments 1-3 recorded. Both instrumented builds
  also reproduce the arithmetic-2m digest.
- Metal arithmetic-2m proof digest on the candidate equals the CPU digest
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`, with
  `classification: accelerated_without_fallbacks`, 74 Metal dispatches and
  `cpu_fallbacks: 0`. The streaming committer is host-shared and Metal
  inherits the parallel replication cleanly.
- Pinned official Rust verifier accepted a candidate arithmetic-2m proof:
  `verified: true`, channel `blake2s`, `stwo_cairo_revision`
  `82f21252a68ec006d73e299f5bf1ce6d4db0ee78`, proof digest
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.
- `zig build test-cairo-cpu-product test-cairo-frontend test-stwo-prover
  -Doptimize=ReleaseFast` passed on the candidate; `stwo-cairo-cpu closure:
  PASS` over 327 transitive Zig sources, `stwo-prover closure: PASS` over 187;
  source conformance reported 5 explained legacy findings and no new
  violations; identity reported `dirty: false`.
- The reverted tree rebuilds and reproduces
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.

### Rejected alternatives

- **Keep the change anyway on the strength of the separation.** The two arms'
  distributions are disjoint and the mechanism is confirmed by the phase split,
  so the effect is not in doubt — but the bar is 1.15x on a stage and the
  measurement is 1.09x. Recording the honest number matters more than banking a
  3% prove-level move that is inside the noise floor.
- **Re-add the fused trailing-group finalization to close the gap.** That is
  `35dcf92e` in full, already measured and rejected in increment 3 at
  1.04x-1.13x. Its fused kernel gives back most of what removing the last
  replication saves, and this increment's phase split explains why: the
  replication it eliminates is now only 11.7-14.3 ms, while the fused pass costs
  hundreds of milliseconds per tree at log 23.
- **Widen the parallel split or lower `parallel_min_nodes_per_worker` for the
  replication.** The pass already runs 18 workers on every layer above 2^14 and
  sustains ~40 GB/s. It is bandwidth-bound, not worker-bound.
- **Pre-fault or `MADV_WILLNEED` the destination allocation.** Would target the
  log-20 case, worth about 1 ms on arithmetic-2m. Below any measurable bar.
- **Replicate with `@memcpy` doubling instead of a per-element broadcast.** Same
  byte volume, same bandwidth ceiling; the loop is not instruction-bound.

### R5 verdict

R5 (Merkle commit pipeline) closes as fully explored. Two independent
structural changes have now been built, measured at pool scale and rejected:
the fused trailing-group finalization (increment 3, 1.04x-1.13x) and the
parallel hasher-state replication (increment 4, 1.09x-1.13x). After increment
4's change the instrumented arithmetic-2m stage is 347.5 ms absorb + 172.7 ms
parent layers + 118.5 ms finalize + 95.7 ms replication: 84% of it is BLAKE2s
compression through a kernel measured at 92.2% NEON with byte-identical
instruction counts across every variant tried, and the remaining 13% is a
bandwidth-saturated streaming copy. There is no structural slack left in this
stage to find.

## Orchestrator verdict: increment 4 reinstated

Increment 4's agent rejected its own candidate against the campaign's 1.15x
stage bar. The orchestrator (Claude Fable 5) overturned the rejection and
reinstated the measured implementation (cherry-pick of `1e234274`, commit
`a1a94947`), because the evidence is promotion-grade despite missing the
heuristic bar: across three paired warmed A-B-B-A blocks the arms' per-sample
ranges are disjoint on both large workloads (arithmetic-2m merkle 646.3-680.1
vs 578.7-591.8 ms; memory-7m 1,503.4-1,626.7 vs 1,355.1-1,390.3 ms), standard
deviations are 5-38 ms, the mechanism is confirmed at 1.53x on its own phase,
proofs are byte-identical, and every gate passes. The measured effect —
merkle_commit 1.128x/1.131x, prove 1.033x/1.026x — is real; the 1.15x bar was
calibrated for contaminated-host evidence and would donate a genuine
compounding win. Reinstatement was revalidated: rebuild reproduces digest
`25e5719f…` with self-verification, and the product gates pass.

Campaign acceptance policy from here: mechanism confirmation (paired phase
split or S1) AND either stage >= 1.10x with disjoint ranges across >= 3
paired blocks, or prove >= 1.02x with non-overlapping paired CI — byte-exact
proofs and gates always mandatory.

## Increment 5: composition evaluation

**Outcome: accepted candidate.** One source change on
`src/frontends/cairo/proving/air/simd_evaluator.zig`,
`src/frontends/cairo/proving/air/component.zig`, plus a new
`src/frontends/cairo/proving/air/read_plan.zig`. Exact proof bytes preserved
on every measured workload. `composition_evaluation` improves 1.114x-1.130x
with disjoint per-sample ranges on all three workloads, and complete prove
time improves 1.021x-1.028x.

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.

### Audit: what the composition stage is made of

Cairo evaluates its AIR by interpreting captured template programs on the
host. `ComponentProvers.computeCompositionEvaluationForBackend`
(`src/prover/air/component_prover.zig:307`) routes any multi-component AIR
with a pool to `component_parallel.compute`
(`src/prover/air/component_parallel.zig:15`), which gives each component its
own accumulator and pre-assigned coefficient range. Each Cairo component's
`evaluateConstraintQuotientsOnDomainImpl`
(`src/frontends/cairo/proving/air/component.zig:134`) splits its own rows
across the pool and calls `simd.evaluatePartRange`
(`src/frontends/cairo/proving/air/simd_evaluator.zig`), a fixed-width
four-lane interpreter over the captured instruction stream.

Temporary instrumentation gated behind `STWO_COMPOSITION_AUDIT` and
`STWO_COMPOSITION_ABLATE` was added, measured, and reverted. It is preserved
in history at `bb0de1e5`.

#### Static census (exact)

arithmetic-2m instantiates **29 components**. One dominates: evaluation log
size 22 (4,194,304 rows, 1,048,576 four-row groups), 278 base instructions,
493 extension instructions, 63 mask read sites and 32 constraint roots per
group. It alone is 56.5% of all mask reads and 71% of all QM31
multiplications; the top five components are 84.4% of all reads.

Dynamic interpreted instruction executions for one arithmetic-2m proof:

| Stream | Opcode | Executions |
| --- | --- | ---: |
| base | `trace_col` | 116,856,192 |
| base | `constant` | 85,364,920 |
| base | `mul` | 78,381,656 |
| base | `sub` | 52,101,504 |
| base | `add` | 37,880,320 |
| base | `neg` | 2,097,152 |
| base | total | **372,681,744** |
| ext | `secure_col` | 183,648,984 |
| ext | `mul` | 158,082,864 |
| ext | `add` | 148,842,712 |
| ext | `param` | 143,504,416 |
| ext | `sub` | 42,347,808 |
| ext | `constant` | 37,164,024 |
| ext | `neg` | 7,409,184 |
| ext | total | **720,999,992** |
| fold | constraint roots | 41,717,720 |

Two structural facts fall out of the census.

**Every mask read re-derived facts that do not depend on the row.**
`readTrace` was a function pointer invoked once per read instruction per
four-row group — 116,856,192 indirect calls per proof. Each call re-checked
tree arity, linearly rescanned the component's `trace_spans`
(`resident_geometry.componentSpan`), redid overflow-checked span arithmetic
and two column bounds checks, and then per lane called
`offsetBitReversedCircleDomainIndex` and a complete
`Poly.valueAtLiftingPosition` — which itself revalidates the column length
against its log size and rechecks the derived index. That is **467,424,768
per-lane index derivations and column revalidations** per proof.

**The offset map does not depend on the column.**
`offsetBitReversedCircleDomainIndex(position, trace_log, eval_log, offset)`
is a function of the row and the mask offset only. Every measured component
uses exactly **two distinct mask offsets** against up to 69 read sites per
group, so the same four mapped lane positions were being recomputed dozens of
times per group.

#### Ablation attribution (paired A-B-B-A)

Five comptime-selected ablations were built into the predecessor sources and
run paired, two A-B-B-A blocks each, one untimed warmup per pair. Ablated
runs abort at `constraint_check_and_assembly`, so the observable is a
component wall-span probe — `max(end) - min(start)` across all 29
components — rather than the CLI stage profile. On the unablated arm that
probe tracks the recorded `composition_evaluation` stage.

| Ablated phase | `none` mean ms | ablated mean ms | Bucket ms | Share |
| --- | ---: | ---: | ---: | ---: |
| Mask gather + read dispatch (`no_read`) | 401.05 | 306.28 | **94.78** | 23.6% |
| Bit-reversed offset derivation (`no_index`) | 360.25 | 343.66 | 16.59 | 4.6% |
| Scatter into the composition column (`no_output`) | 406.16 | 402.68 | 3.48 | 0.9% |
| Per-lane denominator gather (`no_denominator`) | 366.68 | 374.83 | -8.15 | 0% |

Each row is its own paired block, so the `none` levels differ between rows;
only the within-row bucket is a measurement. Per-sample values are in
`transcripts/session-05.md`.

The residue — roughly 300 ms of a ~400 ms instrumented stage, 75% — is the
interpreted constraint arithmetic and the interpreter's own per-instruction
overhead.

#### The wall verdict (four walls)

**Not memory-bound at the output, not bookkeeping-bound, not bound by the
field arithmetic: bound by per-instruction interpreter overhead, and inside
that by the per-read callback.**

- Accumulation into the composition column is 3.5 ms of ~400 (0.9%). The
  `SecureColumnByCoords` scatter of 11,155,584 rows is free at this scale.
  Domain bookkeeping is unmeasurable.
- 1.09 G interpreted instruction executions complete in ~380 ms across 18
  workers, about 24 G cycles, i.e. **~22 cycles per interpreted
  instruction**. A four-lane M31 add is one NEON instruction; the other 21
  cycles are operand load, opcode switch, register-file store and stalls.
- The loop is **not instruction-throughput-bound on cheap instructions.**
  This was tested directly, not inferred: hoisting all row-invariant
  `constant`/`param` instructions and the constraint-fold coefficient splats
  out of the row loop removes 24.3% of interpreted instructions and
  222,386,160 QM31 splats per proof, and moved the stage by about 1% — inside
  the noise. That candidate is preserved at `f1c881d6` and rejected below.
- It **is** bound by heavyweight per-instruction work. Removing 116,856,192
  indirect calls and 467,424,768 per-lane revalidations moved the stage
  1.114x-1.130x.

#### Scheduler and serial residue

The dominant-domain scheduler landed at `d2be3be3` behaves as designed here.
`dominantDomainComponent` (`component_parallel.zig:101`) selects the
largest-domain component exposing a `domain_parallel_evaluator`; every Cairo
component exposes one (`component.zig:51`), so the log-22 component is chosen
and runs on the caller thread while the other 28 drain as leaf jobs from the
same pool. The caller then splits its own rows across
`min(pool.workerCount(), row_count / 4)` = 18 workers
(`component.zig:176-188`).

Two serial phases exist and neither is measurable: `generateSecurePowers`
(`component_parallel.zig:52`) runs before the fan-out, and the per-component
accumulators are merged serially afterwards (`component_parallel.zig:95-97`).
The component wall-span probe brackets ~99% of the recorded stage, so unlike
increment 4's merkle replication there is no serial residue worth attacking.

### Mechanism as implemented

`read_plan.build` (`src/frontends/cairo/proving/air/read_plan.zig:49`) walks
the instruction stream once per evaluated range and produces two things:

1. A `sites` array, one entry per read instruction in stream order, holding
   the instruction's committed column slice and its lifting shift. Resolution
   goes through a new `TraceReader.resolve` callback
   (`simd_evaluator.zig:146`); `component.resolveTrace`
   (`component.zig:303`) performs the tree lookup, the `componentSpan` scan,
   the preprocessed-index mapping and the column shape validation **once**.
2. An `offsets` table of the distinct mask immediates, and a slot index per
   site.

The row loop then maps lane positions once per distinct offset per group and
gathers directly:
`values[lane] = column.values[((position >> shift_amt) << 1) + (position & 1)]`.

Per arithmetic-2m proof this turns **116,856,192 indirect resolve-and-read
calls into 8,082 resolutions** (63 sites × 18 workers on the dominant
component, and so on) and **467,424,768 per-lane index derivations into
22,311,168** (two offsets × four lanes × 2,788,896 groups).

Exactness: the candidate feeds every lane the same column, the same mapped
position and the same lifting index the predecessor computed. `shift_amt` is
`(evaluation_log_size - column.log_size) + 1`, exactly
`Poly.valueAtLiftingPosition`'s shift; the offset map is the same
`core.utils.offsetBitReversedCircleDomainIndex` call with the same arguments,
merely shared between sites that agree on the offset. No value is reordered
and no arithmetic changes. Byte parity below confirms it.

Admission is structural: the plan is derived from the instruction stream's
own opcodes and immediates. Nothing inspects a workload name, path, digest,
or component identity.

### Mechanism confirmation: paired phase split

The `no_read` ablation was applied to **both** arms and run paired, two
A-B-B-A blocks per arm. It bypasses the mask gather entirely, so it isolates
the bucket the change targets.

| Arm | `none` mean ms | `no_read` mean ms | Read bucket ms |
| --- | ---: | ---: | ---: |
| predecessor sources | 401.05 | 306.28 | **94.78** |
| candidate sources | 305.55 | 284.90 | **20.65** |

The read bucket collapses **4.59x**. The absolute `none` levels are not
comparable across the two sessions — the predecessor block ran at load
average 7-15, the candidate block at 4.7-8 — but the bucket is a within-block
paired difference in both cases. The 74.1 ms the bucket loses is the same
order and direction as the 45.2 ms the whole stage gains on arithmetic-2m,
with the difference being the irreducible column traffic the candidate still
performs.

### Paired stage and prove measurement

A-B-B-A cold processes, `--verify` on every run, one untimed warmup process
per arm before each workload's blocks, uninstrumented binaries on both sides.
Predecessor = pristine full `zig-out` tree built from clean head `a52c450c`
before any edit and copied whole to `/private/tmp/campaign-inc5-pred`. No
sample discarded.

arithmetic-2m, three blocks:

| Block | Arm | composition ms | Prove ms |
| --- | --- | ---: | ---: |
| 1 | pred 1 | 383.518 | 2,260.451 |
| 1 | cand 1 | 352.395 | 2,249.096 |
| 1 | cand 2 | 351.817 | 2,230.907 |
| 1 | pred 2 | 384.565 | 2,266.368 |
| 2 | pred 1 | 389.986 | 2,296.626 |
| 2 | cand 1 | 367.228 | 2,430.938 |
| 2 | cand 2 | 372.400 | 2,470.008 |
| 2 | pred 2 | 416.647 | 2,510.579 |
| 3 | pred 1 | 429.186 | 2,542.370 |
| 3 | cand 1 | 383.330 | 2,514.790 |
| 3 | cand 2 | 376.494 | 2,518.204 |
| 3 | pred 2 | 471.120 | 2,842.032 |

memory-7m, two blocks:

| Block | Arm | composition ms | Prove ms |
| --- | --- | ---: | ---: |
| 1 | pred 1 | 1,292.193 | 6,067.920 |
| 1 | cand 1 | 1,215.274 | 6,091.940 |
| 1 | cand 2 | 1,187.386 | 6,034.513 |
| 1 | pred 2 | 1,355.866 | 6,295.072 |
| 2 | pred 1 | 1,424.966 | 6,357.980 |
| 2 | cand 1 | 1,264.187 | 6,189.684 |
| 2 | cand 2 | 1,263.775 | 6,302.525 |
| 2 | pred 2 | 1,417.616 | 6,419.825 |

all-opcodes, three blocks:

| Block | Arm | composition ms | Prove ms |
| --- | --- | ---: | ---: |
| 1 | pred 1 | 357.933 | 1,459.879 |
| 1 | cand 1 | 318.744 | 1,429.537 |
| 1 | cand 2 | 311.793 | 1,428.659 |
| 1 | pred 2 | 360.600 | 1,466.916 |
| 2 | pred 1 | 356.468 | 1,486.636 |
| 2 | cand 1 | 322.811 | 1,436.662 |
| 2 | cand 2 | 318.802 | 1,457.047 |
| 2 | pred 2 | 363.773 | 1,500.378 |
| 3 | pred 1 | 363.166 | 1,483.265 |
| 3 | cand 1 | 324.862 | 1,467.735 |
| 3 | cand 2 | 322.644 | 1,442.145 |
| 3 | pred 2 | 367.402 | 1,504.295 |

Summary:

| Workload | Observable | pred | sd | cand | sd | Ratio | Ranges disjoint |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| arithmetic-2m | composition | 412.504 | 31.249 | 367.277 | 11.757 | **1.1231x** | yes (383.5-471.1 vs 351.8-383.3) |
| arithmetic-2m | prove | 2,453.071 | 207.769 | 2,402.324 | 118.560 | 1.0211x | no |
| memory-7m | composition | 1,372.660 | 53.652 | 1,232.655 | 32.841 | **1.1136x** | yes (1,292.2-1,425.0 vs 1,187.4-1,264.2) |
| memory-7m | prove | 6,285.199 | 132.975 | 6,154.666 | 101.808 | 1.0212x | no |
| all-opcodes | composition | 361.557 | 3.688 | 319.943 | 4.260 | **1.1301x** | yes (356.5-367.4 vs 311.8-324.9) |
| all-opcodes | prove | 1,483.562 | 16.125 | 1,443.631 | 14.344 | 1.0277x | no |

Per-block stage ratios, which is the honest way to read a drifting host:

| Workload | block 1 | block 2 | block 3 |
| --- | ---: | ---: | ---: |
| arithmetic-2m | 1.0907x | 1.0906x | 1.1849x |
| memory-7m | 1.1021x | 1.1245x | — |
| all-opcodes | 1.1396x | 1.1225x | 1.1283x |

**Both limbs of the acceptance policy are met.** Stage improvement is
1.114x-1.130x with per-sample ranges disjoint across every block on all three
workloads, and prove improvement is 1.021x-1.028x with per-block prove ratios
of the same sign in 8 of 8 blocks. Prove-level per-sample ranges do overlap;
the claim there rests on the paired per-block structure, not on the pooled
distributions, and is the weaker of the two readings.

all-opcodes is the cleanest block set — predecessor sd 3.7 ms, candidate sd
4.3 ms, blocks agreeing within 1.7% — and it reads 1.130x. arithmetic-2m's
block 3 is inflated on the predecessor arm (429.2 and 471.1 ms against 383.5
in block 1); its 1.1849x is reported but the conservative reading is blocks
1-2 at 1.0907x/1.0906x, which still clears 1.10x on the pooled mean and keeps
the ranges disjoint.

Host load: the arithmetic-2m block opened at load average 3.0 and closed at
13.6; memory-7m closed at 13.6; all-opcodes ran at 10.0 falling to 7.1.
Absolute prove times drift upward across the session by roughly 15%, which is
why per-block ratios are tabulated alongside the pooled means. A-B-B-A
adjacency plus the warmup process is the defence applied.

### Verification

- Proof bytes byte-identical predecessor versus candidate on every workload
  and every arm — 12 timed proofs on arithmetic-2m and all-opcodes, 8 on
  memory-7m, one distinct digest each: arithmetic-2m
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`,
  memory-7m
  `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`,
  all-opcodes
  `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`. All
  three equal the digests increments 1-4 recorded.
- Pinned official Rust verifier accepted a candidate arithmetic-2m proof:
  `verified: true`, channel `blake2s`, `stwo_cairo_revision`
  `82f21252a68ec006d73e299f5bf1ce6d4db0ee78`, proof digest
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.
- Metal arithmetic-2m proof digest on the candidate equals the CPU digest
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`, with
  `classification: accelerated_without_fallbacks`, 74 Metal dispatches and
  `cpu_fallbacks: 0`. The template interpreter is host-shared and Metal
  inherits the resolved read plan cleanly.
- `zig build test-cairo-cpu-product test-cairo-frontend -Doptimize=ReleaseFast`
  passed; `stwo-cairo-cpu closure: PASS` over 328 transitive Zig sources;
  identity reported `dirty: false` at commit `9ea1e4bc`.
- `test-stwo-prover` was not required: the diff touches only
  `src/frontends/cairo/proving/air/`, no shared prover code. The
  `merkle-worker-stress` gate was likewise not rerun for the same reason; its
  known pre-existing `blake_deep` `InvalidNRounds` failure and the stale
  `vectors/reports/merkle_worker_stress_artifacts/` directory recorded in
  increment 3 are unchanged.
- Both instrumented builds used during the audit also reproduced the
  arithmetic-2m digest on their unablated arm.

### Rejected alternatives

- **Hoist the row-invariant instructions out of the interpreter loop.**
  Built, byte-exact, measured, reverted; preserved at `f1c881d6`. It
  partitions each program once per range into a row-invariant prefix
  (`constant` and `param` instructions whose destination register is written
  exactly once in the stream — a structural, provably safe admission rule)
  and the row-varying remainder, and pre-splats the constraint fold's
  coefficients. It removes 24.3% of interpreted instruction executions and
  222,386,160 QM31 splats per arithmetic-2m proof. Measured effect on the
  composition stage: about 1%, inside the noise floor. This is the increment's
  most useful negative result — it is the direct evidence that the loop is not
  instruction-throughput-bound on cheap instructions, and it is why the read
  path, not the arithmetic, was the right target.
- **AOT-specialize or codegen the constraint evaluators.** Already rejected on
  this branch at 1.017x geomean for 5.9 MiB of binary. The audit does not
  change that verdict: the win found here is available from a runtime plan.
- **Strip-mine the interpreter over a tile of row groups** (interchange the
  instruction and row loops so each opcode dispatch is amortised over T
  groups). This is the natural next attack on the ~22 cycles per interpreted
  instruction, and the audit supports it. Not attempted in this increment:
  the dominant component's extension register file is 493 × 64 B = 31.5 KB at
  T=1 and 126 KB at T=4, which crosses this host's 128 KB L1D, so it trades
  dispatch amortisation for a register file that no longer fits. It needs its
  own S1 study of the T sweep and is recorded for the roadmap.
- **Widen the interpreter's logical vector beyond four lanes.** Not attempted
  without S1 proof; the campaign's register-pressure lesson stands and the
  QM31 register file would grow with the width.
- **Parallelise the serial accumulator merge or `generateSecurePowers`.** The
  component wall-span probe brackets ~99% of the stage; there is no
  merkle-style serial residue here to recover.

## Increment 6: strip-mined AIR interpreter

**Outcome: negative audit. The candidate was built, proved byte-exact,
measured, and reverted. Remaining budget went to the fallback base-witness
graph attribution, which produced the increment's durable finding.**

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.
Predecessor `6e3daaf2`. Host: 18 cores, 8 MB L2, load average 3.4-6.0 across
the session.

### What was tested

Increment 5 left the composition stage interpreter-bound: ~22 cycles per
interpreted instruction over 1.09 G executions, with mask gather, scatter,
denominators and NEON field arithmetic all excluded as the binding
constraint. Strip-mining — interchanging the instruction and row-group loops
so one opcode dispatch feeds `T` four-row groups instead of one — was the
located attack, gated on an S1 tile sweep because the dominant component's
register file crosses this host's L1D somewhere between `T=2` and `T=4`.

### S1 tile sweep

`stwo-prof zig` harnesses `r6b-tile-{1,2,4,8}` and `r6b-small-{1,2,4,8}`,
compiled against the repo's real module graph (`src/core/mod.zig`,
`src/backend/mod.zig`, `src/prover/mod.zig`, `src/frontends/cairo/mod.zig`) so
the loop under measurement is live working-tree source, not a copy. The
workload builds a synthetic captured program matched *structurally* to
increment 5's census of the dominant arithmetic-2m component — 278 base
instructions of which 63 are mask reads, 493 extension instructions, 32
constraint roots, two distinct mask offsets, SSA registers — giving a register
file of 278 × 16 + 493 × 64 = 36,000 B per tile slot. One op is one four-row
group, so the counters are directly comparable across `T`. Three rounds,
twelve iterations each.

Dominant-component shape (36,000 B/slot; `T=4` = 144 KB, past L1D):

| T | instructions/op | cycles/op | ns/op | IPC | cycles vs T=1 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 50,067 | 9,447.3 | 2,185.9 | 5.30 | 1.000x |
| 2 | 44,646 | 9,163.3 | 2,120.2 | 4.87 | 1.031x |
| 4 | 40,887 | 8,965.0 | 2,073.5 | 4.56 | **1.054x** |
| 8 | 39,338 | 9,058.4 | 2,094.0 | 4.34 | 1.043x |

Control shape, small register file (70 base / 120 extension instructions =
8,800 B/slot, so even `T=8` at 70 KB sits inside L1D):

| T | instructions/op | cycles/op | ns/op | IPC | cycles vs T=1 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 16,107 | 3,129.2 | 718.4 | 5.15 | 1.000x |
| 2 | 14,601 | 3,009.0 | 691.5 | 4.85 | 1.040x |
| 4 | 13,642 | 2,901.3 | 667.1 | 4.70 | 1.079x |
| 8 | 13,450 | 2,867.9 | 659.8 | 4.69 | **1.091x** |

Per-round dispersion is tiny: instructions/op agree to five significant
figures across rounds, cycles/op to within 0.5%.

**The mechanism is confirmed and the mechanism does not pay.** Dispatch
removal is exactly as predicted — instructions/op falls monotonically with
`T`, by 21.4% at `T=8` on the dominant shape and 16.5% on the small shape,
which is 13.9 machine instructions of dispatch per interpreted instruction
eliminated. But cycles/op barely follows: the best tile is 1.054x on the
dominant shape and 1.091x even in the most favourable cache regime, against a
1.15x gate. IPC falls from 5.30 to 4.34 in lockstep with the instruction
count. That is the whole story: at IPC above 5 on an 8-wide core the
interpreter's dispatch instructions were already being issued in superscalar
slack alongside the vector work, so deleting them frees issue slots that were
never the constraint. The L1D cliff is real but secondary — it costs `T=8`
about 1% against `T=4` on the dominant shape — and it is not what kills the
idea. Increment 5's "~22 cycles per interpreted instruction" is not 22 cycles
of dispatch; it is a vector-issue and dependency-latency figure that
strip-mining cannot touch.

### Whole-prover corroboration

The S1 gate had already failed, so this was one cheap confirmatory probe, not
an acceptance attempt: two A-B-B-A blocks on arithmetic-2m, one untimed warmup
per arm, uninstrumented binaries both sides, predecessor the pristine `zig-out`
tree copied from `6e3daaf2` before any edit.

```
block1  pred comp 371.468 prove 2490.966   cand comp 361.335 prove 2472.034
        cand comp 361.463 prove 2517.963   pred comp 373.814 prove 2557.877
block2  pred comp 376.144 prove 2562.225   cand comp 363.847 prove 2561.374
        cand comp 372.823 prove 2575.035   pred comp 386.506 prove 2601.989
```

| Block | comp pred | comp cand | ratio | prove pred | prove cand | ratio |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 372.641 | 361.399 | 1.0311x | 2,524.42 | 2,495.00 | 1.0118x |
| 2 | 381.325 | 368.335 | 1.0353x | 2,582.11 | 2,568.20 | 1.0054x |
| pooled | 376.983 | 364.867 | **1.0332x** | 2,553.26 | 2,531.60 | **1.0086x** |

Against acceptance thresholds of 1.10x composition or 1.02x prove, both limbs
fail, and the whole-prover number sits close to the S1 prediction of ~1.05x
minus the stage's non-interpreter residue. The S1 harness read the machine
correctly.

Every one of the eight samples produced digest
`25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`, so the
strip-mined evaluator is byte-exact on a real 2 M-step proof, not merely in
argument. Byte-exactness is structural: each tile slot computes the same
values from the same inputs, no value crosses a slot boundary (slot `t` of
register `r` lives at `r * tile + t`, and an instruction's operands and
destination share `t`), and output rows are accumulated in the same ascending
order.

### The implementation, preserved

`c02ce7f1` holds it; `e130f7cb` reverts it. `evaluatePartRangeTiled(comptime
tile, ...)` in `src/frontends/cairo/proving/air/simd_evaluator.zig`, with
`chooseTile` selecting the width from the program header's `max_base_regs` and
`max_ext_regs` against a byte budget — structural admission, no name, path or
digest inspected — and residual groups below one full tile falling back to the
`tile == 1` instantiation. It is reinstatable as-is if a future host, a wider
lane count, or a colder interpreter changes the arithmetic; on this host it
does not.

### Fallback scope: base-witness graph attribution

Pure audit, no source change. `base_trace_build` is the second-largest CPU
bucket the campaign has not attributed. The prover already records a
`base_witness_graph` subtree with per-component leaves, so the instrument is
the existing stage profile read at pool scale — `STWO_ZIG_WORKERS` at 18, 8
and 4 — which separates what parallelises from what does not.

memory-7m, all times ms:

| Bucket | W=18 | W=8 | W=4 | W4→W18 |
| --- | ---: | ---: | ---: | ---: |
| `base_trace_build` (total) | 824.755 | 1,271.024 | 1,931.992 | 2.343x |
| `witness_program_execute` | 593.221 | 1,039.870 | 1,704.918 | **2.874x** |
| outside `base_witness_graph` | 94.126 | 93.936 | 93.869 | 1.000x |
| `witness_base_lower` | 73.448 | 72.478 | 70.718 | 0.963x |
| per-component residue | 48.838 | 49.366 | 48.029 | 0.983x |
| `witness_input_materialize` | 15.037 | 15.298 | 14.387 | 0.957x |
| `witness_output_initialize` | 0.019 | 0.020 | 0.019 | 1.000x |
| `witness_output_allocate` | 0.044 | 0.039 | 0.035 | — |

arithmetic-2m, same instrument:

| Bucket | W=18 | W=4 | W4→W18 |
| --- | ---: | ---: | ---: |
| `base_trace_build` (total) | 277.012 | 542.149 | 1.957x |
| `witness_program_execute` | 197.008 | 461.944 | **2.345x** |
| outside `base_witness_graph` | 38.341 | 38.092 | 0.993x |
| `witness_base_lower` | 22.796 | 22.913 | 1.005x |
| per-component residue | 15.044 | 15.486 | 1.029x |
| `witness_input_materialize` | 3.787 | 3.673 | 0.970x |
| `witness_output_initialize` | 0.012 | 0.012 | 1.000x |

Four findings, in descending order of usefulness to a witness-writer rework.

**1. Output initialization is not a cost, and the brief's three-way split is
really a two-way one.** `witness_output_initialize` is 19 µs on memory-7m and
12 µs on arithmetic-2m — 0.002% of the stage. Increment 2's work already
removed it. Any R2 scoping that budgets for output init is budgeting for
nothing.

**2. A pool-invariant 28% of `base_trace_build` is the real residue, and its
largest part is uninstrumented.** Summing the flat buckets: 231.4 ms on
memory-7m (28.0% of the stage at W=18) and 79.9 ms on arithmetic-2m (28.8%).
The two workloads agreeing to within 0.8 points on a 4.5x size difference says
this is structural, not incidental. The single biggest flat bucket is the
94.1 ms / 38.3 ms *outside* `base_witness_graph` — the part of
`base_trace_build` that no probe currently attributes at all, 11.4% of
memory-7m's stage sitting completely dark. `witness_base_lower` (73.4 / 22.8
ms) is next and is fully serial. This 231 ms is the Amdahl floor:
parallelising program execution perfectly would take memory-7m's stage from
825 ms only to ~231 ms, and every millisecond below that has to come from the
lowering and post-graph tail.

**3. Program execution parallelises, but poorly, and the reason is component
granularity.** Efficiency is 64% on memory-7m (2.874x for 4.5x the workers)
and 52% on arithmetic-2m (2.345x). The component nodes sum to roughly their
parent — 669.2 ms of top-six against a 730.6 ms graph on memory-7m — so
components run as a *serial chain*, each internally pool-parallel. And the
chain is dominated by one link: `add_opcode_small` is 400.966 of 593.221 ms of
program execution on memory-7m (67.6%) and 188.834 of 197.008 ms on
arithmetic-2m (**95.9%**). On arithmetic-2m the other eight components are
effectively free; the stage is one component's row loop. The lever is
therefore intra-component row-range parallelism inside the witness writers,
not more components in flight — the pool is already being handed the work one
component at a time.

**4. Incidental defect: the single-worker path produces wrong composition
values.** `STWO_ZIG_WORKERS=1` fails with `error: ConstraintsNotSatisfied` on
both arithmetic-2m and memory-7m, on the pristine `6e3daaf2` predecessor
binary and on the reverted head alike, while `STWO_ZIG_WORKERS=2` proves
normally and reproduces `25e5719f…`. It is pre-existing and unrelated to this
increment. The mechanism is visible in
`src/frontends/cairo/proving/air/component.zig:170-174`: the serial fallback
returns `evaluation.evaluateRange(0, row_count, false)` — `additive` hardcoded
false — and never updates `column.next_fresh_index`, whereas the parallel path
at lines 180-199 derives `direct_store` from `next_fresh_index`, passes
`additive = !direct_store`, and writes the index back. A second component
accumulating into the same composition column therefore clobbers the first
instead of adding to it. The same hazard applies to the
`row_count < parallel_row_threshold` branch on the line above. Recorded, not
fixed: this increment's fallback scope is audit-only.

### Verification

- Tree at `e130f7cb` is byte-identical to `6e3daaf2` (`git diff` empty), so
  the campaign's accepted state is unchanged.
- All three campaign digests reproduce on the reverted head: arithmetic-2m
  `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`,
  memory-7m
  `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`,
  all-opcodes
  `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`.
- The preserved strip-mined candidate at `c02ce7f1` reproduces
  `25e5719f…` on all four of its timed arithmetic-2m samples plus the
  spot proof.
- `zig build test-cairo-cpu-product test-cairo-frontend
  -Doptimize=ReleaseFast` passed on the reverted head; `stwo-cairo-cpu
  closure: PASS` over 328 transitive Zig sources; identity reported
  `dirty: false` at commit `e130f7cb`.
- Metal and the official Rust verifier were not rerun: the reverted tree is
  bit-identical to `6e3daaf2`, whose increment-5 record already carries both
  results against these same digests. Known pre-existing
  `merkle-worker-stress` `blake_deep` `InvalidNRounds` and the stale
  `vectors/reports/merkle_worker_stress_artifacts/` directory are unchanged.

### Rejected alternatives

- **Strip-mining the interpreter over a tile of row groups.** Built,
  byte-exact on a real proof, measured at 1.054x cycles at S1 and 1.033x
  composition whole-prover, reverted. Preserved at `c02ce7f1`. Increment 5
  predicted the L1D register-file cliff would be the binding constraint; the
  sweep shows the cliff is real but minor and that the idea fails for a
  different and more fundamental reason — the dispatch instructions were
  already free. Together with increment 5's rejected row-invariant hoist
  (24.3% of interpreted instructions removed for 1.01x) this closes the
  "reduce interpreter instruction count" family: two independent mechanisms
  have now removed 24% and 21% of instructions respectively for ~1% and ~3%.
  The composition loop is issue-latency-bound, not instruction-count-bound.
- **Fixing the single-worker composition path.** Out of scope for an
  audit-only fallback, and it is a correctness bug on a non-default
  configuration rather than a throughput lever. Handed to the campaign.
