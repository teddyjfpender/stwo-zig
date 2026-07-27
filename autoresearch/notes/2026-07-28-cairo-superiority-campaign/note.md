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
