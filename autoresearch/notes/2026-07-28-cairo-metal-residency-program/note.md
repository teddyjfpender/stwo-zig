# Cairo Metal residency program (campaign 3)

## Phase 0: baseline and design

Survey, baseline and design increment. **No product source was changed.**
Successor to `2026-07-28-cairo-superiority-campaign` (campaign 1) and
`2026-07-28-cairo-data-movement-campaign` (campaign 2), whose closing
assessment named this program as the only remaining path to `>=1.6x`
proving-speed superiority over the pinned Rust `stwo-cairo` prover.

Implementation model: Claude Opus 4.5. Orchestration: Claude Fable 5.
Baseline head: `cfad207b`, clean tree
(`identity.source.commit = cfad207b…`, `dirty = false`).
Host: Apple M5 Max, 12 performance + 6 efficiency cores.
Raw data: `/private/tmp/metal-residency-phase0/` (`raw.json`,
`attribution.json`, `projection.json`, `harness.py`, `attribute.py`,
`project.py`).

### The program, and the invariant

The Metal Cairo product today accelerates only PCS, quotient and FRI. Witness
generation, interaction construction and AIR composition run on the host. The
released capability contract says so explicitly
(`src/products/cairo_metal/capabilities.zig:23-27`):

```zig
.stage_placement = .{
    .execution = "cairo-vm-sidecar",
    .witness = "host",
    .air_constraint_evaluation = "host-simd",
    .commitment_lde_quotient_fri = "metal",
},
```

The program is to make those three stages device-resident using the
repository's existing authenticated-AOT and arena machinery. The invariant that
must survive every phase: **Zig CPU and Zig Metal proofs stay byte-identical,
Metal evidence reports zero CPU fallbacks, and the official Rust verifier
accepts.** That contract string is itself a released governance artifact, so
every phase that moves a stage must also move the declaration.

### The bar, stated as a number

Campaign 2's closing three-lane matrix at `7250e88d` (this baseline's parent)
measured **Zig Metal 1.105x slower** than pinned Rust on the seven-row
portfolio geomean, with Metal already faster than Rust on fibonacci (0.906),
arithmetic-2m (0.882) and memory-7m (0.886).

So the target is not "improve Metal by 1.6x". It is:

```
required Metal prove improvement = 1.105 x 1.6 = 1.768x geomean
```

Every projection below is judged against `1.768x`, not against `1.6x`. This
distinction decides the program's phase count, and it is the single most
important number in this note.

---

## 1. Fresh Metal stage baseline at `cfad207b`

### Method

`zig build stwo-cairo-metal -Doptimize=ReleaseFast
-Dmetal-core-aot-bundle=/private/tmp/cairo-quotient-baseline-v2/aot-bundle`
and `zig build stwo-cairo-cpu -Doptimize=ReleaseFast`. The Metal build's
`identity` was checked after building and reports
`source.commit = cfad207b621a7df1112b2857b9053c735b7e5b87`, `dirty = false`,
`core-aot-manifest-sha256 = 0bc89238…` — i.e. the bundle flag took and the
reinstall did not silently skip.

Per workload: **one untimed Metal warmup, two timed Metal runs, one timed CPU
run**, cold processes, `run-and-prove`, `--stage-profile-out`, profile
`official-live-cairo-canonical-small`.

Two deliberate protocol choices:

- **Preprocessed artifact caches forced OFF** (`STWO_CAIRO_PREPROCESSED_CACHE=0`)
  in every run. The caches landed in campaign 1 increment 9 and campaign 2
  increment 2.1. Cache-off is the lane that is like-for-like with the close2
  matrix whose Rust ratio defines the bar, so pricing residency against a
  cache-on baseline would double-count a landed lever. The cache is then
  credited explicitly and separately in §3.
- **One CPU run per workload, used as a placement oracle, not as a comparison.**
  A stage whose Metal and CPU times agree is host work; a stage that diverges is
  device-backed. This replaces an assumption with a measurement, and it
  independently reproduced the capability contract (§1.2).

Workloads. `pedersen-aggregator` is the row where host witness dominates. The
corpus `pedersen.json` still hits its pre-existing `SegmentPointerOverflow`, so
the row uses the cargo `test_data` aggregator as instructed:
`~/.cargo/git/checkouts/stwo-cairo-ef02e8e85a2fe399/82f2125/test_data/test_pedersen_aggregator/compiled.json`.

### 1.1 Evidence and hygiene

| Workload | Metal prove (2 runs, ms) | spread | CPU prove (ms) | proof SHA-256 | CPU==Metal | dispatches | fallbacks |
| --- | ---: | ---: | ---: | --- | --- | ---: | ---: |
| all-opcodes | 1,273.2 / 1,296.0 | 1.018x | 1,494.9 | `79ae76e1…` | yes | 75 | 0 |
| pedersen-aggregator | 1,434.5 / 1,472.0 | 1.026x | 1,672.9 | `99ce64aa…` | yes | 75 | 0 |
| arithmetic-2m | 1,940.4 / 1,945.6 | 1.003x | 2,826.5 | `25e5719f…` | yes | 74 | 0 |
| memory-7m | 4,498.2 / 4,727.1 | 1.051x | 6,667.6 | `e3317e55…` | yes | 79 | 0 |

All four rows: `classification = accelerated_without_fallbacks`,
`cpu_fallbacks = 0`. arithmetic-2m, memory-7m and all-opcodes reproduce the
campaign digests exactly (`25e5719f…`, `e3317e55…`, `79ae76e1…`). The
`test_data` pedersen row establishes a new digest for this program,
`99ce64aac8281e6b…`, byte-identical across CPU and Metal.

**Host load is reported, not assumed.** `loadavg` at the start of each timed
run: all-opcodes 3.37, pedersen 5.02, arithmetic-2m 6.05, memory-7m 6.38
(1-minute). The elevated figures are this harness's own cold-process churn plus
an unrelated `zig build registry-parity` from a separate worktree that was
running when the session opened and had exited before the first timed run.
Two-run spread is 1.003-1.051x, so the numbers below are pricing inputs at
roughly ±3-5%, not promotion-grade paired evidence. Every conclusion in this
note is drawn at a granularity coarser than that noise.

### 1.2 The placement oracle: which stages are actually on the device

Metal-ms / CPU-ms per stage. `~1.0` means host; well below `1.0` means the
device is doing the work.

| stage | all-opcodes | pedersen | arithmetic-2m | memory-7m | verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| `base_trace_build` | 0.919 | 1.052 | 1.020 | 0.990 | **host** |
| `interaction_trace_build` | 0.945 | 0.947 | 1.017 | 0.974 | **host** |
| `composition_evaluation` | 1.047 | 1.053 | 1.030 | 0.980 | **host** |
| `preprocessed_table_build` | 0.985 | 1.059 | 0.973 | 0.971 | **host** |
| `proof_of_work` | 1.143 | 1.038 | 1.056 | 1.207 | **host** |
| `preprocessed_materialize_and_commit` | 0.445 | 0.418 | 0.410 | 0.404 | device |
| `main_trace_commit` | 0.586 | 0.503 | 0.308 | 0.403 | device |
| `interaction_trace_commit` | 0.449 | 0.445 | 0.356 | 0.368 | device |
| `composition_interpolate_and_split` | 0.375 | 0.332 | 0.336 | 0.374 | device |
| `composition_commit` | 0.314 | 0.309 | 0.264 | 0.233 | device |
| `sampled_value_evaluation` | 0.794 | 0.668 | 0.334 | 0.246 | device |
| `fri_quotient_build_and_commit` | 1.620 | 1.080 | 0.756 | 0.813 | device, **not winning on small rows** |
| `trace_decommit` | 4.309 | 4.142 | 5.390 | 2.822 | device, **losing** (readback) |

This reproduces `capabilities.zig:23-27` from timing alone, which is the
check that the attribution table below rests on something measured.

Two findings fall out of it that are not in the contract:

1. **`fri_quotient_build_and_commit` is slower on Metal than on CPU for
   all-opcodes (1.620x) and pedersen (1.080x)** and only wins on the two large
   rows. The accepted fragmented-input quotient work (campaign of 2026-07-27)
   fixed the 5.15x inversion on arithmetic-2m; the small-row end was never
   recovered. 243.6 ms on a 1,284.6 ms all-opcodes proof is being spent on a
   device stage that the host does in 150 ms.
2. **`trace_decommit` is 2.8-5.4x slower on Metal.** It is tiny in absolute
   terms (2.2-4.5 ms) but it is the one stage in the pipeline whose cost is
   dominated by a device→host readback, and it is therefore the cheapest
   available calibration of readback cost. Any residency design that adds a
   readback per component per stage should expect to pay at this rate.

### 1.3 The stage profile (Zig Metal, mean of 2 timed runs, ms)

| stage | all-opcodes | pedersen-aggregator | arithmetic-2m | memory-7m |
| --- | ---: | ---: | ---: | ---: |
| `preprocessed_table_build` | 113.6 | 125.7 | 122.1 | 112.6 |
| `base_trace_build` | 17.5 | **624.1** | 310.3 | **938.7** |
| `air_template_instantiation` | 0.2 | 0.2 | 0.2 | 0.2 |
| `preprocessed_materialize_and_commit` | 64.8 | 62.0 | 60.4 | 59.5 |
| `main_trace_commit` | 104.8 | 61.0 | 162.4 | 534.7 |
| `interaction_trace_build` | 116.7 | 100.7 | 230.5 | 467.7 |
| `interaction_trace_commit` | 113.2 | 76.9 | 137.7 | 362.5 |
| `composition_evaluation` | **305.8** | 131.6 | **435.4** | **1,219.2** |
| `composition_interpolate_and_split` | 3.3 | 3.0 | 5.8 | 14.1 |
| `composition_commit` | 16.3 | 16.3 | 26.3 | 39.6 |
| `sampled_value_evaluation` | 26.6 | 21.9 | 34.3 | 82.6 |
| `fri_quotient_build_and_commit` | 243.6 | 159.7 | 229.3 | 514.5 |
| `proof_of_work` | 81.5 | 2.4 | 112.8 | 23.8 |
| `fri_decommit` | 2.5 | 2.2 | 3.2 | 5.6 |
| `trace_decommit` | 2.8 | 2.2 | 3.0 | 4.5 |
| `constraint_check_and_assembly` | 0.9 | 0.6 | 0.2 | 0.2 |
| **prove (backend-reported)** | **1,284.6** | **1,453.2** | **1,943.0** | **4,612.7** |

`merkle_commit` inside the two trace commits: all-opcodes 82.8 + 66.3,
pedersen 50.4 + 49.8, arithmetic-2m 70.0 + 75.1, memory-7m 252.4 + 179.3 ms.

### 1.4 The host-vs-device attribution table

Buckets are assigned from §1.2, not from names. `serialization` is
`wall - execute - prove`, i.e. proof encode, file write and process startup —
it sits **outside** the `prove` boundary the benchmark and the bar use.

| Workload | prove | host witness | host interaction | host composition | host preproc | host PoW | device | misc | unnamed residual | serialization (outside prove) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| all-opcodes | 1,284.6 | 17.5 | 116.7 | 305.9 | 113.6 | 81.5 | 577.8 | 1.1 | 70.5 | 78.9 |
| pedersen-aggregator | 1,453.2 | 624.1 | 100.7 | 131.8 | 125.7 | 2.4 | 405.2 | 0.8 | 62.5 | 74.1 |
| arithmetic-2m | 1,943.0 | 310.3 | 230.5 | 435.7 | 122.1 | 112.8 | 662.4 | 0.3 | 68.8 | 447.2 |
| memory-7m | 4,612.7 | 938.7 | 467.7 | 1,219.4 | 112.6 | 23.8 | 1,617.5 | 0.3 | 232.6 | 1,223.6 |

**The three-stage residency target:**

| Workload | witness + interaction + composition | share of prove |
| --- | ---: | ---: |
| all-opcodes | 440.1 | 34.3% |
| pedersen-aggregator | 856.7 | **58.9%** |
| arithmetic-2m | 976.5 | 50.3% |
| memory-7m | 2,625.8 | **56.9%** |

Three observations that shape the design:

- **Composition is the largest single target on three of four rows** (305.9 /
  131.8 / 435.7 / 1,219.4 ms) and it is the one whose cost campaign 2 proved is
  pure field arithmetic: increment 2.3 measured **72.3% of the composition
  loop's instructions inside `PackedQm31.mul`**, at 139 multiplies per four-row
  group. That is the workload profile a GPU is unambiguously best at, and it is
  the reason composition — not witness — is the recommended Phase 1.
- **Witness is bimodal.** 17.5 ms on all-opcodes and 624.1 / 938.7 ms on
  pedersen and memory-7m. A witness phase is worth nothing on the small-row end
  of the portfolio and is the single biggest item on the large end.
- **The unnamed residual is 70 ms on three rows and 232.6 ms on memory-7m**
  (5.0% of prove) — work inside the proof transaction that no stage span covers.
  On memory-7m that is larger than `composition_commit` + `sampled_value_evaluation`
  combined. It should be instrumented before it is designed around.

`serialization` deserves a flag even though it is out of scope: memory-7m
spends **1,223.6 ms** encoding and writing the proof, 26.5% of its own prove
time again. It does not count against the bar, which uses backend-reported
prove, but it is over a second of user-visible latency per proof and no
increment in three campaigns has looked at it.

---

## 2. Amdahl analysis: does residency clear the bar?

### 2.1 The device-time estimate, derived from measurement

An Amdahl ceiling with the migrated stages at zero cost is not a projection, it
is an upper bound. To get an actual expectation the migrated stages need a
device-time estimate, and the only honest source for one at this commit is the
measured device speedup on stages that have **already** been migrated and are
structurally comparable — per-row, column-parallel passes over the same trace.

Measured host/device ratios on already-migrated stages (from §1.2, inverted):

| already-migrated stage | measured host/device |
| --- | ---: |
| `main_trace_commit` | 2.36x |
| `interaction_trace_commit` | 2.50x |
| `preprocessed_materialize_and_commit` | 2.39x |
| `fri_quotient_build_and_commit` | 1.02x (small rows lose) |

Taking the two trace commits gives **S = 2.43x** as the conservative device
estimate for a newly resident data-parallel stage. It is conservative in a
specific, statable way: those measured ratios **include** the host→device
upload of the columns being committed, which residency removes; and a Merkle
commit is hash-bound whereas composition is multiply-bound, which favours the
device further. The upper end of what this device has demonstrated on
well-shaped work on this branch is the fused raw-quotient kernel at **6.37x**
stage improvement, so `S` and `2S` bracket a defensible range rather than
guessing one point.

### 2.2 Amdahl ceilings and priced projections

Cumulative, all anchored on measured numbers. `cache` credits the two landed
preprocessed artifacts (increment 9's table artifact, measured here at 112.6-125.7 ms,
and increment 2.1's tree-digest artifact, credited at the note's measured
164 → 41.9 ms fraction of the preprocessed commit).

| Workload | prove | warm caches | residency @S | @S + caches | @2S + caches | ideal + caches |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| all-opcodes | 1,284.6 | 1,123.8 | 1,025.7 | 865.0 | 774.3 | 683.7 |
| pedersen-aggregator | 1,453.2 | 1,282.4 | 949.4 | 778.6 | 602.2 | 425.8 |
| arithmetic-2m | 1,943.0 | 1,777.0 | 1,368.7 | 1,202.6 | 1,001.6 | 800.5 |
| memory-7m | 4,612.7 | 4,456.8 | 3,068.3 | 2,912.4 | 2,371.7 | 1,831.0 |

Per-row speedups, and the four-row geomean against the `1.768x` bar:

| Lever | all-opcodes | pedersen | arithmetic-2m | memory-7m | **geomean** | vs bar `1.768x` |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| warm artifact caches only (landed) | 1.143 | 1.133 | 1.093 | 1.035 | **1.100x** | short |
| residency @ S=2.43x, caches off | 1.252 | 1.531 | 1.420 | 1.503 | **1.422x** | short |
| residency @ S=2.43x + warm caches | 1.485 | 1.867 | 1.616 | 1.584 | **1.632x** | **short by 8.3%** |
| residency @ 2S=4.86x + warm caches | 1.659 | 2.413 | 1.940 | 1.945 | **1.971x** | clears |
| residency IDEAL + warm caches | 1.879 | 3.413 | 2.427 | 2.519 | **2.502x** | clears |

### 2.3 The answer, stated plainly

**The Amdahl ceiling clears the bar, but the three phases at the conservatively
measured device speedup do not.**

- Full residency of witness, interaction and composition with the three host
  stages reduced to **zero** cost, plus warm caches, is **2.502x** — comfortably
  above `1.768x`. The program is not Amdahl-blocked.
- The same three phases at the **measured** device speedup `S = 2.43x`, caches
  off, are **1.422x**. That is not close.
- The same three phases at `S`, **with warm caches**, are **1.632x** — short of
  the bar by 8.3%.

Solving for the required device speedup on the migrated stages:

| lane | required device speedup on migrated stages |
| --- | ---: |
| caches off | **6.94x** |
| warm caches | **3.13x** |

So the program's success condition is: **the resident witness, interaction and
composition kernels must average better than 3.13x against their host
implementations, and the artifact caches must be on.** 3.13x is above the 2.43x
that the already-migrated commit stages achieve and well below the 6.37x the
fused quotient kernel achieved, so it is plausible and unproven — which is
exactly the thing Phase 1 should be designed to falsify cheaply.

Three consequences the orchestrator should sequence against:

1. **The caches are on the critical path, not a nice-to-have.** They move the
   required device speedup from 6.94x to 3.13x — a factor of 2.2 in the
   difficulty of every subsequent phase. Campaign 2 flagged "productize the
   artifact cache (pruning, ops)" as fill-in work. It is not fill-in work; it is
   a precondition. It also carries the caveat campaign 1 recorded: a cache-hit
   lane compares a warmed serving process against a cold Rust one, so the
   headline claim must state it.
2. **Three phases are probably not sufficient on their own.** At 1.632x the
   margin is negative, and the four rows measured here are the favourable end
   (they include the two rows where the witness is largest). A fourth lever must
   be held in reserve. The best-supported candidate is not more residency: it is
   **`fri_quotient_build_and_commit` on small rows** (§1.2 finding 1), where the
   device is currently 1.62x *slower* than the host on all-opcodes and is
   spending 243.6 ms of a 1,284.6 ms proof. Recovering the host's 150 ms there is
   worth ~1.08x on the weakest row in the table, and it is a bug-shaped target
   rather than a new subsystem.
3. **This geomean is over four rows, not the portfolio's seven.** fibonacci-100k,
   factorial-100k and poseidon-aggregator were not measured in this increment.
   Structurally they sit between all-opcodes and arithmetic-2m, and Metal
   already beats Rust on fibonacci, so the four-row geomean is likely a fair but
   not established proxy. The first phase that makes a promotion claim must
   re-measure all seven.

### 2.4 The residual budget after ideal residency

What is left to attack if all three stages became free (ms):

| Workload | device | host PoW | preproc (warm) | misc | unnamed residual | total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| all-opcodes | 529.6 | 81.5 | 1.0 | 1.1 | 70.5 | 683.7 |
| pedersen-aggregator | 359.0 | 2.4 | 1.0 | 0.8 | 62.5 | 425.8 |
| arithmetic-2m | 617.5 | 112.8 | 1.0 | 0.3 | 68.8 | 800.5 |
| memory-7m | 1,573.3 | 23.8 | 1.0 | 0.3 | 232.6 | 1,831.0 |

After residency the proof is **device-throughput-bound**: 77-88% of what remains
is device time. That reframes the program's second half — once the stages are
placed, the lever becomes kernel and epoch efficiency, and the phases should be
sequenced so that the device stages' own cost is measured after each move rather
than assumed constant.

---

## 3. Machinery survey

File:line references verified directly in the worktree at `cfad207b`. Where a
question was not closed inside the budget it is marked **OPEN** rather than
answered by inference.

### 3.1 The headline correction: the SN2 schedule is a test fixture, and the
### resident subsystem is not wired into the product

The brief asked what is resident "for the captured SN_PIE_2 schedule" and what
makes it SN2-only rather than live-geometry. The premise needs one correction
before the rest of the survey makes sense.

**Every `sn_pie_2_*` reference in `src/` is inside a `test` block.** Checked by
resolving the nearest enclosing declaration for each hit:

| reference | enclosing declaration |
| --- | --- |
| `src/integrations/cairo_metal/witness_aot.zig:169` | `test "witness AOT manifest covers the active base and interaction kernels exactly"` (line 166) |
| `src/integrations/cairo_metal/resident/witness/prepare.zig:562` | `test "Cairo AOT fixed-table requirements follow witness bytecode capabilities"` (line 559) |
| `src/integrations/cairo_metal/arena_binding.zig:2422` | `test "Cairo composition parts address global random coefficient powers"` (line 2419) |

The `vectors/cairo/sn_pie_2_{witness.metallib,witness_programs.bin,composition.metallib,composition.bin,arena_schedule.json.gz,multiplicity_feeds.bin}`
assets are **conformance vectors**, not a product runtime dependency. The
product's `protocol_features` already advertises `live-geometry-v1`
(`identity` output), and `src/frontends/cairo/witness/resident_geometry.zig`
exists.

**And the resident subsystem is not on the product prove path at all.**
`src/integrations/cairo_metal/arena_binding.zig` (2,502 lines) is the resident
orchestrator. Its only non-test consumers are:

- `src/bench/cairo_metal/streaming_commitment.zig:6` — a benchmark;
- `src/tools/metal_arena_plan/proof_layout.zig:6` and `main.zig:21` — the planner tool.

The actual product prove path is `src/integrations/cairo_metal/prover/transaction.zig`,
which is **71 lines** and imports neither `arena_binding` nor anything under
`resident/`. It binds `Engine = metal.PlainMetalProverEngine`
(`transaction.zig:10`) into the *generic* Cairo proving transaction
(`transaction.zig:7` → `src/frontends/cairo/proving/transaction.zig`).

So the correct statement of the current architecture is:

> The Metal Cairo product is the generic host Cairo frontend with a
> Metal-backed *prover engine*. The Metal backend plugs in at the PCS/commitment
> level only. A separate ~4,800-line resident witness/interaction/composition
> subsystem exists, is tested against the SN2 vectors, and is reachable from a
> benchmark and a planner tool — but no product proof executes it.

This reframes the program. **Phase 1 is not "write resident kernels." It is
"wire the existing resident subsystem into the product prove path on live
geometry, behind the capability contract."** That is a materially cheaper and
lower-variance first increment than the brief assumed, and it is the reason for
the Phase 1 recommendation in §5.

### 3.2 What is reusable as-is

| Component | Path | State |
| --- | --- | --- |
| resident witness graph execution | `resident/witness/execute.zig:214` `executeScheduledWitnessGraph` (565 lines total) | implemented, SN2-tested |
| resident witness input prep | `resident/witness/prepare.zig`, `inputs.zig` | implemented |
| resident interaction graph execution | `resident/interaction/execute.zig:49` `executeScheduledInteractionGraph` (395 lines) | implemented, SN2-tested |
| resident composition config | `resident/composition/config.zig` (257 lines) | implemented |
| resident arena orchestration | `arena_binding.zig` (2,502 lines) | implemented |
| trace interpolation, commitment ordering, lookup fixed tables / multiplicity feeds, transcript, relations | `resident/{trace,commitment,lookups,transcript,relations}/` | implemented |
| AIR Metal source generator | `src/tools/cairo_metal_codegen/eval_source.zig`, `eval_prepare.zig`; build step `metal-eval-source` (`build_support/benchmarks/metal.zig:143`) | implemented |
| witness Metal source generator | `src/tools/cairo_metal_codegen/witness_source.zig`; build step `metal-witness-source` (`build_support/benchmarks/metal.zig:156`) | implemented |
| arena planner | `src/frontends/cairo/staged_arena_planner.zig`; build step `metal-arena-plan` (`build_support/benchmarks/metal.zig:28`) | implemented |
| proof plan | `src/frontends/cairo/proof_plan.zig:140` `CairoProofPlan.init(allocator, components)` | **already parameterized by a component list, not by a captured asset** |
| plane width oracle | `plane_widths.zig` (campaign 2 increment 2.2's durable output) | reusable for a narrower device plane ABI |

Two facts here are load-bearing for the live-geometry question:

- `CairoProofPlan.init` takes `components: []const Component` — it is a
  constructor over a component list, not a deserializer of a pinned plan.
- `StagedArenaPlanner.derive(allocator, specs: []const BufferSpec)`
  (`staged_arena_planner.zig:147`) is parameterized by buffer specs, with
  `Inputs` (line 52) and `BufferSpec` (line 23) as plain structs.

**So the planner and the proof plan are not the SN2 blocker.** They are already
geometry-parameterized.

### 3.3 What needs generalization: the schedule is the blocker

The SN2-ness lives in exactly one place, and it is in the resident entry-point
signatures. Both take a **captured JSON schedule**:

```zig
pub fn executeScheduledWitnessGraph(
    allocator, metal, resident_arena: *arena_plan.ResidentArena,
    schedule: []const std.json.Value,          // <-- the captured SN2 schedule
    arena: arena_plan.Plan,
    proof: *const cairo_proof_plan.CairoProofPlan,
    witness_bundle, batch, recipes, interpolation, feeds,
) !WitnessExecutionTelemetry            // resident/witness/execute.zig:214-226
```

```zig
pub fn executeScheduledInteractionGraph(
    allocator, metal, resident_arena,
    schedule: []const std.json.Value,          // <-- same
    arena, proof, witness_bundle, input, batch, recipes, relations,
) !InteractionExecutionTelemetry        // resident/interaction/execute.zig:49-61
```

`schedule: []const std.json.Value` is the deserialized
`vectors/cairo/sn_pie_2_arena_schedule.json.gz`. **This is the whole of the
SN2-only-ness**: the resident executors are driven by a pinned JSON document
rather than by a schedule derived from the live claim's per-component row
counts. Both also validate cardinality against the witness bundle
(`execute.zig:227`: `if (proof.components.len != witness_bundle.entries.len) return Error.InvalidCardinality`),
so a live schedule must agree with the bundle's component set exactly.

**What live-geometry planning requires** is therefore a *schedule derivation*
step, not a planner rewrite: a function from (live claim → per-component log
row counts → `BufferSpec`s → `arena_plan.Plan` + schedule) that produces the
same shape the captured JSON carries. `resident_geometry.zig` and
`quotient_geometry.zig` under `src/frontends/cairo/witness/` are the candidate
homes and both already reference the geometry concepts; **OPEN**: whether either
already derives per-component `log_size` from a claim at runtime was not closed
inside the budget and is the first thing Phase 1 must establish.

### 3.4 The Fiat-Shamir boundary, confirmed from the code

The brief's hypothesis is correct and the code says so exactly, in
`src/frontends/cairo/proving/transaction.zig`:

| line | operation |
| ---: | --- |
| 243-249 | `Engine.commit(&scheme, allocator, base.takeColumns(), recorder, &channel)` — base trace commit |
| 250 | `Engine.flushPendingCommit(&scheme, allocator, &channel)` — **the base Merkle root is mixed into the channel** |
| 253-254 | `transcript.grindInteraction(&channel)` |
| 255-258 | `const lookup = try transcript.drawLookupElements(allocator, &channel)` — **z / alpha drawn here** |
| 267-278 | `interaction_trace.build(..., lookup.z, lookup.alpha, ...)` |
| 289-292 | `transcript.mixInteractionClaim(&channel, interaction.claimed_sums)` |
| 300-307 | `Engine.commit(interaction.takeColumns())` + flush |

**The host-visible value that must come back from the device before interaction
can begin is the base trace's Merkle root**, because the blake2s channel must
absorb it before `drawLookupElements` can produce `z` and `alpha`. This is a
32-byte readback, not a data readback.

Consequences, stated precisely because the design depends on them:

- Interaction **placement** on the device is unconstrained. Interaction
  **scheduling** is: it cannot share a command-buffer epoch with the base
  commit. Residency must therefore be structured as at least three epochs —
  (base witness + base commit) → root readback + host channel work →
  (interaction build + interaction commit) → claim mix → (composition).
- The 32-byte root readback per epoch boundary is cheap. The thing to avoid is
  *column* readback: campaign 2 proved lookup words cannot be fused with their
  interaction consumer for this same transcript reason, so a hybrid design that
  computes witness on device and interaction on host would have to download the
  lookup planes — 3,420 MB of write traffic on memory-7m per that note. **This
  is the argument that witness and interaction must go resident together or not
  at all.**
- `interaction.component_sum` is checked against `public_logup.sum` on the host
  at `transaction.zig:281-288` (`InvalidGlobalLookupSum`). A resident
  interaction must produce that QM31 sum as a readback, which is one more small
  device→host value per proof, not a plane.

### 3.5 The integration seam already exists and is the right one

`Engine` in `frontends/cairo/proving/transaction.zig` is a comptime parameter,
and `Engine.commit` / `Engine.flushPendingCommit` are **already
backend-dispatched stage hooks**. Residency does not need a new dispatch
mechanism — it needs three more hooks of the same kind:

- `Engine.buildBaseTrace` around the `base_trace_build` scope (`transaction.zig:148`);
- `Engine.buildInteraction` around `interaction_trace_build` (`transaction.zig:263-278`);
- `Engine.evaluateComposition` around `composition_evaluation`.

with the host implementation as the default, which is exactly item 4 of the
2026-07-27 four-item architecture list ("Move interaction materialization and
Cairo AIR evaluation behind explicit CPU-SIMD and Metal backend interfaces").
The CPU lane then keeps calling the host path unchanged, which is what preserves
it as the byte-parity reference.

### 3.6 Buffer / transfer inventory — **OPEN**

Not closed inside the budget. What is established:

- 74-79 `metal_dispatches` per proof across the four workloads (§1.1), stable to
  ±5 across a 4.6x range of proof sizes — so the dispatch count is
  **geometry-insensitive**, which says the current hybrid issues a roughly fixed
  schedule of large dispatches rather than per-component ones.
- `Engine.commit` receives `base.takeColumns()` / `interaction.takeColumns()`
  (`transaction.zig:246`, `303`) — i.e. **host-owned column arrays are handed to
  the backend per commit**, which is where the upload happens. Campaign 1's
  rejected "retrofit base-trace backing ownership" increment recorded the
  governing constraint directly: *"The Metal backend accepts a true no-copy host
  source only when all columns cover one contiguous arena. Cairo component
  execution produces multiple independent allocations, so Metal still had to
  pack them."*
- The measured `trace_decommit` inversion (Metal 2.8-5.4x slower than CPU, §1.2)
  is the available readback calibration.

What Phase 1 must measure: per-proof upload bytes at the two `Engine.commit`
call sites, and whether the backend uses shared/UMA or private storage with
explicit blits. The residency credit — uploads eliminated — is currently
**unpriced**, and it is the main reason the §2.1 `S = 2.43x` estimate is
conservative.


---

## 4. Program design: the phased work breakdown

Sequenced by dependency and information value, not by size. The ordering
principle: **the schedule-derivation prerequisite is shared by all three stages
and is the program's single largest unknown, so it must be paid first and on
the cheapest stage that can prove it works.**

### Risk register (shared across phases, from the measured record)

What killed prior attempts on this branch, with the citation:

| # | Risk | Evidence it is real | Mitigation |
| --- | --- | --- | --- |
| R1 | **Readback** | `trace_decommit` is 2.8-5.4x slower on Metal (§1.2). Campaign 2 closed D1 because lookup words cannot cross the Fiat-Shamir boundary without a plane-sized transfer. | No phase may download a *plane*. Only roots (32 B), claimed sums (QM31) and telemetry cross back. Witness+interaction must move together (§3.4). |
| R2 | **Small-component dispatch overhead** | `fri_quotient_build_and_commit` is 1.62x *slower* on Metal for all-opcodes (§1.2). The 2026-07-27 note's rejected unbounded-scheduling branch launched one full-domain pass per source run and cost 1,291 ms. Dispatch count is geometry-insensitive at 74-79 (§3.6), which is the shape that currently works. | Admission by structural size, as the accepted quotient fix does (byte volume + fragmentation, never a workload name). Batch small components into one dispatch. Keep a host path for components below a measured row threshold — and *measure* the threshold. |
| R3 | **Schedule capture** | The resident executors take `schedule: []const std.json.Value` (§3.3); the only schedules that exist are the SN2 vectors. | Phase 1 exists specifically to replace this with claim-derived geometry, and to fail closed (`InvalidCardinality`, `MissingBinding` already exist as errors) rather than silently fall back. |
| R4 | **Host-side representation transform survives the move** | Campaign 1's rejected base-trace ownership retrofit: Metal accepts no-copy only from one contiguous arena, and component execution produces independent allocations, so Metal packed anyway — 3,388.989 vs 3,410.897 ms, and the implementation was removed. Its recorded lesson: *"A valid successor must allocate one backend-shaped base arena before component execution."* | Residency must plan the arena **before** witness execution, which is exactly what `StagedArenaPlanner` is for. Do not retrofit ownership after allocation. |
| R5 | **Byte-parity drift** | The whole program's licence to exist. | The CPU lane stays the reference and is not touched. Every phase adds a backend hook with the host implementation as default (§3.5), so CPU behaviour is unchanged by construction. Fail-closed is already structural: campaign 2 increment 2.3 demonstrated a sabotaged evaluator yields `ConstraintsNotSatisfied`, never an accepted proof, because the verifier recomputes composition at the OODS point. |
| R6 | **Governance surface** | `capabilities.zig:23-27` is a released contract; `build.zig*`, `vectors/`, `conformance/` are protected. | Each phase's scope includes its contract edit as a first-class deliverable, reviewed with the code rather than after. |

### Phase 1 — Live-geometry schedule derivation + resident composition

**Scope.** Two things, deliberately coupled:

(a) *The prerequisite.* Derive an arena plan and execution schedule from the
live claim instead of a captured JSON document. Replace
`schedule: []const std.json.Value` in the resident entry points
(`resident/witness/execute.zig:214`, `resident/interaction/execute.zig:49`)
with a typed schedule produced by a new derivation over
`CairoProofPlan.init(allocator, components)` (`proof_plan.zig:140`) and
`StagedArenaPlanner.derive(allocator, specs)` (`staged_arena_planner.zig:147`).
Home: `src/frontends/cairo/witness/resident_geometry.zig`. The SN2 vectors
become a *regression test* of the derivation — deriving from the SN_PIE_2 claim
must reproduce the captured schedule — which converts the fixture from a
constraint into a correctness oracle at zero cost.

(b) *The cheapest stage that proves it.* Route `composition_evaluation` through
a new `Engine.evaluateComposition` hook at `transaction.zig`'s
`composition_evaluation` scope, host default, Metal implementation via
`resident/composition/config.zig` and the `metal-eval-source` generated kernels.

**Why composition first, not witness.** Four reasons, all measured:
1. It is the largest single target on three of four rows (305.9 / 131.8 / 435.7 / 1,219.4 ms, §1.4).
2. Campaign 2 increment 2.3 measured **72.3% of its instructions inside `PackedQm31.mul`** — pure data-parallel field arithmetic, the highest device-suitability work in the pipeline, and the case where beating the 3.13x requirement is most likely.
3. It sits **after** both commits in the transcript, so it has **no Fiat-Shamir scheduling constraint at all** — unlike interaction. It is the only one of the three that can be moved without also solving epoch sequencing.
4. It reads the base and interaction columns that the device **already holds** from the two commits, so it is the one stage where residency's upload saving is available immediately.

**Priced expectation.** Composition is 305.9 / 131.8 / 435.7 / 1,219.4 ms.
At the measured `S = 2.43x`: 1.163x / 1.057x / 1.152x / 1.183x per row,
**4-row geomean ≈ 1.138x**. At `2S`: geomean ≈ 1.20x. Acceptance bar should be
set on the *stage*, not on prove: composition stage ≥ 2.0x, which is
falsifiable in one A-B and is the number that decides whether the whole program
can reach 3.13x.

**Correctness strategy.** CPU lane untouched (host default). Byte-parity is
fail-closed by construction (R5). Per-component composition-part parity against
the host evaluator before any timing, then the four-row digest set from §1.1.

**Acceptance.** (i) Derivation reproduces the SN2 captured schedule exactly.
(ii) Four-row digests unchanged, `cpu_fallbacks = 0`. (iii) Official verifier
accepts. (iv) `composition_evaluation` stage ≥ 2.0x on arithmetic-2m and
memory-7m with disjoint paired intervals. (v) `capabilities.zig`
`air_constraint_evaluation` updated to `metal`.

### Phase 2 — Resident witness + interaction, together

**Scope.** `Engine.buildBaseTrace` around `transaction.zig:148` and
`Engine.buildInteraction` around `transaction.zig:263-278`, both backed by
`executeScheduledWitnessGraph` / `executeScheduledInteractionGraph` on Phase 1's
derived schedule, with the arena planned **before** witness execution (R4).
Three-epoch structure per §3.4: (base witness + base commit) → root readback →
(interaction build + interaction commit).

**Why together.** §3.4's argument: splitting them forces a plane-sized download
of the lookup words across the Fiat-Shamir boundary, which is R1 and which
campaign 2 already priced at 3,420 MB on memory-7m. This is a correctness-of-
design constraint, not a preference.

**Priced expectation.** witness + interaction is 134.2 / 724.8 / 540.8 /
1,406.4 ms. At `S = 2.43x`: 1.066x / 1.417x / 1.244x / 1.219x,
**geomean ≈ 1.229x**. Composed with Phase 1 at `S` this reaches the §2.2
`1.422x` line; with warm caches, `1.632x`.

**Risks specific to this phase.** R2 is acute here: the witness graph has 68
components of which most are tiny (all-opcodes' entire base trace is 17.5 ms
across the whole graph, §1.3). Per-component dispatch will lose. Batching is
part of the scope, not a follow-up. The multiplicity tables are the one
accumulating output and are already excluded from partial ranges
(`program.zig:351-356`, `component_executor.zig:62`) — they need device atomics
or a separate reduction, and campaign 1 increment 8 measured that 30.9M atomic
increments over a 24 MB table cost *more* than 166 MB of private-copy traffic on
the host, so the device version needs its own measurement rather than an
assumption.

**Acceptance.** Four-row digests unchanged; `cpu_fallbacks = 0`; verifier
accepts; `base_trace_build` + `interaction_trace_build` combined ≥ 2.0x on
pedersen and memory-7m; **no plane-sized device→host transfer** in the buffer
inventory; `capabilities.zig` `witness` updated to `metal`.

### Phase 3 — Epoch fusion, dispatch batching, and the cache precondition

**Scope.** Three items that §2.3 says are not optional:
(a) productize the artifact caches (pruning, ops) — worth the difference between
a 6.94x and a 3.13x device requirement, the single highest-leverage item in the
program per unit of work;
(b) fuse the resident stages into the minimum number of command-buffer epochs
the transcript permits (three), eliminating the intermediate flushes;
(c) fix `fri_quotient_build_and_commit` on small rows, where the device is
currently **1.62x slower than the host** (§1.2) — a bug-shaped target worth
~1.08x on the portfolio's weakest row.

**Priced expectation.** (a) 1.100x geomean measured directly in §2.2. (c) up to
~1.08x on all-opcodes alone. (b) unpriced — it is the lever that moves the
achieved device speedup from `S` toward `2S`, which is the difference between
`1.632x` and `1.971x`.

### Sequencing rationale and the sufficiency verdict

**Say it plainly: Phases 1 and 2 alone are not sufficient.** §2.2 measures them
at `1.422x` caches-off and `1.632x` caches-warm against a `1.768x` bar. Phase 3
is not a polish phase — it is load-bearing, and item (a) within it is a
precondition that halves the difficulty of Phases 1 and 2 rather than adding to
their result.

The Amdahl ceiling is `2.502x` (§2.2), so the program can clear the bar. The
question is entirely whether resident kernels average **> 3.13x** against their
host implementations. Phase 1 is designed so that its stage-level acceptance
criterion (composition ≥ 2.0x, expected well above on multiply-bound work)
answers that question before Phase 2's much larger implementation cost is
committed. If Phase 1 lands composition at only ~2x, the program should be
re-planned rather than continued: at 2.43x-class efficiency the three phases
plus caches top out around 1.63x, and the remaining 8% would have to come from
the device stages' own throughput, which §2.4 shows is 77-88% of the
post-residency proof.

---

## 5. Recommendation for Phase 1's exact scope

Phase 1 as specified above, with one narrowing for risk: **split it at the
derivation boundary and gate on the first half.**

- **Phase 1a** — live-geometry schedule derivation only, validated by
  reproducing the SN2 captured schedule from the SN_PIE_2 claim. No product
  behaviour change, no capability-contract edit, nothing on the prove path. This
  is pure prerequisite, it is the program's largest unknown (§3.3, R3), and it is
  independently verifiable against an existing fixture. If the derivation cannot
  reproduce the captured schedule, the program stops here having spent one small
  increment instead of three large ones.
- **Phase 1b** — `Engine.evaluateComposition` on that derived geometry, with the
  stage-level ≥ 2.0x acceptance bar that decides the program's feasibility.

The information value is concentrated in 1a and the pricing decision is
concentrated in 1b, and neither requires touching witness execution, the
multiplicity atomics, the Fiat-Shamir epoch structure, or the CPU lane.

### Open items the orchestrator should assign

1. **Buffer/transfer inventory (§3.6)** — unpriced, and it is what makes `S`
   conservative. Cheap to close and it tightens every projection in §2.
2. **Whether `resident_geometry.zig` / `quotient_geometry.zig` already derive
   per-component `log_size` from a live claim (§3.3)** — decides whether Phase 1a
   is a small or a medium increment.
3. **The unnamed residual** — 70 ms on three rows, 232.6 ms on memory-7m (5.0%
   of prove, §1.4). Larger than several stages that have had whole increments
   spent on them, and currently invisible to the stage recorder.
4. **The three unmeasured portfolio rows** (fibonacci-100k, factorial-100k,
   poseidon-aggregator) must be re-measured by the first phase making a
   promotion claim (§2.3 consequence 3).
5. **`serialization`** — 1,223.6 ms on memory-7m, outside the `prove` boundary
   and therefore outside the bar, but over a second of user-visible latency that
   no increment in three campaigns has examined.

---

## 6. Survey addendum: findings that revise §3 and §4

Two parallel read-only surveys returned after §3-§5 were drafted. They close the
items §3 marked OPEN and they **change the phase plan**. Where they contradict
§3, this section is authoritative.

### 6.1 The composition bundle is ALREADY claim-derived and already runs in the product

`src/frontends/cairo/air/template_binding.zig:14-89`:

```zig
pub fn instantiate(
    allocator, library: template_library.Library,
    geometry: *const claim_generator.OwnedClaimGeometry,   // <-- LIVE claim geometry
    target_variant: preprocessed.Variant,
    segments: adapter.BuiltinSegments,
) !composition.Bundle
```

It takes live `trace_log` from the claim (`:40-43`), selects templates by
label+log (`:44-48`), derives `evaluation_log = trace_log + blowup delta`
(`:106-116`), recomputes the denominator inverses (`:158-162`, `:211-237`),
rebinds `seq_N` preprocessed indices (`:144-157`), rebinds domain and segment
constants (`:177-188`), and assembles a bundle with fresh `total_constraints`,
`max_evaluation_log_size` and `plan_hash` (`:80-88`).

**And it is wired into the shipping product**: `application.zig:152-156` →
`transaction.zig:167-182`. It is the `air_template_instantiation` stage —
**0.2 ms in every row of §1.3**. The template inputs are properly authenticated
(sha256 per template bundle, `template_library.zig:222-257`, manifest
`vectors/cairo/official/air_template_library_v1.json`), unlike the metallib
(§6.3).

So §3.3's claim that live-geometry derivation is the program's largest unknown is
**wrong for composition**. Live composition geometry already exists, already
runs, and costs 0.2 ms.

### 6.2 The composition metallib is log-size-independent — the single most useful fact in the survey

Kernels are named `stwo_zig_eval_{semantic_hash:016x}`
(`eval_codegen.zig:47-49`), and `semanticHash`
(`src/frontends/cairo/witness/eval_program.zig:284-308`) hashes only
`base_consts`, `ext_consts`, `base_insts`, `ext_insts`, `constraint_roots`.
`setDomainLogSize` (`:258-261`) **does not touch the hash**.

**Therefore pure log-size retargeting reuses the checked-in metallib kernels
unchanged.** Only stride/segment-constant rebinding
(`replaceBaseConstant`, `eval_program.zig:265-282`, which recomputes the hash at
`:280`) mints new semantic hashes and would need a recompiled library — and a
missing kernel fails closed at `composition_prewarm.zig:50` /
`IncompleteCompositionAotPrewarm` (`app.zig:625-627`), never silently.

Coverage of the checked-in `vectors/cairo/sn_pie_2_composition.metallib`
(7.7 MB, git-tracked): **58 components, 279 parts, 1,325 constraints,
`max_evaluation_log_size = 24`**, unfused (one kernel per part). Fusion requires
a source artifact and is therefore not in the asset
(`resident/composition/config.zig:127-130`).

### 6.3 Governance findings that must be fixed inside the program, not after

1. **The composition metallib is unauthenticated by digest anywhere in-tree.**
   Its sha256 (`85db09e0…`) appears only in `autoresearch/notes/`. There is no
   provenance JSON (contrast `air_template_library_v1.provenance.json`,
   `witness_programs_v1.provenance.json`). The `metal-arena-plan` runner derives
   the metallib path by **string substitution on the `.bin` path with no
   integrity check** (`src/tools/metal_arena_plan/main.zig:4130-4144`). The only
   in-repo binding between AIR and library is by-name kernel resolution
   (`composition_prewarm.zig:46-62`), which is a *completeness* check, not an
   *integrity* check. The session product does have a content-address policy
   (`metal_prover_session/preparation.zig:64-77`,
   `--composition-metallib-sha256`) — that is the pattern to generalize.
   **This must be closed before any product path loads the metallib.** It is
   flagged for an independent security review, not just a perf review.
2. **There is no build step that produces the metallib.** It is generated offline
   in CI only (`.github/workflows/ci.yml:423-441`) and requires full Xcode —
   which this host does not have (`/Library/Developer/CommandLineTools` only, per
   the 2026-07-27 note). So the program cannot regenerate the library locally,
   and any phase requiring new semantic hashes is blocked on CI or on a
   toolchain change.
3. **`metal_dispatches` cannot see interaction work.** `telemetry.zig:6-26` has
   no relation/interaction `Event` variant, and `metalDispatchTotal()`
   (`telemetry.zig:57-72`) sums exactly 10 counters. So the measured 74-79
   provably contains **zero** interaction device work, and wiring
   `relationPrepared` in without adding an `Event` variant would leave the
   `accelerated_without_fallbacks` gate (`app.zig:52`, `telemetry.zig:271-274`)
   silently under-reporting. **Adding the counter is part of the phase scope, not
   a follow-up** — it is what makes the zero-fallback evidence meaningful.

### 6.4 The interaction kernels already exist and are already in the AOT bundle

`src/backends/metal/shaders/core/relation.metal` (224 lines) — the LogUp
machinery is named "relation" throughout, which is why §3 missed it:

| kernel | line | role |
| --- | ---: | --- |
| `stwo_zig_relation_fused` | 131 | fraction numerators/denominators + batch inversion + per-row cumulative fold |
| `stwo_zig_relation_block_scan` | 163 | 256-lane threadgroup prefix scan in circle order |
| `stwo_zig_relation_scan_blocks` | 188 | serial scan of block sums; writes the claimed sum |
| `stwo_zig_relation_scan_finalize` | 205 | adds block prefix, subtracts the `claimed_sum·rows⁻¹·(i+1)` normalization |

The batch inversion is the same algorithm as the host's — a per-row
suffix/prefix product across the column axis (`:145-160`) with **exactly one
`qm_inv` per row**. Pipelines are built **unconditionally in the shipping
runtime init** (`runtime.m:606-609`, required non-nil at `:659-660`) and the
kernels **are in the authenticated core AOT bundle**
(`shaders/manifest.zig:97-100`, `:201`, `:269`, ABI-frozen test `:473-500`).
Execution is one command buffer with all four kernels
(`runtime/prepared_auxiliary.m:184-228`), with `z` and alpha-powers bound from
**inside the resident arena** (`:199-200`), not uploaded per call.

`relationPrepared` has two call sites: the recipe (`recipes/relation.zig:164`)
and a parity test (`tests/metal/backend/commitment_test.zig:129`). The shipping
prover never reaches it.

**No prior Metal interaction A/B exists.** All 11 recorded interaction
experiments across the campaign notes are CPU-side; the two accepted ones
(`14975401`, `1dbea2d7`) left `metal_dispatches` at exactly 74. The only
structural rejection on this edge is campaign 2's D1 blocker, which forbids
moving interaction *earlier*, not moving it *onto the device*. So this lane has
no negative prior — it is unexplored, not falsified.

### 6.5 The real Fiat-Shamir barrier is CPU proof-of-work, not the root readback

§3.4's conclusion is correct in outcome but wrong in cost attribution. Three
serialization points, not one:

1. **Root (32 B)** — `lifecycle_and_tree.m:312-318`. On UMA `rootReadback == hash_arena`
   (`:173-174`), so it is a **pointer read with zero blit**. Cheap.
2. **Channel digest for PoW (40 B)** — `transcript.grindInteraction` runs
   `channel.grind(24)` **on the CPU** (`transcript.zig:41-45`;
   `interaction_pow_bits = 24` at `:12`). **There is no PoW kernel**
   (`grep 'kernel void.*grind\|pow' src/backends/metal/shaders/` → not found).
   This is the genuinely unavoidable host round trip.
3. **`z`, `alpha` (32 B)** — drawn *on-device*
   (`transcript_decommitment.m:37-52`), then read back only so the host can run
   an alpha-power **prefix product** in scalar QM31
   (`resident/transcript/operations.zig:78-117`). That is trivially kernelizable.

Also: **every transcript op is its own command buffer with a blocking wait**
(`transcript_decommitment.m:14`, `:31`, `:48`, `:66`), so `bootstrapThroughBase`
(`protocol_recipes.zig:669-671`) costs **13 sequential round trips** before a
single relation thread runs. And `CommandEpoch` has **no `encodeRelation`**
(`command_epoch.zig:127-213`; `merkle_epochs.m` has 7 encoders, none for
relation), so relation dispatches cannot currently be batched with commitment
work at all.

### 6.6 What "74 dispatches" actually means — and why this reframes R2

**A counted dispatch is one host-blocking command-buffer submission (an epoch),
not one `dispatchThreads` call.** `combined_commit.zig:182` records **one**
`metal_circle_lde_dispatch` for an epoch that encodes IFFT + rescale + RFFT
layers + leaf hashing + the entire Merkle parent chain
(`circle_commit_epoch.m:4-568`).

So the stable 74-79 across a 4.6x proof-size range (§1.1) is not evidence of
"large coarse dispatches" as §3.6 inferred — it is **74-79 blocking host↔device
round trips per proof**. And on UMA, uploads are almost entirely **zero-copy
aliases** of host allocations (`newBufferWithBytesNoCopy`,
`circle_commit_epoch.m:88-91`; `grep didModifyRange` → not found; no managed
buffers anywhere), while downloads reduce to 4×32 B roots, query hashes, and one
sampled-value block.

**This closes §3.6 with an answer that inverts its premise: the transfer *bytes*
are already negligible. The cost is serialization.** Residency's win therefore
does **not** come from eliminating uploads — it comes from eliminating
round trips. Which means:

- The §2.1 `S = 2.43x` estimate is *not* conservative for the reason stated
  there (uploads are already zero-copy, so there is no upload to eliminate). Its
  conservatism rests only on the arithmetic-intensity argument. **The §2 numbers
  should be treated as the central estimate, not a floor.**
- Conversely, **epoch fusion moves from Phase 3 polish to a primary lever**: at
  74-79 blocking submissions per proof, collapsing them is plausibly worth more
  than any single stage migration, and it is the only mechanism identified that
  could plausibly deliver the `2S` column of §2.2.

### 6.7 Revised phase plan

The corrections above change the sequencing materially. §4's phases are
superseded as follows.

| Phase | Revised scope | Why it changed |
| --- | --- | --- |
| **1** | `Engine.evaluateComposition` against the **existing** checked-in metallib, driven by the **already-live** `template_binding.instantiate` bundle. Plus the metallib integrity binding (§6.3.1) and the telemetry `Event` variant (§6.3.3). | §6.1: no schedule derivation needed. §6.2: no library regeneration needed for log-size changes. This is now a **much smaller** increment than §4 assumed — the two things §4 called prerequisites do not apply to composition. |
| **2** | `Engine.buildInteraction` against the **existing** `relation.metal` kernels, which are already in the authenticated AOT bundle. Requires arena residency for the base columns and lookup words, and the `encodeRelation` epoch encoder. | §6.4: kernels exist and are pipeline-loaded. Budget 336 ms (arithmetic-2m) / 467.7 ms (memory-7m). Promoted **ahead of** witness because no kernel authoring is required. |
| **3** | Epoch fusion + the alpha-power prefix-product kernel + a PoW kernel. Collapse the 13-round-trip transcript bootstrap and the 74-79 per-proof submissions. | §6.5/§6.6: promoted from polish to a **primary lever**. This is the mechanism for the `2S` column, i.e. the difference between 1.632x and 1.971x. |
| **4** | `Engine.buildBaseTrace` (resident witness) + live-geometry arena schedule derivation (replace `len_words` from the captured JSON, `metal_arena_plan/main.zig:2384-2385`, with claim-computed bytes). | Demoted: it is the only phase that still needs the schedule-derivation work, and the only one with no pre-existing kernels for parts of its scope. The planner itself needs **no change** — it is already row-count-agnostic (`staged_arena_planner.zig:147-170`); only the spec *sizes* are pinned. |
| **5** | Cache productization; small-row `fri_quotient_build_and_commit` (§1.2 finding 1). | Unchanged in content; the cache remains a precondition per §2.3. |

**The sufficiency verdict in §2.3 is unchanged.** The projections do not move —
only the order and cost of the work does. Phases 1+2+4 at `S` plus warm caches
remain `1.632x` against a `1.768x` bar, and Phase 3 (epoch fusion) is now the
identified mechanism for the remainder rather than an unpriced hope.

### 6.8 Revised Phase 1 recommendation (supersedes §5)

**Phase 1 = `Engine.evaluateComposition` on the existing metallib, with its
integrity binding and its telemetry counter.** The §5 split at the
"derivation boundary" is no longer needed: §6.1 shows the derivation already
exists in-product and §6.2 shows the library does not need regenerating for
log-size changes. Concretely:

1. Bind the composition metallib by content digest — generalize the session
   product's `approved_metallib` policy
   (`metal_prover_session/preparation.zig:64-77`) into the Cairo Metal product,
   and add the missing provenance JSON. **Do this first**; nothing else should
   load the library until it does.
2. Add a relation/composition `Event` variant to `telemetry.zig:6-26` and include
   it in `metalDispatchTotal()` so the zero-fallback evidence stays meaningful.
3. Add `Engine.evaluateComposition` at `transaction.zig`'s
   `composition_evaluation` scope, host default, Metal implementation via
   `resident/composition/config.zig` + `arena_binding.zig:1470-1506`. Require
   `isComplete()` (`recipes/composition.zig:152-154`) and fail closed
   (`PartialCompositionCannotContinue` already exists as the precedent at
   `metal_arena_plan/main.zig:4163-4169`).
4. Measure the stage against the ≥2.0x bar on arithmetic-2m and memory-7m —
   still the number that decides the program's feasibility.

The residual risk concentrates in one place worth naming: the captured schedule's
own metadata records `pass = false`, `vram_fit = false` and
`manifest_policy = "Fake {...}"`. Any throughput expectation inherited from SN2
resident measurements is provisional on that, which is a further argument for
pricing Phase 1 on a fresh A-B rather than on prior resident numbers.

### 6.9 The witness AOT path is in worse shape than §3.2 implied — Phase 4 demotion confirmed

The third survey closes the witness questions and every answer argues for keeping
witness last.

**Coverage is 33 of 68, not 68.** `vectors/cairo/sn_pie_2_witness_programs.bin`
holds **33 entries** (asserted in-tree at
`src/frontends/cairo/witness/bundle.zig:100`), generating `entries.len * 2` = **66
kernels** (`witness_aot.zig:28-30`). The 68 figure is the pinned official claim
registry (`official_claim_registry.zig:46`, `claim_field_count = 68`). The
separate `vectors/cairo/official/witness_programs_v1.bin` holds **64** entries
(pinned at `tools/cairo-witness-compiler/orchestrator.py:29`, missing exactly
`memory_address_to_id`, `memory_id_to_big`, `memory_id_to_small`,
`verify_bitwise_xor_12`) — and **no Metal path reads it**; it is consumed only by
CPU/frontend tests. Its provenance records `release_eligible: false` with three
blockers (`witness_programs_v1.provenance.json:3-8`). The 35 registry components
absent from the SN2 bundle are covered by other resident writers (fixed tables,
memory trace, native EC-op recipe), not by the witness batch.

**The checked-in witness metallib is stale and cannot load.**
`vectors/cairo/sn_pie_2_witness.metallib` exports 33 legacy unsuffixed
`stwo_zig_witness_<hash>` symbols — zero `_base` / `_interaction` / `_v6`
symbols. The current contract requires 66 names of the suffixed v6 form
(`witness_codegen.zig:60-76`), so it fails `validateRequiredExports` with
`error.WitnessExportCountMismatch` — which is exactly the regression test at
`witness_aot.zig:264-285`. Nothing in the repo references the file.

**The witness "AOT" path is source-JIT in practice.** The complete authenticated
admission contract exists and is tested —
`prepareAuthenticatedAotWitnessBatches` (`resident/witness/prepare.zig:192-233`),
`AuthenticatedMetallib.authenticate` with codegen-version pin, exact-order export
validation and TOCTOU re-stat (`witness_aot.zig:63-76`, `:115-164`) — and has
**no production caller** (only its definition and a re-export at
`arena_binding.zig:1073`). What the runner actually calls hardcodes `.source_jit`
(`prepare.zig:143-153`, `:168-178`, terminal switch `:515-534` →
`metal.compileEvalLibrary`). So both witness libraries are **compiled from
generated Metal source on every prepared-state miss**. Consistent with this,
`metal-witness-source` only *builds the generator*; no CI job or script ever runs
it (contrast the composition metallib, which CI does compile,
`ci.yml:422-441`).

**The Metal proof plan is structurally 33 components.**
`CairoProofPlan.fromWitnessSchedule` (`proof_plan.zig:213-239`) is documented as
"the recorded-witness portion used by the **legacy** Metal schedule", allocates
exactly `bundle.entries.len` seeds (`:221`), and hardcodes the sole native writer
by name (`:228-231`). The hard equality
`if (proof.components.len != witness_bundle.entries.len) return Error.InvalidCardinality`
(`resident/witness/execute.zig:227`) then pins the plan at 33 — never the 57 in
the schedule nor the 58 in the composition bundle. The live-geometry constructor
`fromSemanticArtifacts` (`proof_plan.zig:246-284`) has **zero Metal callers**.

**Residency is gated by a 10-way env-var AND.** `canonical_full_proof_plan`
(`metal_arena_plan/main.zig:2661-2673`, `eligible()` at `:734-740`) requires ten
`STWO_ZIG_SN2_*` conditions simultaneously; the session sets exactly that matrix
(`metal_prover_session/preparation.zig:377-399`). Any product path must replace
this with a structural predicate.

**Hardcoded cardinalities sit on the executing path**, not in dead code:
`resident/witness/prepare.zig:94` (`big.len != 28 or small.len != 8`), `:102`
(`trace.len != 273 or partial.len != 126`), `:88`/`:103-104` fixed arrays
`[37]`/`[273]`/`[127]`, `:116-121` multiplicity binding ordinals bound to literal
`(component, ordinal)` pairs, `:430-433` pointer-table caps 2048/8192/2048.
`resident/preprocessed/coefficients.zig:24-26` states the coupling in its own doc
comment: *"Binds all 33 canonical witness programs to the captured SN2 arena."*
SN2 protocol geometry is likewise baked at `compact_protocol_geometry.zig:32-47`
with the session's "live" derivation overriding only 3 of its fields
(`metal_prover_session/verification.zig:123-132`), and preprocessed tree-0 width
is a three-value whitelist (`compact_verifier_interchange.zig:30-37`).

*(One reassurance: the most alarming-looking table, `Sn2Counts`
(`schedule_bindings.zig:21-31`) with its literal 370/58/161/26/13/18, is
**residual** — it is reachable only via `PreparedProofBindings.initSn2`
(`arena_binding.zig:172-180`), which has no callers. The live gate is the list
above.)*

**Host work does not disappear at a device witness dispatch.** Thirteen host
items remain per request, of which three are per-dispatch rather than per-proof:
pointer-table workspace materialization is a host `@memset` + `@memcpy` **before
every kernel dispatch, per component per epoch**, 5-7 tables each
(`recipes/aot_witness.zig:160-170`, invoked from `executeIndex` at `:156`);
direct witness-input lowering is a **per-row host scalar loop**
(`resident/witness/inputs.zig:55-80` → `direct_inputs.zig:71-97`); and the
RC9_9 LUT is a host-built 2^18-entry table with two full passes
(`memory_trace.zig:182-205`). Plus, because the session sets
`STWO_ZIG_METAL_REPLAY_RETAINED_LOOKUPS=1` (`preparation.zig:395`),
`retainsLookupInputs` returns false (`proof_plan.zig:56`) and the interaction
epoch **re-runs a second full witness pass over all 33 programs** rather than
retaining the lookup slab.

**Verdict.** Phase 4 (witness) is confirmed as last and is materially larger than
§4 priced it: it needs a live-geometry proof plan (`fromSemanticArtifacts` wired
for Metal), a regenerated and newly *authenticated* witness metallib plus a build
step and CI job that do not exist, replacement of ~8 hardcoded cardinality sites,
a structural replacement for the 10-way env gate, and removal of per-dispatch
host materialization. Its measured prize is real — 624.1 ms on pedersen and
938.7 ms on memory-7m (§1.4) — but it is the one phase where the "reuse existing
machinery" premise is weakest, and the 33-of-68 coverage means a live-geometry
witness needs **new generated writers for components the SN2 bundle never
contained**.

---

## Phase 1: composition residency

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Head at start: `bf03954c`, clean. Raw data: `/private/tmp/p1-verify/`.
Predecessor binaries: `/private/tmp/p1-pred/bin/` (built at `bf03954c`,
`dirty = false`, verified via `identity`).

### The headline: the program gate could not be measured, and why that is the finding

**Verdict: the composition hook is a rejected candidate — rejected by a
structural precondition, not by measurement. The `>= 2.0x` program gate on
arithmetic-2m and memory-7m is NOT MEASURED, and cannot be measured until trace
residency exists.** The digest binding and the telemetry counter landed and stand
on their own.

§6.7-§6.8 scoped Phase 1 as "wire the existing composition metallib into the
product prove path", on four premises that are each individually true: the
metallib exists and is log-size-independent (§6.2), the composition bundle is
already claim-derived and already runs in-product (§6.1), the arena planner is
row-count-agnostic (§3.2), and `Engine`-style backend hooks already exist (§3.5).
All four hold. They are not sufficient, because of a fifth fact the survey did
not reach: **the AOT eval kernel ABI is single-arena-offset-only.**

| fact | file:line |
| --- | --- |
| every eval dispatch takes one `ResidentBuffer` arena and a plan | `src/backends/metal/runtime/prepared_execution.zig:544` `evalPrepared(self, arena: ResidentBuffer, plan: EvalPlan)` |
| batched eval dispatch, same single-arena signature | `prepared_execution.zig:566` `evalBatchPrepared(self, arena: ResidentBuffer, batch)` |
| `EvalLayout` is 11 `u32` **offsets into that one arena** — trace, interaction, base/ext params, random coeffs, denominator inverses, four output coordinates | `src/backends/metal/runtime/resource_plans.zig:172-184`; the 14-argument ABI at `:204-212` |
| the Cairo composition front/finalize recipes take arena offsets for every input and output | `src/integrations/cairo_metal/arena_binding.zig:1470-1506` (`prepareCompositionInputs`, `prepareCompositionFront`, `prepareCompositionFinalize`) |
| the product prove path holds **host** trace columns and has no resident arena | `src/prover/prove.zig:250-262` (`scheme.trace(allocator)`); `src/integrations/cairo_metal/prover/transaction.zig` imports neither `arena_binding` nor `resident/` |

There is no host-pointer eval surface. So `Engine.evaluateComposition` cannot
dispatch the composition metallib over host-allocated trace columns at all. To
dispatch it the base and interaction LDE evaluation columns, the preprocessed
columns, the denominator-inverse tables, the parameter tables, the random
coefficient powers and the output coordinates must all already live at planned
offsets inside **one** resident arena. Getting them there is either a
plane-sized host→arena pack per proof — which is R1, and which R4 already
recorded as a rejected retrofit (*"Metal accepts a true no-copy host source only
when all columns cover one contiguous arena. Cairo component execution produces
multiple independent allocations, so Metal still had to pack them"*) — or it is
trace residency, which is Phase 2/Phase 4 scope.

The volume makes the pack option unarguable rather than merely unattractive: the
composition bundle's `max_evaluation_log_size` is 24 (§6.2), so one column is
2^24 x 4 B = 64 MB, and Cairo composition reads the full base and interaction
column set across trees. Campaign 2 priced the comparable transfer at 3,420 MB
on memory-7m.

**Consequence for the program plan: Phase 1 is not independent of Phase 2.**
§6.7's reordering put composition first because it needs no new kernels and has
no Fiat-Shamir constraint. Both remain true. But composition residency is
downstream of *trace* residency, and trace residency is the arena work in
Phases 2/4. The correct Phase 1 is therefore either (a) the arena/residency
plumbing itself, priced and measured on its own, with composition as its first
consumer, or (b) a genuinely non-arena device composition path — for which the
precedent exists at `secure_composition.zig:48-107`
(`evaluateLargeRecurrenceComposition` binds a host column pointer plus an
optional resident tree handle and dispatches a bespoke kernel), but which would
require new Cairo composition kernels outside the AOT metallib and so forfeits
the "reuse the existing library" premise that made Phase 1 cheap.

One correction to §3.6/§6.6 while here: `scheme.backendResidencyHandles`
(`src/prover/pcs/scheme_views.zig:51-64`) yields `B.quotientResidencyHandle`,
which is a **Merkle tree handle** (`src/backends/metal/merkle_tree.zig:208-213`
returns `resident.tree.handle`), i.e. the hash arena of a committed tree — not
the LDE evaluation columns. Composition cannot read its inputs from it.

### Work item 1 (landed): digest-binding the composition metallib

The composition metallib was the only Metal artifact on any Cairo path loaded
with no integrity check anywhere in-tree. §6.3.1 identified it; this closes it.
`src/integrations/cairo_metal/composition_aot.zig` (new, 355 lines):

- `authenticate(path, policy)` measures the file with stat / full read / re-stat,
  so a library swapped between the digest check and `loadEvalLibrary` is caught
  by the re-stat rather than loaded. Same TOCTOU handling as
  `witness_aot.zig:130-160`.
- `approved_metallibs` is the in-tree manifest. `vectors/` is protected, so the
  manifest is a source constant rather than a provenance JSON; the single entry
  is `sn_pie_2_composition_v1`, sha256
  `85db09e024a661d78e34e53ed2ae36c150567977223f34bba88f119b3c7b21ab`,
  length 7,740,844. Admission is by digest **and** length; `label` is evidence
  only and never participates, so renaming, relocating or path-substituting an
  artifact cannot affect admission.
- `Policy` has **no unchecked variant**. `approved_manifest` is the default and
  the only policy a proving path may use. `pinned_digest` admits one named
  digest — the escape hatch for a CI-compiled library that predates a manifest
  entry, via `STWO_ZIG_COMPOSITION_METALLIB_SHA256`; a malformed value is an
  error, never a downgrade. `report_only` measures and admits, reserved for
  offline codegen tooling (`metal-eval-prepare` operates on libraries it has just
  generated, which by construction cannot be in a checked-in manifest) and
  documented as forbidden on any path that produces a proof. `Policy.gates()`
  lets a caller assert it holds a gating policy.
- Digest parsing rejects non-canonical spellings (uppercase included) so a digest
  in a report is byte-comparable with a digest in the manifest.

Enforcement point: `resident/composition/config.zig` gained `loadAuthenticated`,
and `arena_binding.zig:1192`'s `.metallib` arm now calls it. Library selection
already lived in `config.zig`, so integrity lives there too: there is now exactly
one place a `.metallib` can enter a resident composition and it cannot be reached
without a digest check. `composition_prewarm.Inputs` gained a `policy` field
defaulting to `approved_manifest`, and `Evidence` now carries the measured
`metallib_sha256` / `metallib_length` / `metallib_label` of the library actually
loaded.

**This is a security fix independent of the performance work and it deserves
independent security review, not only a performance review.** What it defends
against specifically: by-name kernel resolution
(`composition_prewarm.zig:46-62`) is a *completeness* check. A library that
exports correctly-named kernels with substituted bodies resolves every pipeline
cleanly and evaluates the wrong AIR for a full proof. The verifier does reject
the result (it recomputes composition at the OODS point, R5), but only after the
prover has paid the entire proving cost, and no artifact anywhere names the swap.

Two limitations recorded rather than hidden:

1. `metal_prover_session/app.zig`'s prewarm passes `report_only`. It warms
   pipelines over a content-addressed artifact-store snapshot and is not a proof;
   the session gates that object separately through
   `preparation.authorizeCompositionProgram`, whose own default is `.diagnostic`
   (permissive), and the library a session proof actually loads is gated at the
   runner. Threading the session's `--composition-metallib-sha256` down to this
   prewarm as a `pinned_digest` so both gates read one value is an identified
   follow-up.
2. The manifest has one entry because CI is the only producer of this artifact
   and this host has no full Xcode (§6.3.2). Any phase minting new semantic
   hashes needs a CI round trip and a manifest addition.

### Work item 2 (landed): counting interaction and composition dispatches

§6.3.3 is closed. `metalDispatchTotal` summed exactly ten counters and had no
relation or composition variant, so the measured 74-79 provably contained zero
interaction device work and the `accelerated_without_fallbacks` gate could not
have seen any.

- `Event.metal_relation_dispatch` and `Event.metal_composition_eval_dispatch`,
  both added to `metalDispatchTotal`.
- `metal_relation_dispatch` is recorded where the fused LogUp kernel chain is
  actually submitted: `src/backends/metal/recipes/relation.zig:165`
  (`RelationRecipe.execute`, after `relationPrepared`).
- `Event.cpu_composition_evaluation` added to `cpuFallbackTotal`, recorded at
  `composition_aot.authenticateFromProcess`'s failure path — so a declined device
  composition is a *counted* fallback and cannot report
  `accelerated_without_fallbacks`.

The judgement worth flagging: `cpu_composition_evaluation` is deliberately **not**
recorded for the default host placement of composition. That is a placement, not
a fallback. Recording it there would make every hybrid Metal proof report a
fallback and would destroy the meaning of the classification the whole program
uses as its invariant.

### Verification

Cache-off (`STWO_CAIRO_PREPROCESSED_CACHE=0`), `run-and-prove`, single cold runs.
These are correctness evidence, not paired timing evidence — no A-B was run,
because there is no mechanism change to price.

| workload | Metal proof sha-256 | campaign value | match | dispatches | Phase 0 baseline | fallbacks | classification |
| --- | --- | --- | --- | ---: | ---: | ---: | --- |
| all-opcodes | `79ae76e1ac0c` | `79ae76e1…` | yes | 75 | 75 | 0 | `accelerated_without_fallbacks` |
| arithmetic-2m | `25e5719f4c57` | `25e5719f…` | yes | 74 | 74 | 0 | `accelerated_without_fallbacks` |
| memory-7m | `e3317e55a5db` | `e3317e55…` | yes | 79 | 79 | 0 | `accelerated_without_fallbacks` |

CPU all-opcodes: `79ae76e1ac0c`, byte-identical to Metal, `host-only`, 0
dispatches — the program invariant holds and the host path is untouched.
Dispatch counts are **unchanged from the Phase 0 baseline on every row**, which
is the check that three new counters defaulting to zero cannot move an existing
workload's evidence; it is also asserted directly as a unit test against a
74-dispatch hybrid profile.

Prove times for the record (single cold runs, host load 4.73 1-minute, so these
are not comparable with Phase 0's numbers and no speedup is claimed from them):
all-opcodes Metal 1,215.9 / CPU 1,340.1 ms; arithmetic-2m 1,691.3 ms;
memory-7m 4,450.0 ms.

Tests: `test-cairo-metal-product`, `test-cairo-frontend`, `test-native-metal` all
pass (Metal product closure PASS, 385 sources; native Metal lifecycle PASS).
`composition_aot.zig`'s 8 tests pass, including the fail-closed cases: a
length-preserving single-byte flip in a kernel body is rejected as
`UnapprovedCompositionMetallib` under the manifest and as
`CompositionMetallibDigestMismatch` under a pinned digest, and empty / missing /
zero-length paths are rejected.

**Honest gap in the fail-closed evidence.** The brief asked for an end-to-end
corrupt-the-metallib test showing host fallback with the fallback counted in
`backend_evidence`. That cannot be demonstrated in the product, because the
product prove path never loads the composition metallib — which is precisely the
finding above. The fail-closed behaviour is demonstrated at the module level and
the fallback counter is unit-tested; the end-to-end demonstration becomes
available in the same increment that first puts a device composition on the
prove path.

Pre-existing, noted not chased: `metal-prover-session-test` fails to compile at
`bf03954c` with 5 errors (`metal_arena_plan_cli has no member named
PreparedStateKey` / `canonical_protocol` / `PreparedHostGeometry` /
`protocolObjectIsCanonical`) — confirmed pre-existing by stashing all changes and
reproducing. `composition_aot.zig`'s tests are consequently not reachable from
any green build step: `src/integrations/cairo_metal` is excluded from both
aggregate closures (`build_support/products/aggregate.zig:141-156`) and the
cairo_metal product owns only `src/integrations/cairo_metal/prover`
(`build_support/products/cairo_metal.zig:47`). They were run directly with
`zig test`. Wiring them into a green step is a follow-up worth doing before the
security review.

### Where Phase 2 should start

The interaction increment's blocker is the same one, and it is worth stating that
plainly: `relation.metal`'s kernels are reached through
`metal.relationPrepared(self.arena.buffer, self.prepared)`
(`recipes/relation.zig:164`) — the identical single-arena surface. Interaction
residency is therefore also downstream of trace residency, and `z` and the alpha
powers are already bound *from inside* the resident arena
(`runtime/prepared_auxiliary.m:199-200`), not uploaded per call. So the arena is
not one phase's incidental cost; it is the shared precondition for composition
**and** interaction, and it should be planned, built and measured as its own
increment rather than absorbed into either.

---

## Phase 1.5: the resident trace arena (stopped mid-increment)

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Head at start: `ef8e0c2c`, clean. Predecessor binaries: `/private/tmp/p15-pred/zig-out`
(built at `ef8e0c2c`, `identity` verified `dirty = false`,
`core-aot-manifest-sha256 = 0bc89238…`). Raw data: `/private/tmp/p15/`.

**Stopped on orchestrator instruction** so the branch can be rebased onto a
modularity refactor that moves the seams this increment touches. No paired
A-B-B-A evidence was taken and the composition binding smoke test was not
written. What follows is the design, the seam map, the one blocker the increment
measured, and the correctness evidence that exists.

### The headline: the arena can be planned, but not *before* execution

The increment's premise was that the claim-derived geometry is available before
witness execution, so one arena could be planned from it and every base column
written at its final offset. The layout half of that is true and landed. The
timing half is false, and this is the finding:

**A claim derived before witness execution still carries `deferred`
per-component log sizes.** `claim_generator.LogSize` is a union with a
`.deferred` arm and `OwnedClaimGeometry.deferredCount()` exists precisely to
count it; the resolution point is `resolveFeedGeometry`, whose own doc comment
names it *"the witness-to-statement handoff"*. The AIR template binder refuses
a deferred log size outright (`air/template_binding.zig:42`, `:104`,
`error.IncompleteClaimGeometry`), and so does `flatten`
(`claim_generator.zig:144`).

This was measured, not reasoned: the first wired build failed the all-opcodes
run with `error: IncompleteClaimGeometry` raised from the pre-execution
`instantiate` call. So for every live Cairo workload the per-component row
counts that the layout needs are only known *after* the witness graph has
reported its feeds.

Phase 0 §3.2 said the arena planner is row-count-agnostic. That is correct and
it is not the constraint. **The constraint is that the row counts themselves are
not available in time.** Campaign 1's rejected retrofit was rejected for
allocating after fragmentation; this increment shows the successor it demanded —
"allocate one backend-shaped base arena BEFORE component execution" — cannot be
driven by the live claim alone, because the live claim is not complete before
component execution.

### Layout design, and the seam map

| concern | file:line |
| --- | --- |
| arena layout planner (new, 315 lines) | `src/frontends/cairo/proving/trace_arena.zig` |
| layout tests (new, 192 lines) | `src/frontends/cairo/tests/base_trace_arena.zig` |
| allocation-before-execution seam | `src/frontends/cairo/proving/base_trace.zig` `buildInto` + `Collector.capture` |
| product gate (comptime, Metal only) | `src/frontends/cairo/proving/transaction.zig` `arena_capable` |
| commit-side adoption decision | `src/prover/pcs/backed_columns.zig` `adoptOrDetach`, `freeSource` |
| detach bypass | `src/prover/pcs/scheme.zig` `commitOwnedPreparedWithRecorderAndBacking` |
| per-group arena binding | `src/prover/pcs/columns/preparation.zig` `arenaGroupRun` |
| backend declaration | `src/backends/metal/commit_backend.zig` `adopts_source_trace_arena` |

**Layout.** Columns are grouped by `log_size` in first-appearance order —
exactly the order `circle_transforms.buildLogSizeGroupsFromColumns:522-533`
produces at commit time — and within a group they keep ascending flat-column
order. Each group starts on a page boundary. The base region is page-padded and
the interaction region is *reserved* (offsets and length computed and tested)
but not materialized, because interaction columns are written after the base
commit per Fiat-Shamir.

**Why that shape.** The no-copy commit source already exists and this is what it
requires. `runtime/circle_legacy.m:227-229` computes
`source_is_base = source_columns[column] == base_columns[column]` for every
column; when it holds, the whole fused-upload encoder is skipped
(`:265-322`) and the IFFT runs in place from layer 1. `:229-230` additionally
requires `base_columns[0]` page-aligned and `base_bytes` a page multiple for the
`newBufferWithBytesNoCopy` alias; failing that costs exactly one memcpy
(`:322-328`) and stays byte-correct. `combined_commit.zig:91-99` and
`columnsCoverContiguousBacking:320-332` are the same contract for the uniform
one-epoch path.

**Why the CPU product is untouched by construction, not by testing.**
`prepareColumnsCombinedForBackend:249-262` only allocates a group coefficient
arena when `combined_base_in_place` is absent. `cpu_scalar/mod.zig:39` declares
it, and `:37-38` cap the combined path at 256 columns — which the Cairo base
trace exceeds — so the CPU backend neither allocates nor can receive a group
arena. The product gate is comptime on `Engine.Backend.adopts_source_trace_arena`,
which only Metal declares.

**Fail-closed vs fall-back, deliberately split.** Planning refusals are a
*fallback* (`trace_arena.tryPrepare` → `null`, product keeps the fragmented
path): non-contiguous or empty spans, out-of-range row counts, size overflow, a
structural size floor, and now an incomplete claim. A plan/actual *width*
disagreement at capture time is a *hard error* (`ArenaPlanMismatch`), because by
then storage is already committed and the alternative is writing outside a
planned range. `transaction.zig` additionally re-checks
`trace_arena.columnsMatchPlan` before handing the arena to the commit, because
that pointer equality is the entire basis of the no-copy binding and it is
cheaper to check than to assume.

### Correctness evidence (single cold runs; no timing claim)

Cache-off (`STWO_CAIRO_PREPROCESSED_CACHE=0`), `run-and-prove`.

| lane | workload | proof sha-256 | campaign value | match | dispatches | fallbacks | classification |
| --- | --- | --- | --- | --- | ---: | ---: | --- |
| Metal | all-opcodes | `79ae76e1ac0c` | `79ae76e1…` | yes | 75 | 0 | `accelerated_without_fallbacks` |
| CPU | all-opcodes | `79ae76e1ac0c` | `79ae76e1…` | yes | 0 | 0 | `host-only` |

Byte-identical CPU/Metal, dispatch count identical to the Phase 0 baseline. That
is expected and it is also the weakness of this evidence: **the arena path falls
back on this workload**, so what is verified is that the machinery is inert, not
that it is correct when engaged. arithmetic-2m and memory-7m were not run.

`test-cairo-metal-product`, `test-cairo-frontend` and `test-cairo-cpu-product`
all pass (Metal product closure PASS, 386 sources; CPU closure PASS, 335). The
layout's five tests run inside `test-cairo-frontend`; they were deliberately put
in the frontend *test root* because `addTest` only collects tests from its root
module's own files, so tests beside the planner would compile inside the product
closure and never run — this was verified by breaking an assertion and observing
the step still pass. That is the same gap the Phase 1 note recorded for
`composition_aot.zig`, avoided rather than repeated.

### What a successor needs

The arena cannot be driven by the pre-execution claim. Three routes, in
increasing cost:

1. **A width-and-row oracle that does not need the witness.** The base tree's
   *widths* are static per component (the AIR template spans); only the *row
   counts* of feed-dependent components are deferred. A conservative planner
   could allocate at an upper bound per deferred component and bind only the
   used prefix — at the cost of a per-group contiguity break, which is exactly
   what `source_is_base` forbids. So the upper bound would have to be exact, not
   conservative.
2. **Resolve feeds before the base graph runs.** `resolveFeedGeometry` consumes
   `FeedGeometry` reports produced during execution. If the feed row counts can
   be computed from the prover input alone (a counting pass, not a witness
   pass), the claim completes before execution and the layout as landed works
   unchanged. This is the cheapest route that preserves the no-copy binding and
   it is the one to price first.
3. **Plan after execution, write once.** Give the witness graph the arena as its
   output target in a second phase that never materializes fragmented columns —
   i.e. move the arena decision inside `live_graph.execute`. Larger, and it is
   adjacent to the Phase 4 witness-residency work.

The composition binding smoke test — `evalPrepared` bound against a live arena
for one component, byte-compared against the host evaluator — was **not
written**, so the Phase 1 eval-binding unlock is **not demonstrated**. The
existing template for it is
`src/tests/metal/backend/execution_graph_test.zig:234-322`, which already builds
a resident arena, writes trace words and offsets into it, constructs the eleven
`EvalLayout` offsets and dispatches `evalPrepared`; what it does not do is use
the digest-verified metallib or a real Cairo component's program.
