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
