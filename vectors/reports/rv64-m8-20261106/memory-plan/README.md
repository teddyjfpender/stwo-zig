# M8 memory plan: a generated per-class memory policy for the job runtime (memory-plan-p2)

Spec §3.7 and frontier-delta §4 item 3. Branch `codex/rv64-m8-memory-plan-p2`, cut from `codex/rv64-m7-integrate` at `dbe394860`.
Compact data is in `summary.json`. Raw worker plans and logs stay on the pod under `/workspace/m3/runs/m8-memory-plan-p2/`
(`sweep-{lifo,reuse}-2`, `sweep-policy-1`). Each `run.json` there carries the log's SHA-256.

## What landed (default-off)

| piece | file | what it does |
|---|---|---|
| policy | `rv64/jobs/plan.zig` | Loads `STWO_RV64_M8_JOBS_PLAN=<policy.json>` (schema `rv64-m8-jobs-memory-policy/v1`). `resolve(key, declared)` replaces the job's hand-declared `device_words` with the class's measured peak. `pairFits`, `checkPair` and `checkPolicyLayout` drive the worker's real `Arena` through every co-resident class pair, on both placements. |
| worker | `rv64/jobs/worker.zig` | Consumes the policy at start: arena size, persistent budget and allocator. If a job pair does not fit side by side, the worker serializes it instead of failing it. `Regions` holds class-persistent regions in one pool and evicts LRU among regions that no in-flight job pins. The `reuse` allocator reclaims non-LIFO frees: holes, best fit, coalescing, and addresses that depend only on the class's allocation sequence. Per-side peak, live peak and the allocation that set the peak are recorded. `STWO_RV64_M8_JOBS_PLAN_DIR` writes one plan file per worker, from any harness. |
| scheduler | `rv64/jobs/scheduler.zig` | Places a job only on workers it fits on by footprint (`Worker.fits`). If no worker fits, the least-loaded worker takes the job and serializes it. |
| generator | `scripts/rv64_m8_plan_sweep.py` | `run` / `collect` / `generate` / `check`. Tests are in `scripts/tests/test_rv64_m8_plan_sweep.py`. |
| policy data | `policy.json` | Generated from the reuse sweeps: device 32607 MiB, reserve 2 GiB, margin 2%. |

With `STWO_RV64_M8_JOBS_PLAN` unset, the worker behaves exactly as before: declared footprints, the env or config arena,
per-key persistent allocations and LIFO frees.

## Sweep: declared vs measured, per class [M]

The sweep ran every job class through a real DeviceWorker on RTX 5090 dev0. Base: frozen a25 image. Addon: built from this tree; the
CUDA is unchanged. Two harnesses were used:
- the outer fixture: a 2^21-row trace-only leaf, 4 prefix jobs and 8 whole-node jobs;
- the native GPU tests in `test-rv64-jobs`, run with `STWO_RV64_M8_PCS_SCALE=1`.

All figures are words (4 bytes).

| class | declared peak | measured peak, lifo | measured peak, reuse | live peak | policy peak (+2%) | declared / measured |
|---|---|---|---|---|---|---|
| outer leaf 2^21 (fixture) | 1,374,107,520 | 613,580,672 | **595,746,432** | 595,746,432 | 607,661,376 | 2.24x (lifo), 2.31x (reuse) |
| native PCS, segment-scale (1564 cols, lift 24) | 2,684,654,208 | 2,141,977,472 | 2,141,977,472 | 2,141,977,472 | 2,184,817,024 | 1.25x |
| native stage-1 probe | 77,112 | 5,248 | 5,248 | 5,248 | 5,376 | 14.7x |
| native stage-2 probe | 1,063,896 | 16,320 | 16,320 | 16,320 | 16,704 | 65x |
| native tail probe | 1,056,928 | 14,144 | 14,144 | 14,144 | 14,464 | 75x |

- **LIFO waste:**
  - Outer: 17,834,240 words (71 MB) per node under LIFO frees. The reuse allocator removes all of it: peak equals live peak, −2.9% [M].
  - Native PCS: none. Its live peak equals its bump peak, so LIFO frees are *not* why its peak is high. The PCS keeps its own block pool
    and releases everything in reverse order at the end.
- **What sets the peak (the "late PCS scratch"):** in both large classes the peak comes from the last allocation of the job, and that
  memory is live, not fragmentation.
  - Outer: allocation 120/120, 216,295,168 words.
  - Native PCS: allocation 78/78 or 79/79, 805,306,368 words (3.2 GB).

  A further drop has to come from the PCS: release retired planes to the arena as soon as they retire, so the reuse arena can coalesce
  adjacent ones for that last plane. That code is in `pcs_enqueue.cu` (native-owned). The request is in M8-INTERFACES.
- **Byte identity:** byte-identical in both allocator modes [M].
  - Outer fixture: 8/8 whole-node proofs byte-equal to legacy, plus prefix parity 4/4.
  - Native: 4/4 `byte_identical=1` (PCS scale ×2, stage-2, tail), plus commit/stage-1 root and channel parity.

## Generated policy [D from M]

| field | value |
|---|---|
| `arena_words` per GPU | 2,501,732,864 (10.0 GB): PCS-scale peak + the largest staged input (its own 316.9M; the outer leaf stages 268M) |
| `persistent_budget_words` | 8,142,528 (32.6 MB) |
| `allocator` | reuse |
| `max_concurrent_jobs` | 2 (every class fits beside every class's staged inputs) |
| `device_budget_words` | 8,010,858,496 (32607 MiB − 2 GiB reserve) |

Comparisons [D]:
- **Default 8 GiB arena** (2,147,483,648 words): too small for a staged neighbour next to the segment-scale PCS (it needs 2.50e9). Without
  the policy that pair fails `JobWorkExceedsArena`; with it, it serializes or fits.
- **Outer fixture's hard-coded arena** (5,368,709,120 words): the policy needs 2.15x less.
- **Headroom:** about 5.5e9 words (22 GB) per GPU is left. Stage A, where legacy native shares the GPU, can size against it [E].

The Zig test `layout: the committed memory policy passes the pairwise check` re-verifies `policy.json` on every `test-rv64-jobs` run.

## Validation with the policy in force [M]

Same harnesses with `STWO_RV64_M8_JOBS_PLAN=policy.json`:
- Every worker ran with `arena_words = 2,501,732,864`, `allocator = reuse`, and the persistent pool.
- Outer: 3 regions and 8,141,824 words from the pool, 0 evictions.
- `over_plan = 0` for every class, and measured peaks were within the 2% margin.
- Outer: 8/8 whole-node proofs byte-identical and prefix 4/4.
- Native: `test-rv64-jobs` 166/166 passed (GPU tests included) and 4/4 `byte_identical=1`.

Class-region LRU eviction is covered by host tests: eviction order, pins block eviction, failed fills retired, a hopeless acquire evicts
nothing, and worker-level refill. It has not been exercised on the GPU, because no current GPU harness has more persistent classes than
the pool holds.

## Not claimed

- **No timing:** this stream changes memory layout only.
- **Real request classes not swept:** the 24628607 segment classes and the real leaf/fold/root classes are not on the job path yet
  (`jobs/mod.zig provider()` still fails closed). The sweep spec takes new harnesses as wire-outer and native-producers land them. The
  policy's `unplanned = declared` keeps unknown classes on their declarations.
