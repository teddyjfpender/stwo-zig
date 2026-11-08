# runtime-persist-p3 receipts (M8 architecture pass 3, stream runtime-persist)

Branch `codex/rv64-m8-runtime-persist-p3` from `codex/rv64-m7-integrate @ 18e524795`. Pod 2x RTX 5090 (`/workspace/m3`).
Labels: [M] measured on the pod, [D] derived, [E] estimated.

## B3 composition regressions

| item | root cause | fix |
|---|---|---|
| `rv64.jobs.plan_test ... PLAN_DIR rows parse back` crashed on the pod | `Worker.report` fired the completion sink **before** recording class stats; `writePlanDir` read `classes` without the mutex, so a waiter could see 0 classes and `classes[0]` panicked (ReleaseSafe) | stats recorded under the mutex before the sink; `writePlanDir` copies rows under the mutex; regression test `worker_service_test.zig` "class stats are recorded before the completion fires" |
| `outer_staged.zig` layout test (64 vs 10 words) | test expected 2-word alignment after the 256 B change | cherry-pick of integrate fix dfe586711 |
| outer fixture `GPU_PCS_JOB_ENQUEUE error=job arena allocation failed` | not the worker arena (fixture arena 5<<30 words) and not the policy (fixture runs without one): `OuterNodeJob.enqueue` sizes its single work heap from its own `footprint()`, which after 880a39d5b is a fit to 26235156 real leaves and under-bounds the 2^21 fixture node | runtime side: `api.Enqueue.footprint()` / `planned()` (the footprint the worker planned with). The one-line consumer change and the fit are in `outer_job.zig` (outer-fold owns it); asked in M8-INTERFACES. **Open** until outer-fold lands it |

Host tests: `test-rv64-jobs` + `test-rv64-jobs-outer` green locally (Debug, ReleaseSafe, 5 repeated runs) and on the pod
(x86_64-linux-gnu ReleaseSafe, `runs/m8-runtime-persist-p3/host-1.log`, `host-2.log`: 251/256, 5 skipped).

## Persistent service: per-request open/close [M]

`service-1.json` (sha256 of the pod copy `7dd74fa1…442f29a`):
`rv64-jobs-channel-parity service 0 20480 2256 5`. GPU0, one worker, 20 GiB arena, 2256 MiB pinned cap (the hybrid gate's
`STWO_RV64_M8_JOBS_PINNED_BYTES`), each job stages 16 MiB and grinds a 12-bit PoW. Harness binary sha256 `614385b8…c86e63f`
(source = 27975dd43 without the row-initialisation fix), addon `e8d353c3…bc8e52` (integrate p2b), base
`m7-combined-residency`. Wall clock of host operations (no GPU kernel timing is claimed).

| arm | open per request | close per request | pinned host memory |
|---|---|---|---|
| today's window: `Worker.create` + `destroy` per request, 3 eager slots | 3674-4453 ms | 1427-1574 ms | 7.10 GB allocated each request |
| persistent: `unpark` / `park` | 0.0-0.1 ms | 0.0-0.1 ms | 100.7 MB, 3 allocations for the life of the worker |

Both arms produce the same PoW nonce. Warm persistent jobs take 1.4-1.5 ms, the same as the window arm's 1.6-2.3 ms. Cold jobs 1-3 take 21-33 ms, because each grows one lazy slot.
`same_base=true` on cycles 2-5: the arena epoch stays at 2 after the first unpark, so captured graphs stay valid.

**Reproduced on the landing source** (`service-2.json` = pod `runs/m8-runtime-persist-p3/service-2.err` without its `GPU_` log lines, sha256 `d46d057d…c76331fb`; tree of `03291f578` = landed `b9a009101`): harness sha256
`36e56d91…b213c5fdc`, this stream's addon `7843b498…e699abda` (`jobs-addon-1`, the one the gates use), same arguments, under `gpu.lock`.

| arm | open per request | close per request | job | pinned host memory |
|---|---|---|---|---|
| window (`create`/`destroy` per request) | 3714-4160 ms | 1430-1608 ms | 1.65-2.17 ms | 7.10 GB each request |
| persistent (`unpark`/`park`) | 0.03-0.08 ms | 0.05 ms | 1.58 ms warm, 22.7-35.4 ms cold (cycles 1-3) | 100.7 MB total, 3 allocations |

Persistent boot 0.53 ms, stop 22.2 ms; nonce 1070 in every row of both arms; `same_base=true`, epoch 2 on cycles 2-5.
Channel parity on the same binaries (`parity-2`, GPUs 0,1, 4 jobs per worker): ok, 24 jobs, 0 failures, 896/896 boundary snapshots.
[D] The hybrid window's measured 6.3-8.2 s open and 2.4-3.0 s close (wire-outer-p2, two workers) is about all worker create/destroy, dominated by the pinned slots. `WorkerSet.startParked` with park/unpark removes it once outer-fold consumes it.

## Gates

`gates.json` (pod run `runs/m8-runtime-persist-p3/g1`, source `03291f578`, same tree as landed `b9a009101`):

- **default** `rv64_gate.sh` 26235156: [M] **PASS** (byte-identical to the frozen D2 golden, fresh CPU receivers, corpus).
- `--env STWO_RV64_M8_JOBS=1`: FAIL closed, `M8RequestProviderNotLanded` after boot parity - unchanged from integrate.
- hybrid `STWO_RV64_M8_OUTER_JOBS=1` on 26235156 / 24628607: FAIL closed - 11 / 12 job nodes direct, folds refused
  `JobFootprintExceedsArena` (4,9 / 4), then a teardown abort `host budget heap underflow` (exit -6). The same abort and fold
  refusals are in integrate's `m8-wire-outer-p2/gate-h2`, so this is pre-existing, not introduced here. **Open** (owner: the
  hybrid path / host budget allocator; `src/prover/host_budget_allocator.zig:290` reached from `rv64_large_block_recycler.deinit`).
- The one new flag this change makes reachable is `STWO_RV64_M8_JOBS_PINNED_LAZY` (default off on `WorkerSet.start`); both job-flag
  gates ran with it `=1` and reach the same outcomes as integrate's eager-slot runs. `startParked`/`park`/`unpark` have no production
  caller yet and `prep_threads` defaults to 0.
