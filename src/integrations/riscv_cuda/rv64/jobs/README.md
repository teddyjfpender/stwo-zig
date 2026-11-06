# rv64/jobs — M8 job runtime (as built)

Spec: `design/riscv-proving-stack/rv64-m8-job-architecture.md`. This directory is the new path; legacy files stay
untouched and are the parity reference. Selected only by `STWO_RV64_M8_JOBS=1` on `combined-serve`.

| file | role |
|---|---|
| `api.zig` | the contract (spec §3.1): `Job`/`VTable`, `Stager`, `Enqueue`, `Footprint`, `SlabView`, `Job.from` |
| `worker.zig` | `DeviceWorker`: one thread per GPU, 1-lane exec context, h2d stream, two-sided arena, 3 pinned slots, 3-stage loop |
| `ops.zig` | device op table: base-image exports + addon exports; `Exec` (enqueue-only) vs `Wait` (worker loop only) |
| `channel.zig` | `DeviceChannel`: Fiat–Shamir on the device over `NAT/rv64/channel.cu` + addon raw draw + PoW |
| `slab.zig` | `ProofLayout`/`ProofSlab`, `encodePhysical`, resident-PCS readback layout (`PcsGeometry`) |
| `channel_parity.zig` | host `Om31Channel` vs device channel at every boundary; `Recorder` (om31_observer) |
| `scheduler.zig` | request DAG → workers; key affinity > root-critical > least loaded |
| `request.zig` | `Provider` seam + spool protocol; per-request `m8-jobs.json` |
| `mod.zig` | `combined-serve` entry: selection, workers, boot self-test, provider (fails closed until it lands) |
| `lint.zig` | sync lint: no sync/D2H/lease symbol reachable (file level, transitive) from job sources |
| `fake.zig` | host device model for GPU-free tests (`zig build test-rv64-jobs`) |
| `gpu_native.zig` | GPU-native request contract (`design/riscv-proving-stack/rv64-m8-gpu-native.md`): status words, request slab, peer exchange, class cache, device checks/encoders, memory plan, capture hand-off, factories, `publish` |
| `driver.zig` / `native_device.zig` / `outer_device.zig` / `truth_job.zig` | GPU-native stream entry points (stubs, fail closed) for streams driver / native / recursion |

CUDA addon: `NAT/rv64/jobs/*.cu` → `libstwo-rv64-jobs.so` (`scripts/rv64_m8_jobs_addon_build.py --base <frozen image>
--out <dir>`), loaded with `STWO_RV64_M8_JOBS_LIBRARY`. ABI version in `ops.zig` = `runtime.cu`.

## Rules a job must follow

- `stage`: preflight everything (resources, geometry); allocate inputs with `Stager.alloc`, fill `Stager.pinned`, `upload`.
  Long-lived class data: `Stager.persistent(key, words)` (fill when `fresh`).
- `enqueue`: only enqueue work: `stwo_rv64_*_on(e.ctx(), 0, ...)` / `stwo_*_on(..., e.stream())`, `e.alloc`/`e.free`,
  `e.channel.*`, `e.slab.*`, `e.hostFn` (pinned memory only, no CUDA). No sync, no D2H, no leases, no legacy owner-path
  imports (the lint fails the build of `test-rv64-jobs`).
- `finish`: read `SlabView.words` (pinned, after the worker's single event wait). Decode/publish. The view is valid
  only during `finish`: the pinned slot is reused three jobs later, so copy out what later steps (seal, leaves) need.
- `footprint`: static class plan. A job whose `device_words + slab_words + 32 > arena` is refused, never waited on.

## Memory model

Staged inputs of the job on side S sit at the S end of the arena; its enqueue allocations grow from there toward the
other end, bounded by inputs staged on the other side. All enqueued work shares one exec stream, so successive jobs may
reuse addresses; the h2d stream waits (on the device) for the most recently enqueued job before writing a side. Arena
ranges are 256-byte aligned and validate against the exec context's ledger (one registered allocation).

## Outer job (OuterNodeJob, hybrid recursion)

| file | role |
|---|---|
| `outer_job.zig` | `OuterNodeJob`: one leaf/fold/root node as an api.Job (stage/enqueue/finish), footprint, held buffers, PCS tail |
| `outer_node.zig` | the node body: FIXED (when not handed off), MAIN, INTER, composition, PCS opening |
| `outer_trace_commit.zig` | enqueue-only trace commit: full-LDE `enqueue` and chunk-bounded `enqueueStreamed` |
| `outer_composition.zig` | RC composition + its commit (streamed or tree) |
| `outer_fixed_job.zig` | `FixedJob`: FIXED precommit root on the worker; optional coefficient handoff to the node |
| `outer_graph_cache.zig` | per-worker CUDA graph cache: capture threshold, LRU device budget, request aging, blacklist |
| `outer_heap.zig` | per-node first-fit work heap; trace-commit phases are checked against the int32 index guard |
| `outer_plan.zig` / `outer_staged.zig` / `outer_kernels.zig` | class plan, staged image, kernel table + `Device` view |
| `outer_window.zig` | all-or-none reopen of a parked hybrid window |
| `outer_env.zig` | strict parse of the knobs below |

### Outer job environment

Parsed strictly (`outer_env.zig`): unset = default; flags accept exactly `0`/`1`; numbers must parse completely;
anything else fails `Hybrid.create` with `InvalidM8OuterEnvironment`. None of these changes a proof byte.

| variable | default | effect |
|---|---|---|
| `STWO_RV64_M8_OUTER_JOBS` | `0` | `1` = hybrid recursion (every node an OuterNodeJob); else fails closed |
| `STWO_RV64_M8_OUTER_PERSIST_WINDOW` | `1` | `0` = start/stop the workers per request instead of park/unpark |
| `STWO_RV64_M8_OUTER_FIXED_JOB` | `1` | `0` = legacy owner FIXED precommit (node recommits FIXED) |
| `STWO_RV64_M8_OUTER_FIXED_HANDOFF` | `1` | `0` = node recommits FIXED even after a FixedJob precommit |
| `STWO_RV64_M8_OUTER_PERSISTENT_CLASSES` | `0` | `1` = fold class regions in worker-persistent memory |
| `STWO_RV64_M8_OUTER_RESERVE_BYTES` | 1 GiB | device headroom left outside the window arena (plus the FIXED handoff regions) |
| `STWO_RV64_M8_OUTER_STREAM` | `1` | `0` = full-LDE commits (needs < 2^31-word images: the heap guard refuses folds) |
| `STWO_RV64_M8_OUTER_STREAM_CHUNK_WORDS` | 2^26 | streamed commit chunk (0 = default) |
| `STWO_RV64_M8_OUTER_PCS_RESERVE_TREES` | 11 | PCS working-set multiplier in the footprint (sweeps) |
| `STWO_RV64_M8_OUTER_DECLARE_WORDS` | unset | cap on the declared device peak (sweeps; the heap still fails closed) |
| `STWO_RV64_M8_OUTER_LEAF_PERSISTENT` | `0` | `1` = leaves use persistent class regions too (parity fixtures) |
| `STWO_RV64_M8_OUTER_GRAPH` | `1` | `0` = direct enqueue, no CUDA graphs |
| `STWO_RV64_M8_OUTER_GRAPH_THRESHOLD` | 2 | sightings of a (class, placement) key before capture |
| `STWO_RV64_M8_OUTER_GRAPH_BUDGET_MB` | 256 | executable device budget per worker (LRU eviction) |
| `STWO_RV64_M8_OUTER_GRAPH_IDLE_REQUESTS` | 4 | requests a key may go unused before it is dropped (0 = never) |
| `STWO_RV64_M8_OUTER_FAULT_ORDINAL` | unset | test hook: fail node n where a footprint refusal returns (requires `STWO_RV64_M8_FAULT_INJECTION=1`, else service start fails) |
| `STWO_RV64_M8_OUTER_CLASS_PLAN` | `0` | `1` = per-class plans (outer_class_plan.zig): leaf statics cached by authority identity, initWhole's stream schedules / composition stream / PCS framing built once per class and borrowed by every node |
| `STWO_RV64_M8_OUTER_CLASS_PLAN_HOST_MB` | 65536 | host-byte budget of cached class statics (a class over it stays per node) |
| `STWO_RV64_M8_OUTER_DEVICE_CHECKS` | `0` | `1` = device `lookup_sum` check (outer_checks.cu) at the end of every whole node body; finish requires its verdict and the host reference to agree (needs an addon with `stwo_rv64_outer_lookup_sum_check_v1_on`) |
| `STWO_RV64_M8_OUTER_CHECK_FAULT_ORDINAL` | unset | negative test: node n's device check gets one corrupted public limb and must reject (request fails closed); requires `STWO_RV64_M8_FAULT_INJECTION=1`, else service start fails |
| `STWO_RV64_M8_FAULT_INJECTION` | `0` | second key of every fault-injection knob above (a leftover ordinal alone never corrupts production requests) |

Every `STWO_RV64_M8_OUTER_*` knob is read and parsed once per process (outer_env.zig) and frozen; per-node inits read the frozen value.
