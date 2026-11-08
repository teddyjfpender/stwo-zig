# rv64/jobs — M8 job runtime (as built)

Work in the single canonical checkout, `/Users/theodorepender/Coding/stwo-zig`.
These are the three developer entrypoints:

| Purpose | Command |
|---|---|
| Inner loop | `python3 scripts/dev_test.py <changed-paths>` |
| Before every push | `bash scripts/rv64_gate.sh --stream m8-gn-bind --out <new-receipt-dir> --source-commit <sha> --runtime <pinned-runtime.json>` |
| GPU-native regression set | `python3 scripts/rv64_m8_bench15.py run --assets <pinned-assets.json> --out <regression-dir> --arms gpu-native` |

Use `dev_test.py --optimize ReleaseFast <changed-paths>` to reproduce optimized
CI failures. Without an override, focused tests use Debug and package fallbacks
use ReleaseSafe.

CI checks the [RV64 flag registry](../../../../../conformance/rv64-flags.json)
before source-layout baselines are considered. Every declaration names its
source owner, unset default, lifecycle status and review date; references are
generated. New names and changed default expressions require review. The strict
release gate also rejects 60 or more live controls and remaining M7/M8 switches.
Qualification controls count as live; C/CUDA constants do not. Current counts
and outstanding gates are in the
[productionisation receipt](../../../../../vectors/reports/rv64-productionisation/current.json).

Compiles and proof gates currently run in the corresponding frozen pod source
snapshot. Transport must preserve the canonical source identity; do not select
another laptop worktree to build a different component. The gate owns its GPU
lock. The regression command covers the complete basket unless a diagnostic
subset is explicitly selected; subset evidence is not a basket pass.

Spec: `design/riscv/rv64-m8-job-architecture.md`. The current
[resource and development contract](../../../../../design/riscv/rv64-gpu-hygiene.md)
defines ownership, validation and cleanup acceptance. The native request path
is selected explicitly with `STWO_RV64_M8_GPU_NATIVE=1`; it remains default-off.
Legacy construction is still used during installation, and the default path
remains a separately gated reference.

`rv64_combined_ethereum_main.zig` is the dispatch authority. With JOBS=1 and
GPU_NATIVE=1 it calls `driver_ge.serve`, which constructs recursion authorities,
binds native/capture/input factories, and calls `driver_serve.Service.install`.
Installation warms the known classes and reserves the capture ring, request
slabs, worker arena, pinned pools and events. `serveSpool` then routes each
request through `Service.begin` (capture plus driver batches) and `Service.finish`
(completion, checked publication and capture join). Class misses refuse.
Without GPU_NATIVE, `resident_batch.runServe` owns the single-lane reference
path; `JOBS=1` without `GPU_NATIVE=1` fails closed. The feeder, the native
hybrid, the `OUTER_JOBS` request mode and the admission/two-lane ledger are
deleted. The outer node-job hybrid survives only as the class-installation
harvest (`STWO_RV64_M8_GN_INSTALL=1`, set by `native_recursion_install.zig`)
until a fully qualified native installer replaces it.

| file | role |
|---|---|
| `api.zig` | the contract (spec §3.1): `Job`/`VTable`, `Stager`, `Enqueue`, `Footprint`, `SlabView`, `Job.from` |
| `resources.zig` | word units, checked resource declarations, placement and explicit readback policy |
| `arena.zig` | two-sided address/lifetime bookkeeping, independent of CUDA and the prover |
| `job_timing.zig` | worker-owned, two-parity timing event pools; explicit borrowed spans for installed jobs |
| `memory_plan.zig` / `driver_memory.zig` | checked request region totals, offsets and two-phase capacities; no runtime or prover imports |
| `worker.zig` | `DeviceWorker`: one thread per GPU, 1-lane exec context, h2d stream, two-sided arena, 3 pinned slots, 3-stage loop |
| `ops.zig` | device op table: base-image exports + addon exports; `Exec` (enqueue-only) vs `Wait` (worker loop only) |
| `channel.zig` | `DeviceChannel`: Fiat–Shamir on the device over `NAT/rv64/channel.cu` + addon raw draw + PoW |
| `slab.zig` | `ProofLayout`/`ProofSlab`, `encodePhysical`, resident-PCS readback layout (`PcsGeometry`) |
| `channel_parity.zig` | host `Om31Channel` vs device channel at every boundary; `Recorder` (om31_observer) |
| `scheduler.zig` | request DAG → workers; key affinity > root-critical > least loaded |
| `request.zig` | `Provider` seam + spool protocol; per-request `m8-jobs.json` |
| `mod.zig` | `combined-serve` entry: selection, workers, boot self-test and provider |
| `lint.zig` | sync lint: no sync/D2H/lease symbol reachable (file level, transitive) from job sources |
| `fake.zig` | host device model for GPU-free tests (`zig build test-rv64-jobs`) |
| `gpu_native.zig` | GPU-native request contract (`design/riscv/rv64-m8-gpu-native.md`): status words, request slab, peer exchange, class cache, device checks/encoders, memory plan, capture hand-off, factories, `publish` |
| `driver.zig` / `native_device.zig` / `truth_job.zig` | installed GPU-native driver, native segments and truth jobs |
| `outer_device.zig` | installed recursion authority registry and counted class-plan pins |
| `outer_node_job.zig` | per-request node construction, custody, execution and settlement |

CUDA addon: `NAT/rv64/jobs/*.cu` → `libstwo-rv64-jobs.so` (`scripts/rv64_m8_jobs_addon_build.py --base <frozen image>
--out <dir>`), loaded with `STWO_RV64_M8_JOBS_LIBRARY`. ABI version in `ops.zig` = `runtime.cu`.

## Rules a job must follow

- `stage`: preflight everything (resources, geometry); allocate inputs with `Stager.alloc`, fill `Stager.pinned`, `upload`.
  Long-lived class data: `Stager.persistent(key, words)` (fill when `fresh`).
- `enqueue`: only enqueue work: `stwo_rv64_*_on(e.ctx(), 0, ...)` / `stwo_*_on(..., e.stream())`, `e.alloc`/`e.free`,
  `e.channel.*`, `e.slab.*`, `e.hostFn` (pinned memory only, no CUDA). No sync, no D2H, no leases, no legacy owner-path
  imports (the lint fails the build of `test-rv64-jobs`).
- `finish`: a `job_slab` result has pinned `SlabView.words` after completion. A `request_slab` job has an empty
  host view: its device checks and encoder publish to the driver's request slab. Private device scratch is still
  allocated and charged in both modes. The view is valid
  only during `finish`: the pinned slot is reused three jobs later, so copy out what later steps (seal, leaves) need.
- `footprint`: `resources.Footprint` owns checked word arithmetic and host-mirror sizing. A measured policy may
  increase a fitted device declaration; the resolved footprint must validate before staging. Oversize jobs fail closed.
- `HostFn` declares whether a queued callback computes or releases capture input. Synchronous cancellation uses
  `HostAction`, a separate type. Driver receipts distinguish callback purposes, private slab D2H and final slab D2H;
  these counters exclude CUDA's peer transport and are not a substitute for the CUPTI census.

Timing pairs are reserved on the owning worker during installation and reclaimed after quiescence before context
destruction. Installed Stage-1 jobs borrow by the actual free request slot parity and segment ordinal; an unreserved
pair or parity mismatch fails. Standalone component jobs can explicitly own their timing spans. Request generations
are identifiers, not storage parity. Event-pool growth rolls back only newly created handles on partial failure.

Request region accounting rejects overflowing words, aligned sizes, byte sizes and capacity sums. The same checked
`MainCursor` places each segment's MAIN view in the actual request path and validates sequential layouts in the pure
planner. Invalid layout sizes fail before offsets are published; malformed class reservations refuse installation
before request device allocations or events are created.

The strict CPU receiver compares exported root/tree files with freshly reconstructed bytes using a fixed-size
buffer and an explicit EOF check. It reads at most the expected length plus one byte, accepts only exact equality,
and allocates no artifact-sized mirror. Truncated, changed and longer files all fail the artifact binding check;
missing files and I/O errors remain distinct. This closes the old V04 read-limit ambiguity without raising a cap
or changing proof bytes. `scripts/dev_test.py` routes the publication module to the CPU package's small
`test-recursion-publication` target, including compile-only checks.

With `STWO_RV64_NVTX=1`, enqueue-only ranges name native/truth Stage 1 and 2, seal, and leaf/fold/root jobs as
`rv64/gpu/<stage>/<ordinal>`. Symbols load once when opening the op library. The runtime supports a single range
per context, so inner node bodies do not nest ranges. `rv64_m7_gpu_seconds.py` reports these as host ranges and
counts contained CUDA calls by the owner thread; it does not interpret their duration as GPU time. Missing ranges
are `NOT_INSTRUMENTED`; missing tables are `UNAVAILABLE`; incomplete ranges are `PARTIAL`.

## Memory model

Staged inputs of the job on side S sit at the S end of the arena; its enqueue allocations grow from there toward the
other end, bounded by inputs staged on the other side. All enqueued work shares one exec stream, so successive jobs may
reuse addresses; the h2d stream waits (on the device) for the most recently enqueued job before writing a side. Arena
ranges are 256-byte aligned and validate against the exec context's ledger (one registered allocation).

## Outer job (OuterNodeJob, hybrid recursion)

| file | role |
|---|---|
| `outer_job.zig` | `OuterNodeJob`: one leaf/fold/root node as an api.Job (stage/enqueue/finish), footprint, held buffers, PCS tail |
| `outer_result.zig` | host-observed status, canonicality and lookup-sum validation; separate from device publication |
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

## Development and evidence

Use `scripts/dev_test.py --dry-run <changed-path>` to see the selected
package-owned test. Resource/arena edits select `test-rv64-resources`; worker,
driver and channel edits select `test-rv64-jobs-runtime`; node result/lifetime
edits select `test-rv64-jobs-node`. Recursion registry and request-custody edits
select `test-rv64-jobs-recursion`, which exercises the two in-flight parities,
peer-child seed construction, request verdicts and pin ordering. These host
tests do not require a GPU.
`--check` selects the same roots without executing their tests. Native, truth
and outer routing follows the imports of their owned component test roots. Unknown
paths retain the complete package fallback rather than reporting empty success.

Run compiles in the synced pod tree under a build lock. Full-proof regressions
use `scripts/rv64_gate.py`; matched timing uses
`scripts/rv64_m7_integration_stack.py`. Both and the basket share
`scripts/rv64_validation.py` for artifact pins and fresh CPU acceptance.
`PASS_WITH_LIMITATIONS` records nonsemantic negative-test rejections explicitly;
it exits with code 3 and is not a green semantic gate. `PASS` exits with code 0.
Corpus acceptance requires the exact receiver pin, CPU/cache isolation, complete executable cases, a matching
positive-control statement, clean rejection exit codes and error-backed rejection classifications. Missing or
contradictory verdict evidence fails even when a row claims `passed=true`. The harness and validator share rejection
classification; an absent error is unclassified. Gates may attach Nsight to those same correctness requests with
`--nsys --nsys-root <raw-filesystem>` and `--env STWO_RV64_NVTX=1`; profiling does not qualify their latency.
Library validation runs on the effective environment after overrides merge, including `LD_PRELOAD`. Every library
must resolve to a declared pinned asset. Gates and service comparisons recheck asset hashes after execution, so
changing a binary during a run cannot leave a valid pin receipt.

The worker remains above the source-size ceiling. Its decomposition boundaries
are: pure arena bookkeeping (extracted), persistent class-region ownership,
ordinary three-slot pipeline, GPU-native batches, and thread/control lifecycle.
Move an owner with its invariants and tests; do not spread mutable worker state
through forwarding wrappers. `outer_job.zig` now separates result decoding and
the heap's execution adapters, and uses one held-buffer schedule for budgeting
and allocation.

Other inherited oversized owners remain explicit decomposition work: `driver_request.zig` should separate installed
lane resources from in-flight request state and publication; `gpu_native.zig` should separate class/cache ownership
from request slab/layout contracts; native Stage 1 and 2 should separate installed class construction from request
jobs; `truth_job.zig` has the same class/job boundary. Recursion now separates installed
registry ownership (`outer_device.zig`) from the node construction/custody/execution
owner (`outer_node_job.zig`). Registration reserves both registry maps before
publishing either entry, and quiescent teardown destroys request bodies before
releasing class pins. This change adds only parity/trace/receipt wiring to those owners, except
for extracting Stage-1 timing ownership. Their small net growth keeps those invariants at the existing owner until
a complete boundary can move with tests. No source ceiling or conformance baseline is increased.
