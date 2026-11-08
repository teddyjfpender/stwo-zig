# RV64 M8 job architecture: replacing the owner-callback layer with an enqueue-only, GPU-resident job runtime

Status: architecture spec (2026-11-06). It is the build contract for the M8 architecture streams.
Plan of record: `rv64-frontier-gpu-delta.md` §4 on `codex/rv64-4gpu-realtime-design`.
Base: `codex/rv64-m7-integrate` @ `5a93c2449`.

This is an architectural replacement, not a tuning pass. Every numerical kernel stays. What gets replaced is the layer between the request and the kernels.

---

## 1. What we replace, and why

**Today** (mapped at `5a93c2449`) every GPU stage takes the same blocking path:

> host thread → `stwo_rv64_gpu_session_submit` → that session's single C++ owner `std::thread` (`NAT/rv64/pcs_native.cu:495` `Service`) runs a `callconv(.c)` callback → **full lane join** (`stwo_exec_context_sync`) → the caller's condition variable wakes.

The coupling has four parts:

1. **One job slot per session, a join after every callback,** and leases that only the owner thread may allocate (`pcs_native.cu:788-945`).
2. **Synchronous stage vtables that return host values:** `prover_api/device_pcs.zig` `D.Stage` / `D.TraceCommitStage`, `NumericalStage`, `ResidentOm31Stage`, `DeviceGlobal.Stage`, `Device.Factory`/`Source`.
3. **The generic host `ProverEngine`** (`prover/prove_family.zig`, `prover/pcs/scheme_family.zig`) runs Fiat–Shamir on the host `raw_mod_m31.Om31Channel` between every stage:
   - roots come back to the host and are mixed there;
   - z, α, the composition coefficient and the OODS point are drawn on the host;
   - GKR's device channel is thrown away and re-derived by host `partiallyVerifyBatch` (`gkr_local/child.zig:177-192`);
   - PCS takes a host-built 17-section request (`pcs_native.zig` `prepareRequestWithFraming`), and its device channel state is decoded back into the host channel.
4. **Admission and permit machinery** layered on owner callbacks.

**Measured cost** on 24628607 [M]:
- the native window is 4.7 s at 39% / 61% GPU busy;
- recursion after native is about 5.7 s at about 52–54% busy;
- about 105 blocking calls and about 1.8k launches per recursion node;
- the GPU sits idle wherever the host is preparing the next stage: device 0 2.2 s and device 1 1.3 s with no work queued, plus barrier and admission holds.

**Target model** (Airbender `main` and `v3`, ZisK):
- a whole proof is enqueued and the host waits once;
- the transcript lives on the device;
- proof fields go into a device slab with one readback;
- one proof per GPU, with the next one's inputs staged in a 3-stage per-GPU pipeline;
- memory is planned statically.

---

## 2. Reuse inventory (unchanged by this architecture)

| piece | location | reuse |
|---|---|---|
| rv64 numerical kernels `stwo_rv64_*_on(ctx, lane, …)` (GKR, batch, sumcheck, binding, global, composition roles, trace tree/open, deep, samples, fri, channel, queries) | `RC/abi.zig`, `runtime_api.zig`, `NAT/rv64/*.cu` | as is. They are enqueue-only; custody uses `stwo_exec_context_validate_allocation` (needs only the exec context) |
| stream-level stages `stwo_*_on(..., stream)` (LDE, Merkle, PoW, FRI fold, transcript) | `backends/cuda/abi/stages/*`, `NAT/{transform,commitment,pow,fri,transcript}` | as is |
| exec context runtime (create, lanes, async memcpy, memset, `alloc_u32`, dependency record/wait, graph capture) | `NAT/runtime/context.cu` | as is; the worker owns one context per GPU. `stwo_exec_context_sync` is no longer called on the hot path |
| **native device OM31 channel**: 16-word state, mix = `blake2s(digest‖words)`, draw = `blake2s(digest‖draws‖0)` with `reduce_m31_word` per word (byte-equal to the host raw-mod channel), queries, PoW, step/chain ordering checks, status latch, boundary snapshots | `NAT/rv64/channel.{cu,h}`, `RC/channel.zig` | **the device channel for every stage.** `reserved` must be 0 (raw digest) |
| outer FS helpers `stwo_rv64_outer_fs_lookup_params_on`, `stwo_rv64_outer_fs_powers_on` | `NAT/rv64/outer_fs_ops.h` | as is |
| circuit assignment chain/wide/graph APIs | `NAT/rv64/circuit_fill_chain.cu` | as is |
| PCS pipeline kernels | `NAT/rv64/pcs_pipeline.cuh` | kernels reused. The synchronous `run()` wrapper (internal syncs at `:452`, `:718`, final readback `:818-857`) is replaced by an enqueue-only variant that reads its challenge inputs from device memory and writes proof fields into the slab |
| `ready_dag` Plan/Queue | `rv64_recursion/ready_dag.zig` | reused for the request DAG |
| capture / emulation, compact records, `EarlySegments` | `GE/ethereum/*` | unchanged in this architecture pass |

**Shipping without rebuilding the 1.98 GB image.** New CUDA lives in an addon library, `libstwo-rv64-jobs.so`, linked against the frozen base image's exported symbols (`stwo_exec_context_*`, kernel entry points) and loaded with `STWO_RV64_M8_JOBS_LIBRARY`. This follows the `libstwo-rv64-outer-fs-ops.so` precedent (`device_fs_check.zig:32`).

---

## 3. Components

All new Zig lives under `src/integrations/riscv_cuda/rv64/jobs/`. New CUDA lives under `src/backends/cuda/native/rv64/jobs/` and builds into `libstwo-rv64-jobs.so`.

### 3.1 `jobs/api.zig`: the contract every stream codes against

Owner: stream **runtime**. It must exist before anything else lands.

```zig
pub const Placement = enum { bottom, top };          // alternated per job, Airbender style
pub const DeviceBuffer = struct { ptr: [*]u32, words: usize };

/// One per GPU. Owns the exec context (created on the worker thread, so it is the context owner),
/// an exec stream (lane 0), an h2d stream, the static arena view, and pinned host pools.
pub const DeviceWorker = opaque {};

pub const Stager = struct {            // phase 1: inputs for job k+1 (h2d stream)
    worker: *DeviceWorker,
    placement: Placement,
    pub fn alloc(self: *Stager, words: usize) !DeviceBuffer;              // arena, placement side
    pub fn upload(self: *Stager, dst: DeviceBuffer, src: []const u32) !void; // pinned → device, async on h2d
    pub fn pinned(self: *Stager, words: usize) ![]u32;                    // job-lifetime pinned host memory
};

pub const Enqueue = struct {           // phase 2: the whole proof on the exec stream; no host waits
    worker: *DeviceWorker,
    placement: Placement,
    channel: *DeviceChannel,           // device-resident transcript for this proof
    slab: *ProofSlab,                  // device proof buffer for this proof
    pub fn ctx(self: *Enqueue) *anyopaque;                                // native exec context for *_on kernels
    pub fn stream(self: *Enqueue) *anyopaque;
    pub fn alloc(self: *Enqueue, words: usize) !DeviceBuffer;             // stream-ordered arena allocation
    pub fn free(self: *Enqueue, b: DeviceBuffer) void;                    // stream-ordered: legal immediately after enqueue
    pub fn hostFn(self: *Enqueue, f: HostFn) !void;                       // cudaLaunchHostFunc; pure host compute → pinned only; no CUDA calls
    pub fn waitStaged(self: *Enqueue) !void;                              // exec waits on the h2d event of this job's inputs
};

pub const Job = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        class_key: *const fn (*anyopaque) [32]u8,                         // for key affinity and class-plan caches
        footprint: *const fn (*anyopaque) Footprint,                      // from the class memory plan (static)
        stage: *const fn (*anyopaque, *Stager) anyerror!void,             // phase 1
        enqueue: *const fn (*anyopaque, *Enqueue) anyerror!void,          // phase 2
        finish: *const fn (*anyopaque, SlabView) anyerror!void,           // phase 3: after the single event wait
        abort: *const fn (*anyopaque) void,
    };
};
```

**Rules, enforced by tests:**
- `enqueue` must not call `stwo_exec_context_sync`, `cudaStreamSynchronize`, `cudaEventSynchronize`, any D2H that the host reads, or any lease API.
- Host steps that remain go through `hostFn`. They write pinned memory only and make no CUDA calls.
- Preflight happens in `stage`, so `enqueue` cannot fail halfway for resource reasons.
- A **sync lint test** fails if any function reachable from `Job.enqueue` references the sync symbols.

### 3.2 `jobs/worker.zig`: `DeviceWorker` and its 3-stage loop

Owner: **runtime**.

- **One OS thread per GPU** creates an exec context (`stwo_exec_context_create_options`, 1 lane), an h2d stream and pinned pools. It uses the existing static arena.
- **The loop** (Airbender `gpu_worker.rs:94-379`, `v3 execution_prover/src/workers/gpu.rs:122-180`):

  ```
  stage(job[k+1], placement = alt(k+1))
  enqueue(job[k])
  event_sync(job[k-1]); finish(job[k-1])
  ```

  Placement alternates between top and bottom.
- **No admission, no permits, no leases.** Memory fit is guaranteed by the class plan's footprint (`Footprint ≤ arena` for one job plus the next job's staged inputs). The plan comes from the measured sweep (§3.7). Until the sweep lands, the worker refuses a job whose declared footprint exceeds the arena, rather than waiting.
- **The worker owns the only host wait:** one `cudaEventSynchronize` per job, plus one pinned D2H of the slab. Both are recorded in the job receipt.

### 3.3 `jobs/channel.zig`: `DeviceChannel`

Owner: **runtime**.

- A device buffer holding the 16-word `NAT/rv64/channel.h` state, plus the existing step/chain protocol. Operations enqueue kernels:
  - `initFromCheckpoint`;
  - `mixWords(device ptr)` and `mixRootFromTree(device root ptr)`;
  - `drawSecureFelts(n, device out)`;
  - `drawQueries`, `pow`;
  - `snapshot(slab offset)`.
- **Roots are mixed straight from device tree buffers.** They never go to the host.
- **Parity harness** (`jobs/channel_parity.zig`, also used as a test): run the old host-engine path and the job path on the same block, compare every boundary snapshot word for word, then compare final proof bytes. This harness is the byte-identity contract for the native and outer job streams.

### 3.4 `jobs/slab.zig`: `ProofLayout` and `ProofSlab`

Owner: **runtime**.

- **`ProofLayout`** is computed from class geometry and the PCS profile before enqueue. It holds byte offsets for every proof field: roots, claims, sampled values, FRI layer roots and last layer, PoW nonce, query values and paths, GKR sections.
- **Kernels write fields into the slab directly** (D2D copies for roots; PCS and GKR kernels take slab pointers).
- **`finish`** does one pinned D2H of the slab plus an `encodePhysical` that produces exactly today's proof bytes (Airbender v3 `circuit_prover/src/proof/orchestration/terminal.rs`).

### 3.5 Jobs (stream **native-job** for 1–3, stream **outer-job** for 4)

1. **`NativeStage1Job`** (per CPU segment):
   - witness source (existing contributors' kernels, without their joins);
   - FIXED adoption (device tree root);
   - MAIN commit (`trace_commit` kernels, root mixed on device);
   - local GKR (existing device channel and commands, **with the channel kept**; no host `partiallyVerifyBatch`; the GKR section goes into the slab).

   It publishes the stage-1 root. The global inventory and seal stay a host barrier over the slab roots, and now need only `finish` outputs.
2. **`NativeStage2Job`** (per CPU segment, after the global χ):
   - binding;
   - global interaction (claims stay on device, `publicClaims` computed in a device reduction);
   - INTER commit;
   - composition (coefficient drawn on device);
   - OODS (point drawn on device; a new small kernel builds sample and mask points from challenge-independent mask offsets);
   - the **enqueue-only PCS** (§2) writing into the slab.
3. **`TruthJob`:** the same shape for truth/service proofs (`truth_source`, `truth_composition`, `truth_pcs` kernels).
4. **`OuterNodeJob`** (leaf, fold, root):
   - `stage` uploads the prepared assignment inputs. Host graph/tape preparation becomes the job's *pre-stage* on a host pool, ahead of phase 1, which is how prep latency gets hidden.
   - `enqueue` sequence:
     1. MAIN assignment (chain runs, or one captured CUDA graph per class);
     2. TC MAIN;
     3. channel: statement and outputs, FIXED, MAIN;
     4. z, α on device → `outer_fs_lookup_params_on`;
     5. INTER;
     6. `lookupSum` on device (status word in the slab);
     7. claims mixed on device;
     8. TC INTER;
     9. composition powers (`outer_fs_powers_on`) → RC;
     10. OODS on device;
     11. PCS (enqueue-only).
   - **Per-class CUDA graph capture of the whole enqueue sequence,** once each class is warm (ZisK `cuda_graph_cache.cuh`: threshold, memory budget, blacklist; pointer rebind per node). Target ≤ 50 launches per node.

### 3.6 `jobs/scheduler.zig`: request DAG to workers

Owner: **runtime**.

- **The DAG** comes from `ready_dag.Plan`. Native stage-1 jobs are created per segment as capture releases it. The host barrier (seal) runs when all stage-1 `finish` calls are done. Then stage-2 and truth jobs, leaves on each native completion, folds on children.
- **Placement:** key affinity first (warm class plan or graph), then root-critical chain first, then least-loaded worker. One job in flight plus one staged per worker.
- **Filling the native barrier:** truth jobs and the previous request's recursion can be scheduled during the native barrier.
- **Selection:** `STWO_RV64_M8_JOBS=1` routes the whole `combined-serve` request through the job runtime. Unset means today's path, unchanged.

### 3.7 Memory plan

Owner: a later stream; in this pass, runtime provides the hooks.

- `Job.footprint` is the class plan's static peak.
- The sweep tool and generated per-class policy (delta §4 item 3) plug in here. So do the memory techniques (item 4: partial or leafless Merkle trees, in-place coset switching, non-resident setup).

---

## 4. Byte identity and acceptance

- **The job path must produce byte-identical proofs on both dev blocks** against the frozen D2 golden. The job path performs exactly the same transcript operations as today, in the same order, so this is a correctness requirement, not an aspiration.
- `rv64_gate.sh` with `STWO_RV64_M8_JOBS=1` (gate option `--env`, added by runtime), plus the channel parity harness.
- Fresh CPU receivers and the negative corpus stay unchanged (the proof format doesn't change).

## 5. Expected effect [E]

| | today [M] | job path [E] | why |
|---|---|---|---|
| Native window, 24628607 | 4.7 s | ~2.5 s | no per-stage joins or readbacks; stage 2 doesn't wait on host FS; witness/source joins removed |
| Recursion after native | 5.7 s | ~3–3.5 s | about 105 blocking calls per node → 1; host prep moved ahead into pre-stage; graph replay per class |
| Request | 12.9–13.1 s | ~8–9 s | before memory/capture work |

Later passes (memory plan, capture streaming, GPU witness widening, Poseidon2 leaves, fewer leaves, 4 GPUs) build on this runtime.

## 6. Streams for this pass (disjoint ownership)

| stream | owns | delivers |
|---|---|---|
| **runtime** | `rv64/jobs/{api,worker,channel,channel_parity,slab,scheduler,lint}.zig`; `NAT/rv64/jobs/{runtime,channel_ops,slab_ops}.cu`; the addon build script; the gate `--env` option; the `combined-serve` switch | the api first, then worker, device channel with parity harness, slab, scheduler, request switch, lint |
| **native-job** | `rv64/jobs/native_*.zig`, `rv64/jobs/truth_job.zig`; `NAT/rv64/jobs/{pcs_enqueue,oods_points,native_*}.cu` | `NativeStage1Job`, `NativeStage2Job`, `TruthJob`, the enqueue-only PCS (shared with outer) |
| **outer-job** | `rv64/jobs/outer_*.zig`; `NAT/rv64/jobs/outer_*.cu` | `OuterNodeJob`: pre-stage host prep, enqueue sequence, per-class graph capture |

- No stream edits the legacy files beyond a *read-only reuse* of their kernels and helpers. The job path is a new path, not a patch of the old one.
- The legacy owner-callback path stays as the default and as the parity reference until the job path is promoted.
- **Engineering approach:** design and write the code locally against this spec and the reuse inventory (§2), with unit tests for anything pure-host (`jobs/api` contract, layout, scheduler) run locally under `~/Coding/ge-ops/bin/memguard run --gb 6 --`. Use the pod only to compile, run kernel/parity tests and measure.
