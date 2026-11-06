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
