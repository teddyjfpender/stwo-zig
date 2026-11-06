# native-finish-p3 (B4) receipts

Stream `codex/rv64-m8-native-finish-p3`. Everything is default-off; the job path is still not selected by any request.

## Landed: enqueue-only native composition (`jobs/native_composition.zig`)

- **What it is.** A port of the deployed native configuration of `resident_composition.zig` `Job.run` onto `api.Enqueue`: enqueue mode, direct + compact (el-2) LDE, staged addressed LDE, `hc` and last-anchor auxiliary columns, the finish kernel, and the beta-2 compact commit with one Merkle segment. It uses the same kernels and the same per-role arena layout as legacy.
- **Custody.**
  - The composition coefficient powers alpha^0..alpha^(total-1) are computed on the device from the device alpha (`NAT/rv64/jobs/native_composition.cu`, `stwo_rv64_jobs_native_powers_v1_on`).
  - The root goes to a slab field and is not mixed: Stage2 mixes it.
  - There is no join, no lease and no D2H. The sync lint covers the file.
- **Role specs.** `rv64/m8_native_composition_roles.zig` builds them outside `jobs/`, because it reads legacy kernel metadata:
  - `fromItems` covers CPU segments;
  - `fromTruth` covers truth/service compositions (classic and delegated, truth kernel);
  - `fromItemsWith(..., device_claims = true)` turns the ram/kio/wire claim parameters into `ClaimSlot`s. These are zeroed in the staged table and patched on the device from a claims buffer (`Plan.enqueueWithClaims`).
- **Stage2 integration.** `NativeStage2` binds the producer through `Composition` / `NativeComposition`. The seam now receives the FIXED, MAIN and INTER coefficient views.

### Real-block parity [M]

Run as `rv64-m8-native-parity` with `STWO_RV64_M8_PARITY_ONLY=composition`. Legacy runs on GPU0 and the job worker on GPU1. Legacy inputs are peer-mirrored into the job arena, and FIXED (host) columns are staged.

| block | segments | root == legacy | coefficient words == legacy | host waits/job | receipt |
|---|---|---|---|---|---|
| 26235156 | 4/4 | 4/4 | 4/4 (0 mismatches) | 1 | `composition-parity-26235156.json` (run `parity-5`) |
| 24628607 | 7/7 | 7/7 | 7/7 (0 mismatches) | 1 | `composition-parity-24628607.json` (run `parity-6`) |

`job_wait_ns` is host wall time of the worker's single event wait. It includes the harness peer-mirror copies (thousands of columns from GPU0), so it is **not** GPU time for the composition. No CUDA-event GPU time is claimed here.
