# native-finish-p3 receipts

Stream `codex/rv64-m8-native-finish-p3`. Everything here is default-off. **No request reaches the job path yet:** `jobs/mod.zig provider()` still returns `M8RequestProviderNotLanded`, so `STWO_RV64_M8_JOBS=1` fails closed exactly as on integrate. This landing covers the producers of deliverable 1 (spec §3.5 items 1–2: binding, composition, OODS, PCS), each byte-identical to legacy on real blocks. Deliverables 2–4 (witness source without joins, TruthJob, `request.Provider`) are **not started**; see "Remaining" below.

## What landed

| producer | file | what it does |
|---|---|---|
| local Eq/prefix binding | `rv64/jobs/native_binding.zig`, `Stage1.enqueueWithBinding` | A port of `device_binding_runtime.zig` `.project` + `.finalize` onto `api.Enqueue`. It runs as the Stage1 job's tail, right after the GKR traversal on the same stream. Per instance it enqueues binding metadata from the device GKR state (OOD point, claims and the eta seed from the child channel digest), then P = N + eta·D, Eq, finalize, the prefix scan and b2n. The output is 16 coefficient columns per instance (`[Eq 8 \| prefix 8]`), and the verdict word goes to the slab. There is no host artifact or eta, no join, no lease and no D2H. |
| composition: claim slots | `native_composition.zig` `ClaimSlot`, `Plan.enqueueWithClaims` | The ram/kio/wire claim parameters are zeroed in the staged table and patched on the device from a device claims buffer (8 words per claim), so claims produced on the device never round-trip through the host. |
| composition: truth roles | `m8_native_composition_roles.zig` `fromTruth` | Truth/service compositions (classic with the last anchor, and delegated) go through the same producer and use the truth kernel. |
| OODS + PCS | `native_pcs.zig` `enqueueOpening` (existing, now real-block verified) | The device draws the OODS felt, builds the OODS and base points on the device, and runs the enqueue-only PCS seeded from the device state. The framing is built at a placeholder point, so it is challenge independent. |

## Real-block parity [M]

Run with `rv64-m8-native-parity` on source `HEAD` of this branch, build 8. Legacy runs on GPU0 and the job worker on GPU1. Legacy device inputs are peer-mirrored into the job arena.

| check | 26235156 | 24628607 | receipt |
|---|---|---|---|
| Stage1 job (FIXED, MAIN, local GKR, **binding**): roots, channel, GKR proof | 4/4 | 7/7 | `binding-stage1-parity-<block>.json` |
| binding columns (per-instance trace-tree root of the 16 columns vs legacy `Owner.finalize` columns), verdict 0 | 4/4 (30–35 instances) | 7/7 (25–36 instances) | same |
| global interaction (claims, verdict, INTER witness) / INTER and MAIN roots | 76/76 slots, 8/8 roots | 127/127 slots, 14/14 roots | same |
| composition with **device claim slots** (root and all coefficient words) | 11/11 (4 CPU, 3 truth-classic, 4 truth-delegated) | 14/14 (7 CPU, 3 + 4 truth) | `composition-parity-<block>.json` |
| OODS point + enqueue-only PCS (decoded proof and post-PCS channel vs legacy PCS) | 11/11 (4 CPU, 7 truth) | 14/14 (7 CPU, 7 truth) | `pcs-parity-<block>.json` |

Every job has exactly 1 host wait.

### GPU time per job (CUDA events, GPU1) [M]

| span | 26235156 | 24628607 |
|---|---|---|
| Stage1 enqueue (FIXED + MAIN commit + local GKR + binding; mirrors excluded) | 179–249 ms | 135–203 ms |
| binding alone (separate run, parity-13/15 harness) | 21–25 ms | 15–23 ms |
| composition, CPU segment | 52–59 ms | 30–59 ms |
| composition, truth-classic | 27–463 ms (first is cold) | 40–460 ms |
| composition, truth-delegated | 0.4–28 ms | 0.4–28 ms |
| OODS + PCS, CPU segment | 137–147 ms | 71–152 ms |
| OODS + PCS, truth | 6–140 ms | 3–139 ms |

**Host wait per job** (wall clock of the worker's single event wait, after enqueue returns):
- Stage1: 15–35 ms
- PCS: 3–158 ms

These are per-job numbers from a parity harness that runs one job at a time next to legacy. **They are not a native-window measurement.** No native-window number is claimed: there is no request path yet.

## Findings

- **Legacy buffer lifetime.** The legacy PCS is the last consumer of its trees, so a parity job must read them **before** the legacy call. Reading after the call raced with recycling: an illegal peer read poisoned GPU1 and produced the false `NativePcsTreeRootMismatch` and `CudaEnqueueFailed` rows in the superseded runs 16/17.
- **Memory headroom outside the arena.** The legacy global-interaction kernels reused by `native_global.zig` need device memory **outside** the job arena. With a 23 GiB arena on 24628607, 10/127 slots failed with `CudaEnqueueFailed`; with 20 GiB all 127 pass. The memory plan must leave this headroom, or the scratch must move into the arena.
- **Parked bindings.** On 24628607 legacy parks and replays bindings. The harness wrapper unwraps the owner for `replay_binding`.

## Remaining (precise)

1. **Stage2 end to end in one real-block job.** Every Stage2 producer is now real-block byte-identical on its own: binding, global, INTER commit, composition, OODS and PCS. `Stage2.enqueue` chains them on one device channel, and that chaining is verified only on the GPU fixture (`native_stage2_test.zig`). A real-block single-job run is not done yet: it needs the Stage1→Stage2 device handoff.
2. **Cross-job retained device memory, Stage1 → seal → Stage2.** This is an `api` addition, owned by runtime. MAIN coefficients and binding columns must outlive the Stage1 job across the global-χ barrier. `Stager.persistent` is class-keyed and LRU-evictable, so it is not a safe carrier.
3. **Witness source without joins** (device_source / core_witness / cpu_projection, about 1.5k legacy lines): not started.
4. **TruthJob** (truth_source / truth_composition / truth_pcs): composition and PCS are verified; source and job assembly are not started.
5. **`request.Provider`** (`jobs/provider.zig`, `mod.zig provider()`): not started. Recursion is to be delegated to legacy. Until it lands, `STWO_RV64_M8_JOBS=1` fails closed.
