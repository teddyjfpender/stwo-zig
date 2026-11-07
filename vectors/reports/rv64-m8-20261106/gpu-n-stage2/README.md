# m8-gpu-n-stage2: native Stage 2, device seal, device encoding (piece of rv64-m8-gpu-native.md §3.2/§3.5/§3.6)

Branch `codex/rv64-m8-gpu-n-stage2` (from `codex/rv64-m8-gpu` @ 28ae81a58). GPU receipt: `gpu-tests-01.json`.

## Landed (behind the GPU-native path only; default path untouched)
| piece | files | evidence |
|---|---|---|
| device ProofEncoder (H11/H13): exact `WP.encodePhysical(decodeWords)` bytes into the slab region, plus `pcs_status` / `encode_bounds` words | `NAT/rv64/jobs/native_encode_proof.cu`, `rv64/jobs/native_encode.zig` | [M] 8/8 shapes byte-identical, 76/76 faults rejected, 1.07-1.92 ms GPU/proof vs 131-233 ms host (synthetic, segment-scale) |
| device checks (H10): `root_match`, `global_status`, `composition_accept`, `channel_order` (words_zero), `public_claims` (RAM boundary reduction), felt patch | `NAT/rv64/jobs/native_encode_checks.cu` | [M] parity + negatives |
| device seal (H8): m6_v2_gkr chi chain from exchange root slots, `global_seal`, seal slot publish; `drawShared` on device | `NAT/rv64/jobs/native_seal_chi.cu`, `rv64/jobs/native_device_stage2.zig` | [M] chi and 63 shared felts equal the manifest authority |
| Stage2Job / SealJob / Factory / ClassFraming, Stage-1 handoff contract, `native_device.zig` stage2/seal hooks | `rv64/jobs/native_device_stage2.zig` | host type-check only (no end-to-end GPU run yet) |

## Not done (honest)
- `oods_constraint` on device: needs a point-eval instance of the AOT composition codegen. Its word stays `unset`, so publication refuses.
- Stage 2 end to end on real segments: needs n-stage1's handoff regions (checkpoint, binding, semantic) and a warm-built `ClassFraming` per class.
- PCS framing section 15 / scope identity were host-rebound per request on the hybrid path; not yet verified as unused on device.
- Truth MAIN roots have no exchange slot (interface request filed).

## Review 1 (2026-11-07): findings and dispositions
| # | finding (verified against the code) | disposition |
|---|---|---|
| R1 | One shared `ClassFraming` per class was staged/enqueued by every Stage-2 job: `CommitPlan.stage`, `NComp.Plan.stage` and `PcsJob.bindColumn` write per-job state (arena placement, staged table/log pointers, PCS column bindings) into it. The worker stages job N+1 before it enqueues job N (`worker.zig run`), and both GPUs run the same classes, so job N enqueued with N+1's (or the other GPU's) pointers. | fixed: `Factory.Pool` of exclusive instances, leased from `stage` to the end of `enqueue` (released on abort); `instances_per_device = 2` per GPU per class; exhaustion fails closed (`NativeStage2FramingBusy`), never blocks a worker |
| R2 | Per-segment public parameter slots (JP slots < `JP.local`: cpu_steps, pcs, epoch, rows, calls, first ids, source public incl. the sponge first id read by `native_global.fillParameters`) were never patched: they kept the warm-time values in the global parameter vectors and the composition table. | fixed: third patch source `public` (`RequestInputs.public`, `public_felts` x 8 canonical words of the segment statement from capture, host-validated canonical, uploaded with the job); `sourceOf` now maps every non-claims slot |
| R3 | The semantic handoff was retained at `8 * semantic_felts` words although its contract includes the hc rows; hc patches would index past it and the patch kernel silently skips out-of-range entries (fail-open: a stale parameter with every check accepting). | fixed: `ClassFraming.semantic_words` sizes the handoff; `ClassFraming.validate` (called by `Factory.register`) rejects any patch whose source felt or target word is out of range |
| R4 | `Factory.stage2` never set `Stage2Job.seal_device` (default 0): with the driver's `seal_device != 0` every Stage-2 await failed (`GpuNativeExchangeNotPublished`). | fixed: `Factory.seal_device` (= driver `Config.seal_device`), passed to each Stage-2 job; `Factory.seal` refuses another device |
| R5 | `Stage2Job.footprint` left the public_claims scratch (8 + 8 per 256-cell block, up to 4104 words) inside the 4096-word slack. | fixed: sized from `public_scratch(cells)` |
| - | Transcript order vs `native_hybrid_jobs.Stage2Job`: checkpoint, {header 3, chi 8, claims}, INTER root, alpha, composition root, OODS draw, PCS seed: identical; chi is the seal slot (= the hybrid's manifest digest). | no change |
| - | Gating: `oods_constraint` stays `unset` (publication refuses); Stage-1 checks (`witness_status`, `binding_authority`, Stage-1 `channel_order` latch) belong to n-stage1. | open (as before) |
| - | Memory: INTER + composition coefficients stay live through the PCS (the hybrid moved them out of the window first, [M] overrun h11); the footprint sums both, so the planner sizes for it. Revisit when the two-phase plan is measured on real segments. | open |
