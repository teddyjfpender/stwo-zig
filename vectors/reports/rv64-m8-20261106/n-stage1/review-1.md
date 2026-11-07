# n-stage1 review 1 (2026-11-07): findings on 5c4ff5442..24fe62873

Scope: byte identity / transcript order, device acceptance checks gating publication, memory / lifetime / streams / graph
validity, remaining host compute or waits. Fix commit: `f9c709b94` (branch `codex/rv64-m8-gpu-n-stage1`).

## Confirmed and fixed
| # | finding | fix | evidence |
|---|---|---|---|
| 1 | `binding_authority` compared `claims_out` with `claims`, the buffer it had just been D2D-copied from: always equal, detects nothing. The legacy GKR acceptance (`gkr.Header.validate`, `Section.verify` guards) had no device form. | Check ABI v2 (`stwo_rv64_n1_check_v2_on`): up to 4 constant runs in the launch parameters (detail `0x20+i`). binding_authority = closure status, binding verdict, traversal header words [8,20) == `headerGuard(L, count, chain)`, child snapshot words [8,16) == `snapshotGuard(draws, child_steps, child_chain)`. | GPU: constant-run accept + reject `0x02080020` [M] |
| 2 | The post-MAIN main-channel state was job-arena only and lost at job end; legacy Stage 2 seeds from it (`seedOf(worker.channel)` then `mixManifestAndClaims`). | `ResidentLayout.checkpoint` (16 words, after authority); Stage 1 snapshots `e.channel` there; root_match adds its guard (draws 0, cursor, chain, status latch = seed -> FIXED -> MAIN order). | GPU: post-MAIN guard accepts, cursor=2 [M] |
| 3 | Chunk witness runs were bounds-checked only: a gap commits stale (unzeroed) arena words with witness_status accepting; an overlap makes MAIN scatter-order dependent. | `validateCoverage` at `Stage1Job.init` (host, O(R log R) over the run tables already read on the host): exact tiling of the image, refusal before any enqueue. | host test (gap, hole, overlap) |
| 4 | `Registry.warm` reserved `held_words` on `max(1, workers.len)` GPUs: workers are bound at install, so a 2-GPU service budgeted only GPU 0 (FIXED tree + twiddles unplanned on GPU 1). | `Registry.devices`; warm refuses a registered class with no device count; `installed` refuses `info.devices > warmed_devices`. | host test |
| 5 | `WarmJob.init` leaked the GKR host scratch when the inputs alloc failed. | errdefer. | - |
| 6 | Comment claimed only the run table lands in arena memory; the whole chunk (table + data) is copied. | comment. | - |

## Verified, no change
- Transcript order of the prologue equals legacy `native_stage1.zig` (seed, FIXED root mix, MAIN commit + mix); GPU parity of the
  post-MAIN channel vs the host scheme unchanged [M].
- `GpuNativeFixedNotWarmed` on a fresh region cannot poison it: the worker retires fresh keys of a failed job (`worker.zig` finish).
- Ring lifetime: the chunk h2d is enqueued on the exec stream before the driver's `releaseFn` host step (m8_capture_stream.zig).
- Every check kernel is the last op on the exec stream; an enqueue error leaves `unset` words (reject). Peer publication of root/claims
  precedes the checks, which is safe because `publish()` refuses on any non-accepted word.

## Open (not fixable in this piece; reported)
- **No device GKR verifier.** The legacy `NB.checkAuthority` (claims, OOD point, eta vs the host partial verification of the decoded
  proof) and the host replay of the child digest are not on device; binding_authority covers the guards only. The exchanged claims are
  the authority words themselves. The manifest's local-receipt digest (`Child.verifyPending`) is the seal's open item too.
- `root_match`'s MAIN pair (exchange slot vs section MAIN root) is structural (both from the same buffer) - it only catches a later
  overwrite of the slot.
- Full `Stage1Job` (GKR + binding in the job form, main_resident view, exchange) has still not run on a GPU: it needs a real segment
  `NG.Plan` (service wiring: register/setRequest) and a capture that emits chunks. The GPU test drives the prologue + check kernel.
- Per request host work left: `NG.Gkr.init` + items dupe (small allocs), coverage check, two `cudaEventCreate` per job when timing is
  bound. Chunk h2d sources (ring pointers) vary per request, so this job is not graph-replayable as is.

## Measurements [M] (pod 2x RTX 5090; addon `/workspace/m3/build/m8-gpu-n-stage1/addon2`, base m7-combined-residency)
- `zig build test-rv64-jobs -Doptimize=ReleaseSafe`: host 335/341 (6 GPU skips); GPU env 340/341 (1 skip).
- `GPU_M8_N1_PROLOGUE_PARITY fixed_root_equal=1 main_root_equal=1 channel_equal=1 root_match=0x0 witness_status=0x0 cursor_guard_negative=0x2080020 main_cursor=2`
- `GPU_M8_N1_NEGATIVES root_match=0x2080010 witness_status=0x2010001`
- Logs: `/workspace/m3/runs/m8-gpu-n-stage1/r2/{addon2,host-tests,gpu-tests}.log`; gate-2 at f9c709b94 (default path): **PASS** (build, unit-zig, unit-python, small-block proofs byte-identical to the frozen D2 golden, fresh CPU receivers, negative corpus), `/workspace/m3/runs/m8-gpu-n-stage1/gate-2/gate.json`.
