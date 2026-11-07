# gn-truth: truth proofs published from the device (device OODS check + device encoder)

Branch `codex/rv64-m8-gn-truth` (from `origin/codex/rv64-m8-gpu` @ b289b021f). Labels [M] measured / [D] derived / [E] estimate.

## What landed
- `jobs/truth_oods.zig` + `NAT/rv64/jobs/truth_oods.cu`: the truth OODS constraint check on device
  (`stwo_rv64_truth_oods_check_v1_on`, ABI `Io` 128 B, version symbol `stwo_rv64_truth_oods_version() == 1`).
  Per class, at warm, the descriptor holds each truth role's `secure_polynomial_program_v2` (the program the
  AOT truth composition kernel comes from, `truth_domain_fixtures.record`), pruned to the nodes its
  constraints reach and ordered by DAG level, with every mask read resolved to a PCS-image sample index and
  the classic last-anchor polynomial marked. Per proof it reads the PCS samples, the device-gathered
  composition parameters, alpha and the OODS point. One block per role evaluates its DAG level by level, then
  forms its Horner partial; one thread folds the partials, reconstructs the composition value from the
  composition samples (split 2) and writes `Check.truth_oods`, plus a 16-word diagnostic
  [evaluated | extracted]. `evaluate()` is the bit-exact host mirror.
- `truth_job.Stage2.encode = .device | .check | .host`. In `.device` the PCS image stays in the job arena,
  then the OODS check runs and `native_encode.Encoder` (n-stage2's encoder, reused) writes the exact
  `WP.encodePhysical` bytes into the truth's request-slab encoded region (`Check.encode_bounds`). The
  encoder's PCS status and the truth's own `truth_pcs_status` (header and roots) are merged on device into
  `Check.pcs_status` (`stwo_rv64_truth_verdict_merge_v1_on`). `.check` runs both paths and compares them.
  `.host` is r-truth's path, unchanged.
- `truth_class`: the class holds `oods` (descriptor) and `encode` (encoder program), both built from class
  geometry. They live in class-persistent device regions (`Stager.persistent`, counted in `heldWords`).
  `extra_checks` = {truth_root, root_match, truth_oods}. `max_encoded_bytes` = the encoder program's capacity.
- `truth_factory`: stage 2 defaults to `.device`; the views add the truth_oods and encode_bounds words and the
  encoded region of the request slab.
- Contract (additive): `gpu_native.Check.truth_oods = 0x0308`.
- truthRoot for the native seal: truth stage 1 (r-truth, unchanged) writes `Exchange.truthRoot(t)` on its
  GPU and publishes it with `ctx.peer.publish`. Manifest ordinal = cpu_count + t. Stage 2 reads the seal
  digest words [0,8).

## Evidence
- [M] host (laptop, memguard 6 GB): `zig build test-rv64-jobs-truth` passes. The new tests check the
  descriptor mirror against the engine's `evalCompositionPolynomialAtPoint` on random masks over classic
  keccak/chi/xor5 under both policies. They also check that a changed read sample or composition sample
  makes it fire `mismatch`, and that a corrupted header, the point status or a same-level operand is
  refused.
- [M] real blocks on an RTX 5090 (`rv64-m8-truth-parity` v2): the legacy pipeline on GPU 0 records the
  truths, then the TruthJob runs on GPU 1 from the compact inputs, seed and digest only:
  - `parity-6.json` (26235156) and `parity-7.json` (24628607): **14/14 truths byte-identical**, including
    the encoded bytes.
    - Run 0 (`.check`): device bytes == host `encodePhysical` == the pipeline's `truth-<t>.bin`, and the
      device OODS (evaluated, extracted) == the host engine's values.
    - Runs 1 and 2 (`.device`, no host assembly): device bytes == `truth-<t>.bin`, all 6 stage-2 verdicts
      accepted, 1 host wait per job.
  - Families: keccak (log 13/14/17/18), secp_row (add, double), sha256, arith256_mod.
  - Negatives, in `.device`, once per kind and per block: **40/40 fired**.
    - The device faults each fire exactly their own check, and a rejected encode publishes no bytes:
      oods_sample → 0x03080004, oods_composition → 0x03080004, encode_capacity → 0x01040001,
      encode_value → 0x01040004.
    - The r-truth faults each fire exactly their own check, except `parameter_program`: a corrupted gather
      makes the statement itself wrong, so truth_oods correctly rejects too.
- [M] `rv64_gate.sh --stream m8-gn-truth` (default env) **PASS** at c53885fd9. It covers build, unit tests,
  small-block cold + warm proofs byte-identical to the frozen D2 golden, fresh CPU receivers and the negative
  corpus. Summary: `gate-1.json` (`runs/m8-gn-truth/gate-1`). It PASSES again at bc9820a06 (the parallel
  OODS fold): `gate-2.json`.
- [M] after the parallel root Horner (bc9820a06), `parity-10.json` (26235156) and `parity-9.json`
  (24628607): again **14/14 byte-identical** and **40/40 negatives**. The OODS check now takes
  0.18–0.79 ms GPU per truth (separate CUDA-event span), down from up to about 7 ms with a sequential root
  fold.
- Assets: the parity-6/7 runs used `build/m8-gn-truth/addon-2/libstwo-rv64-jobs.so` and the parity-9/10 runs
  used `addon-3`. Both are linked against the frozen m7-combined-residency base (a25cc3b2…), which is
  r-truth's recording recipe. `addon-1` (c2ee537b…) is linked against the shared opt-combined base
  (25d0e62f…). The harness is `zig-out/bin/rv64-m8-truth-parity`. Run dirs: `runs/m8-gn-truth/parity-{6,7,9,10}`.
- One legacy recording (parity-8, 26235156) died in the legacy GPU-0 pipeline with
  `CudaGlobalWitnessFailed` / `CudaAllocationFailed`: the arena overran with 25.75 GB live, and no other GPU
  process was running. The rerun (parity-10) passed. This is a single-GPU legacy-recording flake, not
  TruthJob code.

| per request [M] (CUDA events / host timers; warm run 2, 7 truths; parity-10 / parity-9) | 26235156 | 24628607 |
|---|---|---|
| device OODS + encoder + merge, GPU | **17.6 ms** | **17.7 ms** |
| of which the OODS check, GPU | 3.5 ms | 3.5 ms |
| host assembly it replaces (decode + engine OODS + encodePhysical) | 651.6 ms | 679.8 ms |
| finish host time, `.device` (harness: includes copying the bytes out of the job slab) | 4.9 ms | 5.8 ms |
| stage 1 GPU | 273.1 ms | 350.8 ms |
| stage 2 GPU (incl. the device encode) | 1444.1 ms | 1738.6 ms |
| stage 2 host enqueue (overlaps GPU) | 438.1 ms | 535.5 ms |
| stage 2 host stage (fillTable etc.) | 1.9 ms | 2.1 ms |

The first build used a sequential root fold (parity-6/7, 42 ms/request device): there, keccak took 7.5–7.8 ms
and sha256 10.7 ms per truth.

Per truth, device OODS / OODS + encode GPU [M, parity-10]:

| family | nodes | levels | OODS | OODS + encode |
|---|---|---|---|---|
| keccak | 45,898 | 200 | 0.51–0.53 ms | 2.33–2.46 ms |
| sha256 | 133,523 | 45 | 0.78 ms | 3.64 ms |
| secp_row add | 73,615 | 42 | 0.54 ms | 3.32 ms |
| secp_row double | 47,035 | 42 | 0.42 ms | 2.68 ms |
| arith256_mod | 11,317 | 41 | 0.18 ms | 0.85–0.88 ms |

Encoded capacity per class: 0.57–2.25 MB.

Stage-2 host enqueue by phase [M] (`STWO_RV64_M8_TRUTH_TRACE=1` host_ns, parity-10, warm, 7 truths, 437.6 ms
in total):
- witness + MAIN commit (replay): 197.8 ms
- interaction roles: 102.4 ms
- INTER commit: 95.4 ms
- PCS: 38.7 ms
- composition: 2.1 ms
- device OODS + encode: 0.2 ms

The cost is launch-bound in the per-column commit/role launches. For keccak log 18 alone: MAIN 117 ms, roles
58 ms, INTER 51 ms.

## Finding (opt-combined image, single-GPU legacy recording)
On the shared opt-combined base (25d0e62f), the single-GPU legacy recording run fails in truth stage two, so
the parity recordings use the frozen m7-combined-residency base:
- `STWO_RV64_DEVICE_ARENA=auto`: the 14.75 GB truth composition lease overruns the arena.
  `GPU_ARENA_OVERRUN requested_bytes=14750402976 live_bytes=11417856512`, then `CudaAllocationFailed`.
- 22G: `CudaGlobalWitnessFailed`, `CudaAllocationFailed`.

The process-wide arena size (`STWO_RV64_DEVICE_ARENA` has no per-device form) also caps the job worker on
GPU 1, whose keccak log-18 stage-2 peak is 5.76e9 words.

## Remaining host work (per request, truths)
- Stage-2 host enqueue: 0.44–0.54 s [M], launch-bound (breakdown above). It overlaps the GPU (stage 2 GPU
  1.44–1.74 s) but is host CPU on the request path. Fixes:
  - drop the MAIN replay by retaining stage 1's MAIN over the seal (−198 ms host, −273–351 ms GPU, at the
    cost of MAIN residency);
  - a whole-job graph capture per class, or batched per-tree commit launches (native_commit.zig, native
    stream).
- Per-job host table (`fillTable`: scripts, spans, programs, PCS expectation): 1.9–2.0 ms [M]. The static
  words could be class-cached.
- Compact input packing from the capture advice, and the stage-2 seed (worker_protocol.begin: a few Blake2s).
  Not timed.
- Stage 2 replays the witness + MAIN commit that stage 1 already ran: 273–350 ms of GPU per request [M],
  duplicated GPU work rather than host work.
- Finish in the GPU-native factory path reads nothing; publication reads the request slab after the single
  D2H. The ~5.5 ms [M] above is the harness's own job-slab copy.
