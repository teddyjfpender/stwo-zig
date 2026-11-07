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
- Assets: addon `build/m8-gn-truth/addon-2/libstwo-rv64-jobs.so` (sha256 c39f6328…), linked against the
  frozen m7-combined-residency base (a25cc3b2…), which is the same recording recipe as r-truth.
  `addon-1` (c2ee537b…) is linked against the shared opt-combined base (25d0e62f…). Harness
  `zig-out/bin/rv64-m8-truth-parity` (fd17f3ae…). Run dirs: `runs/m8-gn-truth/parity-{6,7}` (stdout/stderr).

| per request [M] (CUDA events / host timers; warm run 2, 7 truths) | 26235156 | 24628607 |
|---|---|---|
| device OODS + encoder + merge, GPU | **42.2 ms** | **42.1 ms** |
| host assembly it replaces (decode + engine OODS + encodePhysical) | 630.7 ms | 635.8 ms |
| finish host time, `.device` (harness: includes copying the bytes out of the job slab) | 5.4 ms | 5.7 ms |
| finish host time, `.check` (with host assembly) | 637.1 ms | 643.4 ms |
| stage 1 GPU | 272.9 ms | 349.5 ms |
| stage 2 GPU (incl. the device encode) | 1471.4 ms | 1767.0 ms |
| stage 2 host enqueue (overlaps GPU) | 454.7 ms | 558.2 ms |
| stage 2 host stage (fillTable etc.) | 1.9 ms | 2.0 ms |

Per truth, device OODS + encode GPU [M]:
- keccak (45,898 nodes, 200 levels): 7.5–7.8 ms
- sha256 (133,523 nodes, 45 levels): 10.7 ms
- secp_row add (73,615 nodes): 4.2 ms
- secp_row double (47,035 nodes): 3.4 ms
- arith256_mod: 1.0 ms

Encoded capacity per class: 0.57–2.25 MB.

## Finding (opt-combined image, single-GPU legacy recording)
On the shared opt-combined base (25d0e62f), the single-GPU legacy recording run fails in truth stage two, so
the parity recordings use the frozen m7-combined-residency base:
- `STWO_RV64_DEVICE_ARENA=auto`: the 14.75 GB truth composition lease overruns the arena.
  `GPU_ARENA_OVERRUN requested_bytes=14750402976 live_bytes=11417856512`, then `CudaAllocationFailed`.
- 22G: `CudaGlobalWitnessFailed`, `CudaAllocationFailed`.

The process-wide arena size (`STWO_RV64_DEVICE_ARENA` has no per-device form) also caps the job worker on
GPU 1, whose keccak log-18 stage-2 peak is 5.76e9 words.

## Remaining host work (per request, truths)
- Stage-2 host enqueue: 0.45–0.56 s [M], launch-bound. It overlaps the GPU but is host CPU on the request
  path. The fix is a whole-job graph capture per class (the composition roles + PCS launches).
- Per-job host table (`fillTable`: scripts, spans, programs, PCS expectation): 1.9–2.0 ms [M]. The static
  words could be class-cached.
- Compact input packing from the capture advice, and the stage-2 seed (worker_protocol.begin: a few Blake2s).
  Not timed.
- Stage 2 replays the witness + MAIN commit that stage 1 already ran: 273–350 ms of GPU per request [M],
  duplicated GPU work rather than host work.
- Finish in the GPU-native factory path reads nothing; publication reads the request slab after the single
  D2H. The ~5.5 ms [M] above is the harness's own job-slab copy.
