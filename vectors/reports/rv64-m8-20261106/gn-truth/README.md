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
| host assembly it replaces (decode + engine OODS + encodePhysical; run 0 `.check` only, i.e. first run, serial sum over the 7 truths — see review note) | 651.6 ms | 679.8 ms |
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

## Review (2026-11-07, commit 7c38e67e2)
Checked against the code: transcript order (the device OODS check and encoder run after the PCS and draw
nothing from the channel), the kernel's descriptor validation, the parameter source (the device gather from
the transcript felts, which `truth_status` checks), the verdict merge (unset propagates as a reject), and
publication gating. `truth_oods` is in `Class.extra_checks`, and `encode_bounds` and `pcs_status` are in
`requiredChecks(.truth)`, so every device check gates publication. The encoder checks that samples and
queried values are canonical.

Fixed:
- **Anchor read in an unanchored role** (`truth_oods.cu` + mirror): the kernel writes `anchor_words` only
  when `row.anchor` is set. An `Op.anchor` node in any other role would read shared memory nobody wrote,
  while the mirror returned zero. Both now refuse this as `descriptor`, and there is a new unit test. Valid
  descriptors are unaffected.
- **Device-phase footprint** (`stage2Footprint`): the default arena is LIFO (`reuse_frees` off). In
  `.device` the PCS image is allocated after the tree coefficients, so the coefficients stay resident under
  the OODS and encoder scratch. The phase now counts them. The declared value does not change, because
  `phase_pcs` still dominates (parity-13 declared words equal parity-10's).
- `.check` together with a request-slab region is refused: the region leaves no bytes to compare.
  `Factory.bytes()` is documented as null in `.device`.

Re-test [M] (`parity-13.json`, 26235156, addon-5 = 7c38e67e2 linked against m7-combined-residency,
`LEGACY_ARENA=auto` as in parity-10): **7/7 truths byte-identical** (`.check` and `.device`), **20/20
negatives fire**, device OODS + encode 17.6 ms GPU per request (OODS alone 3.5 ms).
(`LEGACY_ARENA` defaults to 22G in `parity.sh`. With that default the job worker requests its full 22G
arena from a 22G process arena and fails at once with `GPU_ARENA_OVERRUN`. Use `auto`.)

Gate [M]: `rv64_gate.sh --stream m8-gn-truth` (default env) **PASS** at 7c38e67e2 (`gate-3.json`: build, unit
tests incl. the new anchor test, small-block cold + warm byte-identical to the frozen D2 golden, 2 fresh CPU
receivers accepted, negative corpus).

Measurement notes:
- The "host assembly it replaces" figure (651.6 / 679.8 ms) is the serial sum of `stage2_assemble_ns` over
  7 truths, measured only in run 0 (`.check`, the first run of the harness). It is a host-path cost [M],
  not a warm per-request wall saving.
- R6 footprint: the measured stage-2 arena peak exceeds the declared footprint for classic keccak (log 13:
  1.48x, log 14: 1.44x, log 17: 1.15x, log 18: 1.14x). The gap was already there in r-truth
  (gpu-r-truth/parity-4/5: same ratios to within 0.05%). gn-truth adds about 0.47 M words. Every class
  still fits its `ClassEntry.arena_peak_words` budget (3/2 of declared until a measured peak replaces it).
  The declared PCS term still needs a measured per-class peak; it remains a TODO for the memory plan.

Still open, not this stream's files: gn-bind wiring (RecursionFactory.truth → truth_factory, publishing from
the request-slab region), the native-seal framing of `Exchange.truthRoot`, the MAIN replay in stage 2
(about 198 ms of host enqueue and 273–351 ms of GPU per request [M]). The job-slab readback in finish
(roots, claims, felts) also stays: `.device` does not need it for publication, but the per-job wait/finish
of the job runtime keeps it until gn-bind moves truths onto the single request readback.
