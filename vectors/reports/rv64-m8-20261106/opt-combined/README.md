# M8 opt-combined: T1–T9 merged, gated, measured, landed (2026-11-07)

Branch `codex/rv64-m8-opt-combined`, cut from `codex/rv64-m7-integrate @ c72b51646`. It merges all nine
optimisation branches: T1 capture-parallel, T2 assignment-chain, T3 deep-oods, T4 fft-passes, T5 aot-constraint-regs,
T6 merkle-leaf-tree, T7 gkr-batch-sumcheck, T8 logup-batch-inverse and T9 witness-coalesce.
- The file sets are disjoint and every merge was clean.
- No flag, kernel or receipt of any stream was dropped.

Labels: **[M]** measured, **[D]** derived from measured values, **[E]** estimate. Pod `rv64-resident-2x5090` (2×RTX 5090).
Raw data stays under `/workspace/m3/runs/m8-opt-combined/` and is referenced here by path.

## Headline (24628607, warm request, canonical interleaved 3+3, quiet gate enforced, byte parity + fresh receivers) [M]

| | integrate-head behaviour (all opt flags off) | all opt flags on | Δ |
|---|---:|---:|---:|
| request wall, median of 3 | **12.869 s** (13.041, 12.843, 12.869) | **11.644 s** (11.644, 11.579, 12.053) | **−1.225 s (−9.5 %)** |
| capture | 2.043 | 2.068 | +0.03 (flat, as T1 predicted for 7 segments) |
| native prove | 4.720 | 3.824 | −0.90 |
| native verify | 1.745 | 1.629 | −0.12 |
| recursion (after native) | 5.790 | 5.444 | −0.35 |
| kernel GPU-s, CUPTI union, both GPUs (profiled pair, warm) | 10.609 | 8.478 | **−2.13 (−20 %)** |
| busy GPU-s (kernels + copies) | 12.035 | 9.920 | −2.11 |
| kernel launches in the warm window | 71,914 | 60,220 | −11,694 |
| NVML kernel-active, service mean, GPU0 / GPU1 | 21.7–25.0 % / 22.7–28.7 % | 17.8–19.8 % / 21.5–23.0 % | lower: the same work in less GPU time |
| peak device memory (NVML whole-device sample) | 26.0 GiB per GPU | 31.3 GiB per GPU | not comparable: the fullstack arm also holds the runner's 5.68 GB physical canary (≈ 25.6 GiB without it [D]) |

- Receipts: `ab8-experiment.json` (runner output), `ab8-summary.json` (per service), `ab8-kernels.json` (per kernel, warm window).
- Runner status: `TIMED_BYTE_PARITY_AND_FRESH_ACCEPTED`.
- Every request in both arms is byte-identical to the first proof, and the fresh CPU receivers accepted every one.
- Cold requests [M]: 29.69 / 29.34 / 30.17 s with flags off against 28.50 / 28.95 s and the third fullstack service with flags on. That is setup-dominated; see `ab8-summary.json`.

**Environment (`ab-preset.json`).**
- Both arms run the canonical **baseline/default** env: global admission off, sessions off, 1 lane per GPU, pending 17. This is the env every `rv64_gate` run proves.
- Both arms use a **fixed 22G arena**, so the runner's fullstack-only canary cannot resize either arm.
- Only the opt flags differ:
  - `baseline` = every T1–T9 flag `0`, with the T3/T4 kill switches set.
  - `fullstack` = every flag on, plus the T6 chunk knobs at 2^28 words.
- Rejected environments [M]:
  - The canonical fullstack env (22G + admission + sessions + 2 lanes) **fails with flags off** on this image:
    - runtime v2: `NativePostGlobalDrainUnavailable` on the warm request (ab4);
    - runtime v1: the warm request deadlocks, with 76/79 threads in futex wait for 20 min. The service was stopped by STOP → TERM (ab6).
    - The cause is the image's admission-v2/session path, not a T* flag. That env is frozen at integrate (m8-memory note).
  - Default env + auto arena: the fullstack arm OOMs under the canary (`CudaAllocationFailed`, ab5).
- 26235159: **not measured**. The canonical runner and `rv64_m4_resident.py` refuse non-dev blocks by owner rule (only 24697070 once, with `--allow-scale-probe`). T1's capture-bench [M] stays the evidence for 26235159: capture 8.53 → 5.76 s with `LOCAL_LEDGER=1` + `INFLIGHT=16`.

## Where the time went: per kernel family, warm request [M, nsys CUPTI, profiled pair of ab8]

| stream | flag | kernels (off → on) | GPU-s off → on | Δ GPU-s |
|---|---|---|---:|---:|
| T3 | kill switches `STWO_RV64_M8_{DEEP,SAMPLE}_LEGACY` (default on) | deep_combine / deep_validate / sample_first → deep_combine_classes / deep_validate_parallel / sample_first_basis + sample_basis | 1.118 → 0.419 (all deep_*/sample_*) | −0.70 |
| T8 | `STWO_RV64_M8_LOGUP_BLOCK_INVERSE` | global_inverse_contribute 0.391 → inverse_contribute(_sum) 0.180; level-0 scan → scan_tile_{sums,apply} 0.020 | 0.565 → 0.205 | −0.36 |
| T5 | `STWO_RV64_M8_AOT_REGISTER_SCHEDULE` | truth role 0 shards 43–49 + joined_domain_20 → `_t5` | 0.651 → 0.250 | −0.40 |
| T9 | `STWO_RV64_M8_WITNESS_COALESCE` | keccak_witness 0.342 → staged + bitrev 0.021; base generate 0.298 → 0.138 + generate_shared 0.102; bridge → witness_private | 0.640 → 0.260 | −0.38 |
| T4 | kill switches `STWO_RV64_M8_{B2N_WIDE,FFT_SMALL,N2B_WIDE_MIN_LOG,N2B_WIDE_ROWS}` (default on) | all b2n/n2b/lde/fft (n2b_wide_contiguous +0.11 because log 20 now goes wide; continue/stage/final-warp kernels −0.35); 31,638 → 20,387 launches | 3.211 → 2.975 | −0.24 |
| T7 | `STWO_RV64_M8_GKR_BATCH_PAR` | batch_round → batch_round_par (2,250 launches each) | 0.154 → 0.051 | −0.10 |
| T6 | chunk knobs `STWO_RV64_{PCS,TRACE}_STREAM_CHUNK_WORDS=2^28` | mixed_leaf_kernel | 1.346 → 1.250 | −0.10 |
| T6 | `STWO_RV64_M8_MERKLE_FUSED` | child_layer_kernel (no caller uses the new entry point yet) | 0.181 → 0.180 | 0 (inert) |
| **T2** | `STWO_RV64_M8_ASSIGNMENT_FLOW` | chain_run → chain_flow<32> (689 launches each) | **0.996 → 1.141** | **+0.145 (regression)** |
| T1 | `STWO_RV64_M8_CAPTURE_LOCAL_LEDGER=1` + `INFLIGHT=16` | CPU capture (no kernel) | capture 2.043 → 2.068 s | flat on 7 segments |

The kernel sum matches the CUPTI union exactly: 10.609 / 8.478 GPU-s.

## T2: the regressing flag, isolated

- Kernel level [M, ab8 profiled pair, warm 24628607]: `chain_run` 0.996 GPU-s → `chain_flow<32>` 1.141 GPU-s, 689 launches in each arm,
  so +0.145 GPU-s (+15 %). On the real recursion nodes the dataflow executor is slower than the level executor.
  - T2's synthetic microbenchmarks (15.3 → 2.8 ms on a width-1 chain) do not carry over.
  - Its `WideWidth = 32` threshold was an [E] that was never measured on a real node (the dump/replay step never ran).
- Request-level isolation: one 3+3 with every opt flag on against the same minus T2 (`ab-preset-t2-off.json`). It is **not qualified**:
  - 4 attempts (ab9, ab10-1..3) all failed the quiet gate on foreign `zig build-exe` processes of other streams;
  - the only services that completed are all-on ones: warm 11.939 and 11.714 s [M, quiet-accepted];
  - no T2-off service completed.
- Decision: T2 stays default **OFF** and is excluded from the recommended on-set (every gate4 run below uses `ASSIGNMENT_FLOW=0`).
  - Fix path for T2: dump a real node (`STWO_RV64_M8_ASSIGNMENT_DUMP`), re-tune the width split, and require chain_flow ≤ chain_run on that node before re-proposing it.
  - The headline above includes T2 on. The recommended set is therefore ≥ the measured −1.225 s, by up to ~0.1 s [E, from the +0.145 GPU-s on a partly serial chain].

## Gates [M] (`gates-summary.json`; image lib `b181cdd9…`)

All 8 gates PASS: build, Zig + Python unit tests, small-block cold and warm proofs **byte-identical to the frozen D2 golden** (39 artifacts),
2 fresh CPU receivers, and 19/19 negative-corpus cases.

| gate | runtime | env | block | result |
|---|---|---|---|---|
| gate3-on-24628607 | opt-combined image | every opt flag on (T1 pair, T2–T9, T6 chunk knobs) | 24628607 | PASS |
| gate3-on-26235156 | opt-combined image | every opt flag on | 26235156 | PASS |
| gate3-def-24628607 | opt-combined image | default (no env) | 24628607 | PASS |
| gate3-def-26235156 | opt-combined image | default (no env) | 26235156 | PASS |
| gate3-p0-26235156 | frozen p0 (a25cc3b2) | default | 26235156 | PASS (the merged Zig/T1 code on the frozen image) |

After the default flips (commit 3e1de5ddc), the image was rebuilt as lib **`25d0e62f…`**: same recipe, and only the five flipped mode readers differ.
The runtime JSON is `runtime-25d0e62f.json` (the pod copy is `/workspace/m3/build/m8-opt-combined/img/runtime.json`).

| gate | runtime | env | block | result |
|---|---|---|---|---|
| gate4-def-24628607 | 25d0e62f | default: T3/T4/T5/T7/T8/T9 on, T1/T2/T6 off | 24628607 | PASS |
| gate4-def-26235156 | 25d0e62f | default | 26235156 | PASS |
| gate4-on-24628607 | 25d0e62f | recommended on-set: every flag on except T2 (`ASSIGNMENT_FLOW=0`); T1 pair and T6 knobs on | 24628607 | PASS |

The 3+3 above was measured on lib `b181cdd9…`. It has the same kernels as `25d0e62f`; only the defaults differ, and both arms set every flag explicitly.

## The image (`compose_image.py`, `image-build.json`, `native-relink.json`)

**The T* image recipe is broken, so none of the nine branch images could have gated.** All nine branches relinked the frozen
`m7-combined-residency` link line with a few objects recompiled. That line is no longer reproducible [M]:
- 4 of its objects are gone;
- 6 more were overwritten by later m7-integrate builds: commitment-progressive, rv64-composition_finalize, rv64-binding, rv64-global, rv64-circuit_interaction and core_composition_dispatch;
- `runtime/context.cu` and `rv64/pcs_native.cu` changed after it (0eeaad6fd, 898a38bfe, b68e02081, 5a93c2449).

The result mixes revisions. Attempt 1 (lib `afe02a0c`) fails service start with `error: Unexpected` with **every flag off**.

The resident image builder (`rv64_m3_pod.py build --only cuda`; lib `61ff9412`, or `663c8a5b` with T5) fails the same way. That is the
integrate-head defect m8-memory reported at 04:40 in M8-INTERFACES.md. A dlsym trace localizes it: the head-source image stops right after
`stwo_rv64_truth_composition_role_on` is resolved, where the frozen image goes on.

**Working recipe.** It is m8-memory's accepted P1 native relink (`scripts/rv64_m8_native_relink.py`, taken verbatim from 3bb987887):
- all 48 hand-written native TUs are recompiled from this tree, so every T2/T3/T4/T6/T7/T8/T9 kernel is in;
- the frozen P1 node-peaks AOT objects are relinked, and all of them are SHA-checked intact;
- T5's relink (`scripts/rv64_m8_aot_register_relink.py`) then runs on that argv and adds the 8 `_t5` modules plus the flag-gated dispatcher;
- the image is 2.056 GB, under the 2 GiB relocation cap with about 92 MB to spare.

The native objects that differ from P1 are exactly the T* TUs and their header includers (composition_split, round, tail, batch_oracles,
gkr_loop). `pcs_native` and `context` are identical to the startable np3.

## Default flips (this commit) and proposals

Rule (owner): flip only pure kernel replacements with bit-exact kernel parity **and** a measured win.

| flag | decision | evidence |
|---|---|---|
| T3 `DEEP/SAMPLE_LEGACY` kill switches | **stays default ON** (as landed by T3) | 51 parity cases bit-exact, plus memcheck/racecheck/synccheck/initcheck; −0.70 GPU-s [M]; all gates byte-identical |
| T4 `B2N_WIDE/FFT_SMALL/N2B_WIDE_*` kill switches | **stays default ON** (as landed by T4) | 552/552 parity cases bit-exact; −0.24 GPU-s, −11k launches [M] |
| T5 `AOT_REGISTER_SCHEDULE` | **flipped to default ON** (unset or 1 = scheduled; 0 = admitted) | 33 kernel A/Bs bit-exact; −0.40 GPU-s [M]. Only images built with the T5 relink carry the `_t5` kernels: other images have no T5 dispatcher at all, so nothing changes for them |
| T7 `GKR_BATCH_PAR` | **flipped to default ON** | 304 round + 192 tail parity cases with 0 mismatched words; −0.10 GPU-s on the serial native-GKR chain [M] |
| T8 `LOGUP_BLOCK_INVERSE` | **flipped to default ON** | 208/208 parity cases bit-exact; −0.36 GPU-s [M] |
| T9 `WITNESS_COALESCE` | **flipped to default ON** (all three TUs; `0` = reference) | keccak 94/94, bridge 53/53, base selftests bit-exact; −0.38 GPU-s [M] |
| T2 `ASSIGNMENT_FLOW` | **stays OFF; do not enable** | +0.145 GPU-s on real nodes [M]; see the T2 section |
| T6 `MERKLE_FUSED` | stays OFF | inert until callers adopt `stwo_blake2s_merkle_layers_on` (5 call sites, other owners). Kernel A/B 0.48–0.81× [M, T6] |
| T6 chunk knobs (2^28 words) | proposal only (not a kernel replacement; +512 MiB PCS scratch) | mixed_leaf −0.10 GPU-s [M] |
| T1 `CAPTURE_LOCAL_LEDGER=1` + `INFLIGHT=16` | proposal only (CPU scheduling, not a kernel; +3–4 GiB RSS on 26235159) | flat on 24628607 [M, this 3+3]; 26235159 capture −2.77 s [M, T1 capture-bench] |

The pinned default runtime (`p0-runtime.json`, the frozen a25 image) is **unchanged**, because there are no frozen-path overwrites. The flips take effect on
images built from this tree. The opt-combined image and its runtime JSON are at `/workspace/m3/build/m8-opt-combined/img/`.

## Not done / open

- 26235159 request-level 3+3: the owner rule forbids it in the canonical tooling (see above).
- The canonical fullstack env on any source-built image: the admission v2 drain failure and the v1 warm deadlock (ab4, ab6). They need the runtime/memory owners.
- The T1–T9 pod run dirs were **not** pruned. Other agents created them, and their committed receipts cite raw data inside them (≈ 520 MB, 398 MB of it the T5 bench).
