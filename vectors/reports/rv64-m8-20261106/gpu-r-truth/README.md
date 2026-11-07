# gpu-r-truth: GPU-native TruthJob (recursion stream, piece r-truth)

Branch `codex/rv64-m8-gpu-r-truth` (from `codex/rv64-m8-gpu` @ 28ae81a58). Labels [M]/[D]/[E].

## What landed
- `jobs/truth_job.zig`: a truth is two jobs (its MAIN root is framed in the manifest digest):
  Stage1 = compact inputs -> legacy device witness kernel -> MAIN commit -> root (Exchange.truthRoot) + `truth_root` verdict;
  Stage2 = the legacy `TruthWorker.complete` order on the device channel (FIXED class-persistent tree, MAIN replay,
  local challenges, shared challenges from the seal digest on a fresh device channel, interaction witnesses,
  mixManifestAndClaims, INTER, composition, OODS + enqueue-only PCS) + `truth_status`, `root_match`,
  `channel_order`, `pcs_status` verdicts. No transcript value reaches the host before finish.
- `truth_challenges.zig` (device draw scripts), `truth_params.zig` (kernel parameters gathered on device),
  `truth_interaction.zig` (enqueue-only port of `global_stage`, both layouts), `truth_class.zig` (per-class plan built
  once), `truth_factory.zig` (ClassEntry + RecursionFactory `truth`/`truth_stage2` over the request slab),
  `NAT/rv64/jobs/truth_ops.cu` (gather + 4 check kernels).
- Contract (additive, defaulted): `Check.truth_root`, `Exchange.truths/capacity_truths/truthRoot`,
  seal digest convention (`seal_digest_words`), `RecursionFactory.truth_stage2`.

## Evidence
- [M] host: `zig build test-rv64-jobs-truth` 151/151; jobs + outer suites + sync lint clean.
- [M] kernel parity on RTX 5090: `kernel-parity.txt` (48/48 cases, `tests/cuda/rv64/jobs/truth_ops_parity.cu`).
- [M] real-block parity (`rv64-m8-truth-parity`; legacy GPU0 records, TruthJob on GPU1 proves post hoc from
  compact inputs + seed + digest only): `parity-4.json` (26235156) and `parity-5.json` (24628607):
  **14/14 truth proofs byte-identical** to the pipeline's `truth-<t>.bin`, roots/claims/local/shared equal,
  every device verdict 0, 1 host wait per job; negatives (6 faults x 2 kinds x 2 blocks) each fired exactly its check.

| per request [M] (CUDA events, warm) | 26235156 | 24628607 |
|---|---|---|
| stage 1 GPU, 7 truths | 272.8 ms | 351.4 ms |
| stage 2 GPU, 7 truths | 1424.7 ms | 1722.3 ms |
| stage 2 host enqueue (overlaps GPU) | 435.7 ms | 543.9 ms |
| stage 2 host stage (warm) | 2.9 ms | 2.3 ms |
| finish host assembly (decode + OODS check + encodePhysical) | 627.6 ms | 719.0 ms |
| largest stage-2 arena peak (keccak log 18) | 23.03 GB | 23.03 GB |

The legacy truth composition lease is 14.75 GB outside the job windows [M]; here every truth runs inside the job
arena (22 GiB arena; peak 23.03 GB = 5.76e9 words incl. staged). Declared stage-2 footprints undershoot measured
peaks by up to 48% (keccak log13/14); the factory budgets 3/2 x declared until a measured peak is registered.

- [M] `rv64_gate.sh --stream m8-gpu-r-truth` default: **PASS** at df6086a6b (26235156 32/32 byte-identical x2, fresh CPU
  receivers accepted, negative corpus) — `runs/m8-gpu-r-truth/gate-1`.

## Remaining host work (per request)
- finish assembly 0.63-0.72 s [M] (moves to the shared device encoder + device OODS check);
- stage-2 host enqueue 0.44-0.54 s [M] (launch-bound: composition roles + PCS; whole-job graph capture);
- compact input packing from the capture advice and the per-request seed (a few Blake2s) [not timed];
- device seed fill for outer nodes: NOT landed (see the branch summary).

## Review r-truth (2026-11-07, fixes at 4fe25d2b5)
Confirmed and fixed:
1. **Class key read uninitialised bytes.** `K.classKey` hashed the raw bytes of `Witness` (tagged union; `.sha256` /
   `.arith256_mod` leave payload bytes undefined) and `PcsConfig` (padding, null `?u32` payload). The same class could
   get two keys (warmed class reported not warmed, or warmed twice). Every field is now framed explicitly (key v2);
   host test fills padding with 0x00 / 0xff and gets one key.
2. **Delegated assembly used the class's span.** Classes are span-free, but `Stage2.assemble` built the delegated
   component from the class authority (the first request's calls/first id), so the host OODS check of any later
   request with another span evaluated the wrong metadata. `K.withSpan` applies the request span.
   [M] negative control (pre-fix assembly, class built from a span-skewed authority, 26235156): all 4 delegated
   truths (secp_row x2, sha256, arith256_mod) fail with `ConstraintsNotSatisfied`; classic keccak is unaffected.
   With the fix: `parity-rev3-4.json` / `parity-rev3-5.json` **14/14 byte-identical** with
   `STWO_RV64_M8_TRUTH_CLASS_SKEW=1` (the new harness default), every verdict 0, every negative fires only its check.
   [M] warm, CUDA events, per request: stage 1 273.7 / 350.4 ms, stage 2 1428.6 / 1717.3 ms, host assembly 639 / 672 ms;
   peak arena 23.03 GB (22 GiB arena, `ARENA=23622320128`; the parity.sh default of 24 GiB overruns the VMM arena).
   Host: `zig build test-rv64-jobs-truth` 153/153 (laptop, memguard; on the pod this root fails to link without the
   native library, which predates the review).

Open (not fixed here; design-level, other owners or larger pieces):
- Publication: `requiredChecks(.truth)` includes `encode_bounds` and publish refuses an empty proof, but no truth job
  writes encoded bytes or `encode_bounds` into the request slab; the OODS constraint check and `encodePhysical` run on
  the host in `finish` (0.64-0.67 s/request [M]). Fails closed today (nothing publishes). Fix = r-node's device encoder
  (`outer_encode.zig`, envelope=null) + a device OODS check, writing the truth's slab entry.
- Stage 2 replays the witness + MAIN commit stage 1 already ran (stage-1 GPU 274-350 ms/request [M] duplicated);
  retaining MAIN coefficients between the stages (Stager.retain) removes it at the cost of MAIN residency over the seal.
- Stage 2 does not `awaitSlot` the seal slot itself; it relies on the DAG edge (d-wire's truth2 deps on the seal).
- Per-job host table (`fillTable`: program validation, PCS expectation) and stage-2 enqueue 0.44-0.54 s [M] (launch
  bound) remain; class-cache the static table words and graph-capture the job.
