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
