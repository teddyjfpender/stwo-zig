# M8 runtime stream receipts

## Channel parity on GPU (channel-parity-gpu-2.json) [M]
`rv64-jobs-channel-parity 0,1 4` on both RTX 5090s, base image a25cc3b2 (frozen, unchanged) + addon
`libstwo-rv64-jobs.so` (jobs-addon-3, build receipt `addon-build-3.json`).
- 24 ParityJobs (3 scripts x 4 rounds x 2 GPUs) through the real DeviceWorker 3-stage pipeline; both placements on both
  devices; every job exactly 1 host wait and 1 slab D2H.
- 896/896 boundary snapshots (digest, draws, cursor, chain, status) and every draw output equal to the host
  `raw_mod_m31.Om31Channel` word for word, covering mixWords, mixFelts, mixRootFromTree, drawSecureFelts (n = 1..129),
  drawRaw, drawQueries, PoW (device grind + nonce mix, 12 and 20 bits) and a sequence recorded through `om31_observer`.
- Scope: device channel op semantics and the worker pipeline. It is not a proof-byte parity claim and not a timing claim.

## Worker pipeline overlap (pipeline-diagnostic-1.json) [M, diagnostic]
`rv64-jobs-channel-parity pipeline 1 12 256 <bits>` on GPU 1: 12 synthetic jobs, each staging 256 MiB (pinned fill + h2d)
and enqueueing a device PoW grind; same worker with pipeline depth 3 vs depth 1 (serialized). Single run per arm, pod load
8-15 from other streams' builds, so this is a diagnostic pair, not a quiet-gated timing.

| PoW bits | depth 3 (ms) | depth 1 (ms) | hidden per job (ms) |
|---|---|---|---|
| 22 | 198.0 | 324.9 | 10.6 |
| 25 | 191.5 | 322.7 | 10.9 |
| 28 | 3148.8 | 3357.2 | 17.4 |
| 30 | 2925.4 | 3169.6 | 20.3 |

The 3-stage loop hides the next job's staging (host fill + h2d) behind the current job's device work; with one host wait per
job, nothing else is serialized. (Grind length depends on where the deterministic nonce falls, hence 30 < 28 bits.)

## Failure isolation (robust-gpu0.json, robust-gpu1.json) [M]
`rv64-jobs-channel-parity robust <d>` on each GPU, 7 jobs through one worker: a parity job, a refused oversized job
(`JobFootprintExceedsArena`, aborted, never staged), a job that fails after 9 enqueued channel ops (aborted after its single
wait), a parity job filling worker-persistent inputs (fresh), a parity job, a parity job reading those persistent inputs
warm (no upload), and a final parity job. All five parity jobs: 20/20 boundary snapshots equal to the host.

## Service boot with STWO_RV64_M8_JOBS=1 (service-boot-1.txt) [M]
`rv64-word16-ethereum-gpu-combined combined-serve` with STWO_RV64_M8_JOBS=1 + addon, devices 0,1: both workers boot and pass
the channel-parity self-test (incl. PoW; one host wait each), then the service fails closed with
`M8RequestProviderNotLanded` (native/outer providers pending). STWO_RV64_M8_JOBS=2 → `InvalidM8JobsSelection`.

## Scheduler on both GPUs (dag-gpu-2.json) [M]
`rv64-jobs-channel-parity dag 12 12`: request-shaped DAG (12 stage-1 → host seal → 12 stage-2 + 2 truth (seal-independent)
→ 12 recursion leaves + 11 binary folds), every node a ParityJob with per-kind persistent inputs, over two DeviceWorkers.
49 jobs + 1 seal, 980/980 boundary snapshots equal to the host, 27/22 jobs on GPU 0/1, 47 key-affinity placements.
Synthetic jobs; wall clock (36.7 ms) is not a prover timing.
