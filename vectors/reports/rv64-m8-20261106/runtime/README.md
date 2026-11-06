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
