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
