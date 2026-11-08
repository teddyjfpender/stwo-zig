# Outer rawmod OM31 device Fiat–Shamir: first consumer

Status: qualified opt-in partial consumer check on both dev blocks, in M6 and D2 formats. This is an opt-in check path, not the completed device-resident outer prover or a measured performance improvement.

The existing `native/rv64/channel.cu` already matches production `Om31Channel`: raw Blake digest, eight raw words reduced modulo M31 per OM31 draw, and raw digest concatenated with little endian field words for mixing. The generic QM31 transcript secure draw is not substituted. The existing native PCS already owns the GPU DEEP/FRI/PoW/query suffix after its imported OODS checkpoint.

`STWO_RV64_OUTER_DEVICE_FS=check` installs an observer scoped to one exact host channel object and thread. It imports the checkpoint after `Native.begin`, records every prefix mix and draw, and compares all sixteen GPU state words and every challenge word. The before-PCS hook executes on the authoritative channel before the PCS makes its transactional copy; it disables observation for the already resident suffix. Missing observation, missing consumer, unknown modes, hybrid GKR, and global admission are refused.

The first actual consumer replays FIXED/MAIN roots and z/alpha draws, then derives the INTER parameter vector on the GPU: z followed by alpha^0 through alpha^5. The real INTER fraction kernels borrow this scoped lease instead of uploading the CPU's 56 words. The second consumer replays through the third secure draw (composition alpha), derives alpha^0 through alpha^(total-1) on the GPU, checks every word against the CPU shadow, and lends each RC role its original descending role segment with ascending powers within the segment. Whole leases and subranges are validated for context, scope, generation and count before pointer arithmetic. RC role kernels consume this vector without a host power upload. CPU shadow values and the lookup sum check remain authoritative checks. The lease survives through the proof's joined stages and is released on the healthy owner path, with terminal cleanup as the error fallback. The additive helper library remains loaded until cleanup completes.

The checker replays the remaining prefix once before PCS and checks all recorded boundaries. RC still builds a CPU shadow power table, and its lookup/claim parameter bindings and OODS point recipes still consume host values. MAIN root publication and other existing joins remain. This code does not establish the <=10 blocking call or 75% kernel busy gates, and check mode adds diagnostic work.

The addon is explicitly loaded through `STWO_RV64_OUTER_FS_OPS_LIBRARY`; receipt fingerprints include this library independently of the frozen native image. No mode is enabled by default. Two logical proofs per GPU remain held behind the separate exact-process 28 GB gate.

Two negative checkpoints are retained: the first refused an eagerly loaded optional generic raw-draw symbol absent from the frozen image; the second caught Merkle-root mixing through the inner channel bypassing observation. The corrected protocol root adapter hashes the same digest/root bytes through the observed channel method; a focused 64-seed CPU test compares it directly with the legacy adapter. No parameter consumer runs after a failed parity check.

## Qualified production gate

| Format / block | Requests with identical artifacts | Exact node instances | Actual RC role consumers | Fresh CPU accepts |
|---|---:|---:|---:|---:|
| D2 / 26235156 | 2/2 | 30 | 360 | 1/1 |
| D2 / 24628607 | 2/2 | 38 | 456 | 1/1 |
| M6 / 26235156 | 1/1 | 15 | 180 | 1/1 |
| M6 / 24628607 | 1/1 | 23 | 276 | 1/1 |

All six requests match the respective accepted reference in native proof files, canonical bundle and recursive artifacts. Every one of the 106 node instances checks all prefix checkpoints/draws, all 56 INTER words and the complete RC power vector; 1,272 actual RC role calls consume validated GPU subranges. Class coverage is reconciled against each published tree's receiver authority, rather than device-lane TLS hints. The log's `leaf` hint is diagnostic; the published DAG supplies node kind.

The producer is `24b2a03e7985db3036cae7350aabd0420b187e65e28d645b636dfcae238841f0`, with frozen native image `a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45` and addon `1324a16ca1d1830fd0abb89b4f82a63734771fd6da2a1a946817ef2d1f37ea7c`. Reproduction scripts and exact build/source manifests, stderr, pipelines, trees and receiver receipts are in `vectors/reports/rv64-m7-20261105/outer-device-fs/qualified/`.

Focused tests pass: observer identity/copy handoff 4/4; root adapter equivalence to the legacy implementation over 64 seeds; independent addon 1,270 GPU controls and compute-sanitizer zero errors (Root helper receipt). No latency improvement is claimed from check mode, which deliberately repeats the prefix and retains CPU shadows. Blocking-call and kernel-busy targets remain open. Selected native PCS already performs its DEEP/FRI/PoW/query feedback on the device; generic channel call counts do not establish host stalls.
