---
title: H200 Cairo CUDA all-four AIR and relation optimization
author: Teddy Pender
created_utc: 2026-09-29T16:53:41Z
---

Problem: Four canonical SN PIEs were 1.5–2.2 s for proof/decode and 72–115 GB sampled GPU memory on H200. Goal: reduce all four, preserve 70-query canonical security and exact transcript.

Matches: exact dependency closure for oversized AIR; ZisK-like bounded relation materialization; process-owned runtime and preprocessing reuse. Implemented 32-constraint AIR root helpers, 256-row shared-memory relation inversion with exact old zero behavior, and full-plan-keyed bounded arena cache. Full quartet passed Zig and pinned Rust with zero AOT misses/fallback and identical proof digests. Paired cold medians are 1.889/1.323/1.878/1.492 s; peaks 100.971/61.846/99.796/80.267 GB. Warm proof medians 1.733/1.165/1.726/1.334 s; adapted-input totals 3.219/2.307/3.209/2.804 s. Scope excludes raw PIE execution/adaptation and queueing.

Rejected follow-up: slicing AIRs above 4096 instructions and 4-way quotient accumulator. All proofs verified but three of four slowed 21–34 ms. Nsight Systems: quotient 251.024→268.541 ms, window EC 192.368→197.355 ms. Reverted both. Nsight Compute counters unavailable (ERR_NVGPUCTRPERM). Full receipts: autoresearch/notes/2026-09-29-cairo-cuda-hopper-optimization/README.md.

GPU spend $2.7708, pod deleted, balance $19.9749. Subsecond remains unmet; next structural memory opportunity is lookup-word interning, screened but not implemented. Never infer GB savings from unweighted word counts.
