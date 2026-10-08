---
title: RTX 5090 compact Cairo static liveness problem match
author: Teddy Pender
created_utc: 2026-10-08T00:53:03Z
---

# Compact Cairo CUDA static-storage liveness: problem-match brief

**Task and required semantics.** Produce exactly the same canonical Cairo
proof bytes, transcript, and independently accepted Rust verification result
while reducing the device memory required by a compact-GPU PIE-to-root worker.
Each Cairo request must still validate its immutable fixed artifact and bind
fresh request data. A cached receipt may only stand for bytes that remain
resident and unmodified.

**Inputs, scale, and model.** The measured RTX 5090 has 31.36 GiB usable HBM
and 167 GB host RAM. The 5.34M-step PIE plans 37.70 GB of arena storage;
the 6.00M-step PIE plans 44.23 GB and is stopped by the compact profile's
38 GiB gate. The 20.85M-step PIE plans 88.63 GB and takes 314.50 s
input-to-publication under broad managed placement, versus 15.31 s in a
historical, different-source H200 receipt. Source: the retained trial receipts
and `README.md` in this directory. These are deterministic, offline proof
stage schedules; storage has exact slot identities, sizes, lifetimes, and
phase ordering.

**Constraints and exploitable structure.** The current
`resident_session.processRequirements` extends every `process_cache` slot to
`ingress..proof_assembly`, even when its actual in-request last use is OODS,
decommit, or FRI. That is necessary when an arena survives into the next
request. The compact integrated leaf path evicts its Cairo arena before each
circuit leaf wrap and reloads fixed data on the next leaf. Thus cache survival
is not available at this boundary. The proof must not read an aliased static
slot after its declared last use, and the next request must not reuse a stale
static receipt.

| Candidate | Relationship and guarantee | Fit and evidence | Risk |
|---|---|---|---|
| Shorten static slots to actual last-use stages only for an evicted compact leaf arena | Exact special case of offline lifetime-aware storage allocation; no output changes | **Derived:** can allow large static slots to alias later proof scratch, reducing the plan without host traffic | Hidden late use or stale receipt would break soundness; must be tested with exact proof bytes |
| Managed host preference and prefetch | Exact memory-hierarchy placement heuristic | **Measured:** 5.34M 5% coefficient-tail policy reaches 11.82 s median but only 0.12 GiB headroom; lookup and evaluation spills did not improve the frontier | PCIe traffic and migration dominate larger geometries |
| Tile relation and constraint sources through bounded HBM windows | I/O-aware decomposition of the proof DAG | **Hypothesis:** needed for 20M-step PIEs | Kernel, pointer-table, and decommit changes are substantial; premature without a smaller liveness test |

**Chosen canonical problem and mapping.** This is offline weighted interval
storage allocation with a two-level memory hierarchy. A slot is an interval
over ordered proof stages with a byte extent; the compact worker's arena is
fast memory. Extending a static slot to the end when it cannot survive the
request is a false interference edge. Remove only those false edges at the
eviction boundary, then reuse the existing deterministic arena planner. The
broader out-of-core problem is related to the red-blue pebble model of I/O
complexity; that model is a framing and lower-bound tool, not a drop-in
implementation ([Hong and Kung, 1981](https://www.eecs.harvard.edu/~htk/publication/1981-stoc-hong-kung.pdf)).

**Selected transfer and rejected alternatives.** Use the slot's already
authenticated `live_from`, `live_through`, and phase fields for compact leaf
sessions that explicitly retire the Cairo arena before the next request.
Keep existing process-cache lifetimes for other sessions. Do not infer a new
last-use from code shape. Managed-memory advice alone is not a capacity
guarantee: NVIDIA documents preferred location as a hint, which prefetching
can override ([CUDA Unified Memory Guide](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/unified-memory.html)).

**Prediction, crossover, and falsifier.** The first test is whether the
5.34M-step plan loses multiple GiB without a new host-preferred slot. If its
peak and publication time do not improve materially, or if any exact proof,
root, Rust verdict, or stage-order check differs, reject the change. If it
works at 5.34M, test the 6.00M admission and a multi-leaf pipeline. This
does not claim the 20.85M-step PIE will fit: its 88.63 GB plan exceeds the
card by more than this static-lifetime opportunity can plausibly recover.

**Correctness and benchmark plan.** Compile locally first. Compare the
5.34M proof SHA-256 and independent pinned Rust verifier against its saved
receipt. Run the two-PIE exact-root pipeline on the 5090, including repeated
Cairo/circuit transitions and whole-device peak. Test a non-compact path to
confirm that its process-cache lifetime is unchanged. Record source and
binary hashes, cold and warm timings, host RSS, GPU peak, and failures.

**Open uncertainty.** The precise static-slot sizes and effective last uses
are being printed from the plan on the same 5090 source build; a concrete
plan delta is required before changing allocation behavior. The 6M and
20M outcomes cannot be inferred from the 5M point.
