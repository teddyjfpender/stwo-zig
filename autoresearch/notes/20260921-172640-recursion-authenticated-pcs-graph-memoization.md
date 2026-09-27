---
title: Recursion authenticated PCS graph memoization
author: Teddy Pender
created_utc: 2026-09-21T17:26:40Z
---

# Authenticated PCS graph reuse

Task: reuse the proof-independent PCS/DEEP graph across admitted child captures,
without retaining evaluations, Fiat–Shamir draws, query positions or proof data.
Match: bounded memoization of a deterministic straight-line circuit compiler.
Profile equality includes tree order, each column log size, sample-point layouts,
lifting log, blowup and query count. Exact structural equality avoids relying on
hash-table identity alone. Existing Prepared builds/copies/authenticates the graph.

Transfer: immutable shared ownership plus a two-entry FIFO cache scoped to one
worker. Cache hits clone an owned reference; eviction drops only the cache's
reference, leaving in-flight child captures valid. Retained graph payload bytes
are bounded; a miss may transiently build a larger uncached graph, which remains
request-owned. This is not a process peak-memory cap. No global cache or witness
reuse. Source precedent: StarkWare's shared preprocessed multiverifier structure,
https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/stwo_run_and_prove_recursive_tree/src/canonical.rs

Prediction: reduce repeated PCS graph compilation inside the measured child
capture phase (~0.44 seconds per parent), not the larger authority expansion.
Cache lookup O(columns); build/evaluation remain graph-size dependent. No claimed
asymptotic or total 10x gain. A zero-byte cache supplies a same-binary baseline.

Validation: structural mismatch, eviction with a live lease, cache-owner teardown,
zero-byte budget, independent graph identity/reference evaluation and allocation
cleanup. Then CPU/Metal batched full proofs with fresh independent verification,
byte identity, and retained cache counters. Wrong transcripts remain evaluated
and rejected exactly as before. New explicit teardown is required wherever an
arena previously implicitly owned the complete captured graph.
