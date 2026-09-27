---
title: Recursion persistent workspace problem match
author: Teddy Pender
created_utc: 2026-09-21T17:12:55Z
---

# Persistent recursive workspace

Task: amortize immutable transform preparation and scratch allocation across
independent parent requests without sharing witness or transcript authority.
Model: preprocessing/query decomposition, bounded one-entry plan cache, sequential
workspace lease. Exact PCS config and required domain bind the transform plan.
Existing Engine.Session already owns immutable canonical twiddle suffixes and
checks configuration/domain compatibility. Reuse this implementation rather than
introducing another transform cache. StarkWare supplies the analogous boundary:
https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/circuit_prover/src/prover.rs

Chosen transfer: an explicit worker-owned session and bounded retained scratch
arena, reset after all request-owned schemes/evaluators are destroyed. Batch
requests reuse a Metal runtime but retain independent key admission and fresh
channels. Shape/config changes replace the single cached session; they cannot
silently reuse incompatible data. No witness cache, global mutable plan cache or
unbounded key table. Circuit-definition and fixed-commitment reuse remain further
work; this step establishes maintained cross-request ownership.

Hypothesis: one transform construction for compatible requests, fewer allocator
calls for quotient scratch, and no repeat Metal initialization. No predicted 10x
claim. Cold setup stays inside batch wall time; each fresh verifier must consume
outputs after producer exit. Test compatible reuse and incompatible replacement,
budget rejection, repeated request artifacts, CPU/Metal parity and cleanup.
