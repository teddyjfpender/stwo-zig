---
title: Recursion persistent worker integration problem match
author: Teddy Pender
created_utc: 2026-09-21T17:46:06Z
---

# Persistent recursion worker integration problem match

Task and semantics: execute the admitted parent DAG using bounded persistent
provers, retaining exact proof admission and independent verification barriers.
Inputs/model: seven-parent retained-leaf fixture, about 4.4 GB peak RSS per Metal
process, two workers on a 64 GiB host; nonpreemptive precedence-constrained list
scheduling with resident worker memory. Latency and total work are both measured.
Invariants: each request pins its manifest and parent key; fresh witness ownership;
immutable plans belong to one worker; any failure cancels/reaps the whole pool;
no dependent runs before independent verification and artifact admission.

Candidates (derived from the prior source-pinned comparison):
- Existing fresh-process ready DAG: exact admission semantics, repeats setup.
- Persistent bounded pool: selected special case of the same list scheduler;
  resident workspace reuse without changing priority or dependencies.
- Level batches: simpler but forces barriers; cannot eagerly admit a ready parent.
- Shared multi-threaded Metal runtime: not selected; witness allocator and runtime
  concurrency would require a different ownership audit.

Mapping: nodes are producer/verifier transactions, accepted outputs release edges;
worker slots are resident resources even while idle. Reserve the configured full
worker footprint for the pool, rather than reclaiming its memory between jobs.
Reuse the existing scheduler via a producer transport; verifier subprocesses and
admission callbacks remain unchanged. Scanning cost remains O(V^2 + E), a derived
bound at small measured V, with no makespan approximation guarantee claimed.

Sources/transfer: Proofman ready queues and persistent resource affinity, previously
inspected at d485fac207679076958b502554fb595568c2f954:
https://github.com/0xPolygonHermez/pil2-proofman/blob/d485fac207679076958b502554fb595568c2f954/proofman/src/scheduler.rs
StarkWare canonical plan and column-pool ownership, inspected at
cd7bc5f4697fb188a27e09f9242f1dd76df8afdc:
https://github.com/starkware-libs/proving/blob/cd7bc5f4697fb188a27e09f9242f1dd76df8afdc/crates/stwo_run_and_prove_recursive_tree/src/canonical.rs
No upstream code copied. This is integration of the already selected algorithm.

Protocol: first pinned single-request batch sets immutable workspace budgets;
subsequent bounded JSON lines carry another manifest path and SHA-256. One request
at a time per worker. A response follows request teardown and Metal lifecycle /
dispatch checks, but is only a candidate; standalone verification follows.
EOF shuts down cleanly. Malformed input, changed budgets or any proof failure ends
the worker. No automatic retry or reuse after failure.

Prediction (hypothesis): avoid repeated runtime/plan initialization while sibling
CPU preparation overlaps GPU work in other processes. Full parent-tree improvement
is not inferred from cache microbenchmarks. Falsifiers: accepted artifact drift,
missing request-local teardown, hung cancellation, unbounded residency, or worse
controlled tree latency. Test fake-worker reuse, failure/timeout cancellation and
verification barriers; build both producers and independently verify a real parent
DAG, retain all timing observations. Memory reservations remain estimates; actual
aggregate RSS and within-worker pipelining remain outstanding measurements/work.
