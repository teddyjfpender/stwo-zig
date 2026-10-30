---
title: Leased bounded LRU for proof-wide immutable MAIN evaluations
author: Teddy Pender
created_utc: 2026-10-29T08:39:52Z
---

Task and required semantics: retain exact immutable polynomial evaluations under one 256 MiB proof-wide cap, releasing unused older windows without invalidating parallel readers or weakening source degree checks.
Inputs/model: mixed421 q70/26 observed 13,080 requests, 297 recoveries, 1,672 hits, 11,111 capacity misses; 267,912,896 retained bytes. Source identity includes pointers, geometry and recovery policy. Online concurrent variable-sized memoization, word-RAM plus FFT cost.
Constraints: original coefficients/evaluations stay immutable until proof ends; pending values count toward cap; active readers cannot be evicted; no per-row locks; allocation failures propagate, capacity exhaustion keeps original local fallback.
Candidate matches: append-only memoization (exact, existing, fails after early fill); whole-window flush (requires proven barrier across mixed workers, unavailable); reference-counted LRU (exact values, heuristic reuse, safe with leases); global optimal replacement (requires unavailable future schedule).
Chosen mapping: key -> authenticated source/policy/domain identity; value -> original recovery+FFT output; pin -> evaluator lease; eviction -> oldest unused nonpending entry. Pending duplicate callers acquire references before wait. No cache state is verifier authority.
Complexity/limits: bounded linear lookup/eviction over at most4096 metadata entries, O(1) lease release, 256 MiB including pending retained buffers. Scratch and unchanged fallback allocations remain outer-budget charged, not part of retained cap.
Prior implementation/source: existing local cache supplies exact recovery; RocksDB block-cache documentation describes strict capacity plus pinned blocks and per-shard LRU locking (https://github.com/meta/rocksdb/wiki/Block-Cache). Transfer lifetime/capacity design only; no third-party code copied.
Selected transfer: separate leased cache, preserve legacy unleased API, share validated source preparation/recovery. Reject cap increases and eviction of raw borrowed buffers. Reuse is heuristic; large pinned working sets still fall back.
Prediction/falsifier: eliminate permanent early-window starvation; recovered/hit/eviction counters and exact proof SHA measured against same immutable workload. No quantified speedup promised; if composition unchanged then typed per-row work, not recovery, dominates.
Correctness: pending success/failure reference tests, eviction under pin pressure, exact original evaluations, policy/degree/geometry failures, stale-address new-proof isolation, allocation failure cleanup, focused domain parity, then complete proof byte parity.
Open uncertainty: requests within a single component may pin more than cap; bounded LRU cannot remove inherent working-set pressure. Future shared-family composition could remove repeated typed lookup construction as well.
