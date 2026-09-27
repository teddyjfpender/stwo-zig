---
title: BLAKE3 PoW bounded deterministic minimum search
author: Teddy Pender
created_utc: 2026-09-22T09:33:44Z
---

# BLAKE3 PoW: bounded deterministic minimum search

Task: find the lowest u64 nonce satisfying the unchanged core BLAKE3 predicate.
Canonical CSP uses 26 bits, 70 queries, 16 proof workers. Measured serial PoW
1.640898 s of 2.523295 s total; legacy pooled PoW 0.125382 s.

Exact canonical problem: parallel ordered predicate search. Partition nonces by
residue modulo the existing pool worker count, atomically lower a shared best
nonce, and join all lanes before returning. Each lane checks all smaller members
of its residue class. Therefore scheduling cannot change the minimum. O(N) total
candidate work, O(W) fixed stack jobs, ideal span O(N/W) plus imbalance. This is
a direct transfer of the existing Blake2s pooled search policy; the BLAKE3 predicate
and cached prefix stay owned by core. No protocol change or new worker threads.

Reuse the pool only when the dedicated PoW environment override is absent,
matching existing policy; otherwise retain the serial reference fallback for now.
Keep backend host admission before work. Explicitly handle u64 overflow and the
maximum nonce sentinel. Reject unsupported difficulty before scheduling.

Prediction: reduce the measured serial bottleneck; no promised multiplier due to
memory/cache costs and unequal candidate counts. Falsifier: canonical total or
PoW time does not improve. Test minimum-nonce parity for several states and worker
counts, zero difficulty, cached-prefix predicate parity including u64 maximum,
and a canonical full proof with stage recording. Do not infer SIMD acceleration.
