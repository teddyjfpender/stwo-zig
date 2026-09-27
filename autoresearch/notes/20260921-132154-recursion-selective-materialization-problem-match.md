---
title: Recursion selective materialization problem match
author: Teddy Pender
created_utc: 2026-09-21T13:21:54Z
---

# Recursive parent: selective materialization and authenticated reuse

Task and semantics: produce the exact existing recursive parent proof from two
independently admitted children. Preserve all validation, tuple order, parameters,
keys, rejection behavior and owned lifetimes. Target complete-process latency.

Inputs/model: q193/16-PoW development final parent, three retained samples per
backend; Metal 6.782 s, PCS preparation 2.328 s, tuple projection 1.284 s.
339 MB logical rows; bounded in-memory arrays, word arithmetic and memory traffic.
A fresh five-second stack sample confirms structural SHA, hashInt, copying and
ledger hashing as active work. Retained timing is provenance, not an A/B denominator.

Matches:
| Candidate | Relationship | Fit / limits | Reuse / risk |
|---|---|---|---|
| Selection pushdown and producer-consumer fusion | Exact for independently generated rows, conditional for chained hash rows | O(N) metadata validation remains; generate only K selected rows, avoid padded intermediate columns | Existing logicalInputs and authenticated schedules; no external code/license dependency |
| Partial evaluation of fixed authenticated geometry | Special case of staged computation | Reuse immutable geometry, never proof-dependent values | Existing owned admission; lifetime/security review needed |
| Parallel child preparation | Independent-task scheduling | At most two-child span reduction, memory rises | Separate arenas needed; defer until work reduction measured |
| New fused PCS/DEEP AIR | Algebraic circuit fusion | Could reduce rows, but changes keys/proofs | Separate future experiment, outside proof-identical lane |

Sources: Boncz, Zukowski, Nes, MonetDB/X100 (2005), primary institutional record
https://ir.cwi.nl/pub/11098 describes avoiding intermediate materialization via
in-cache vectorized processing. LLVM's official liveness/DCE pass documentation
https://mlir.llvm.org/docs/Passes/ distinguishes non-live computations from
unreachable code. These are transferable mechanisms, not prover speed claims.

Selected transfer: authenticated bulk admission followed by direct selected-lane
logical row emission, starting with independent PCS/FRI input rows. Keep all bulk
reference and witness checks, allocate output internally (no external alias),
retain existing full-column path as test oracle. Avoid a per-row checked logicalRow
call: it rehashes the schedule and would make admission quadratic.

Prediction (hypothesis): eliminate padded main-column allocation/zero/copy and the
second bulk validation previously performed to obtain a parameter exemplar for
these owners. Aim for >=10% lower PCS row phase; complete-parent gain must be
measured. Falsified if row phase does not move or complete parent regresses.

Correctness/benchmark: both lanes differential against full-column oracle;
malformed input/admission checks remain; fresh standalone verifier and identical
key/claim/proof hashes. Rebuild baseline and candidate, discard warmup, paired
ABBA complete parents. Scope is local advisory recursion research: current harness
boards do not score this recursive-parent endpoint; do not mint judged verdicts.

Open uncertainty: remaining authority hashing cost, true staging/wait split, and
representative large-program scaling. Tenfold total improvement is an aspiration,
not justified by current stage bounds; keep a cumulative unchanged baseline.
