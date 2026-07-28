# Session 01: persistent proof-of-work workers

## Objective and evidence boundary

The objective is one net-new `core_cpu/small/time` remote record from immutable
candidate `6efb93d539498178fe2fb67ead0788bb884a6bcb`. A local build, published
branch, or green source-policy check does not count. Completion requires an
attested fork receipt, a new remote submission ID, central intake, and the
service's terminal state.

## Why this candidate survived screening

Earlier profiles placed proof of work near the fixed-cost end of the small
proof. Source inspection found that the prover's global pool advertises PoW as
one of its intended consumers, but the raw Blake2s call path still creates and
joins fresh OS threads. Elicit searches on task granularity and thread
management supported only the qualitative expectation that creation overhead
can dominate fine tasks; they did not provide a transferable STWO magnitude.
The code-path contradiction and prior paired measurements, not a paper result,
were the decision evidence.

Two alternatives were kept as negative evidence. A transcript-keyed nonce
cache was rejected because its gain depended on process history and would not
accelerate fresh production transcripts. A four-lane Blake2s nonce batch
preserved correctness but measured neutral-to-worse on exact main, so it was
not combined with pool reuse.

## Implementation reasoning

Each persistent worker scans a fixed residue class modulo the worker count.
The caller owns residue zero. An atomic minimum shares the best discovered
nonce, and joining every job before return ensures scheduling cannot hide a
lower valid nonce. The candidate mirrors the existing prefix-plus-nonce
construction and retains the original implementation for explicit worker
overrides, generic channels, unavailable pools, and single-threaded builds.
Focused tests compare returned nonces with the original grinder across
difficulties, worker counts, and changed transcripts.

## Current qualification state

The branch was rebased onto frontier `cfd47be98a10598b90a898e787e5cd1c674b09e7`,
passed editable-path and ancestry preflight, and passed the full local tests.
Fork run `30344584862` reproduced a workflow defect: policy and harness tests
passed, then Ubuntu setup tried to build `native-proof-bench-metal` and failed
before the paired benchmark or receipt. The candidate therefore remains
unmeasured at the current frontier. Upstream PR 118 carries the board-scoped
setup repair. No performance claim is made from that failed run.
