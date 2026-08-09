# Typed-AIR performance promotion

This directory contains the frozen performance contract for typed-AIR
milestones M5 through M9.

- [`m5-m9-protocol-v1.json`](m5-m9-protocol-v1.json) is the normative,
  machine-readable protocol. It owns the corpus, measurement schedule,
  estimator, budgets, exact invariants, milestone targets, outcomes, and
  receipt requirements.
- [`m7-composition-checkpoint-2026-08-09.md`](m7-composition-checkpoint-2026-08-09.md)
  records a non-promotional development comparison and proof-identity check;
  it is not an M7 receipt or promotion verdict.
- [`../PERFORMANCE.md`](../PERFORMANCE.md) explains the engineering policy and
  summarizes the normative contract.
- [`../../../conformance/performance-authority/epoch-3/stats.py`](../../../conformance/performance-authority/epoch-3/stats.py)
  is the digest-pinned statistical implementation reused by the protocol.

The protocol separates three kinds of evidence:

1. Exact evidence covers semantics, statement and transcript identity,
   component geometry, committed cells, proof bytes for protocol-preserving
   work, allocation counts, and bounded scheduling.
2. Statistical evidence covers verified request/prover/verifier duration,
   resource work, and peak RSS under paired baseline/candidate sampling.
3. Observational evidence remains visible but cannot pass or fail promotion.

A capture plan must freeze the predecessor commit, candidate claim, corpus
manifest, host/backend lanes, and exactly one primary target before candidate
execution. Changing a threshold or choosing a more favourable workload after
seeing results requires a new protocol version and a new capture. `FAIL` and
`NO_VERDICT` both prohibit promotion.

H-010 remains an isolated, pre-proof diagnostic. Its evidence and receipt are
not inputs to an M5--M9 promotion verdict.

Validate the complete frozen contract, including authenticated local inputs,
closed object shapes, milestone matrices, and numerical gates, with:

```sh
python3 scripts/typed_air_performance_protocol.py
python3 -m unittest scripts.tests.test_typed_air_performance_protocol
```

The contract validator rejects duplicate, missing, and unknown fields. The
separate capture/receipt implementation still must recompute every summary and
verdict from the digest-bound raw attempt bundle; validating this contract is
necessary but is not benchmark evidence.
