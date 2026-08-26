# Real temporal `2 -> 1` parent

**Date:** 2026-08-17; hardened and re-captured 2026-08-20
**Status:** first canonical temporal parent proves and independently verifies
with complete suffix-authority and publication mutation coverage
**Claim boundary:** development evidence; not a frozen performance receipt,
multi-level tree, whole-frontend theorem, or proof-system-soundness claim

## Result

The temporal V3 path consumes two distinct real SegmentV2 proofs. Each native
proof is independently verified before its verifier-owned capture is admitted;
the parent prover never reconstructs trusted inputs from unverified proof
bytes. The two children were 89,491 and 91,126 canonical bytes.

The resulting 36-row temporal parent is 94,740 canonical bytes. On the frozen
2026-08-20 checkout, the lean ReleaseFast production path measured 6,778.261 ms
to prove and 6,208.948 ms to verify. Both the prover cohort and a freshly
reconstructed verifier cohort validate the same manifest, placement,
authority, and global-relation closure before the independent verifier accepts
the proof.

```text
TEMPORAL_PARENT_REAL_PROOF bytes=94740 prove_ms=6778.261 \
  verify_ms=6208.948 rows=36 pair_poseidon=0
TEMPORAL_PARENT_REAL_IDENTITIES \
  proof_sha256=a43d756e1b1832105922579ccef1df55b73e9cd861c8e9dfcf7ea87845b7203b \
  publication_sha256=2a6bf58a8ca8006f01df44a86120519fa28ad3a18b9f0ec06410b5e8c04fa867 \
  cohort_authority_sha256=e9fb54b38946066ca4f8a87cce90ce076316b57850dc437c899cdc069aca95be \
  audit_sha256=71ac4304cc3cb3811cc0d9764bd304184ddec889a12e7c3b0463a00aab9be54f \
  closure_receipt_sha256=a678ca532443de395bcbfc2b72707462c0991e7111c2da44c9626c71b50b63a0
```

These timings are one loaded-host observation and are not promotion evidence.
The test build deliberately measured 39.167 seconds inside verification because
it executes the coherent authority-mutation fleet before minting publication;
that value is test work, not normal verifier latency. The test and lean runner
produced all five identities above exactly.

## Authority chain

Rows 0--17 retain the exact verifier-minted transcript and non-FRI temporal
prefix for each ordered child. Rows 18--19 are supplied by the real binary
pair computation rather than a fixture. Rows 20--35 retain the suffix's typed
AIR authority and are bound to the same authenticated child manifests,
statements, challenge context, relation draws, placement, and closure digest.

The statement boundary publishes 824 field elements: two exact 412-element
child statements. The verifier-input boundary publishes another 696 field
elements: two exact `(85 * 4 + 2 * 4)` external values. Captured samples,
physical claims, and the public wire are deliberately excluded from that
boundary; descriptor validation rejects non-zero padding and shape drift.
Together these sources close the parent without accepting caller-invented
material.

Rows 20--34 are now mutated one at a time under independently resealed audit
material, and row 35's statement-owned provider has its own negative. Coherent
pair, parent-statement, child-order, and context mutations recompute their
enclosing seals and still reject. The native verifier performs one full
interaction/closure reconstruction before it can mint the stack-scoped opaque
success capability; publication can consume that capability synchronously but
cannot be reached from proof-shaped caller values.

The temporal control schedule preserves the complete VM plan, retains the
non-transcript recursive computation steps twice, substitutes the exact
authenticated channel operations, clears the raw terminal mask, and performs
one canonical plan close/complete termination. Every global relation domain
closes with no residual negation.

## Defects found by the real proof

The first end-to-end proof rejected at composition. A row-level diagnostic
localized the disagreement to row 10 statement input and row 11 statement
semantics. The temporal adapter had selected the SegmentV2 proof-kind
parameters `{1, 0}` even though the binary parent witnesses and typed AIR
require `{0, 1}`. Both adapters now select the binary statement authority, and
a regression test pins that semantic distinction.

This is why the real proof is the acceptance gate: structural row coverage
alone could not detect the wrong proof-kind selector.

## Performance shape

Prepared temporal authentication performs zero pair-node hashes and zero
scalar Poseidon permutations in the hot parent path. Cold preparation remains
outside that loop. The proof receipt reports `pair_poseidon=0`; no wall-time
speedup is promoted until the frozen crossover cohort is captured.

The ReleaseFast gate passed end to end. A supplementary Debug executable was
terminated by the development host after reaching 7.86 GiB RSS, after its
44-second compile succeeded; this is recorded as a Debug resource limitation,
not as verification evidence and not as a hidden green result.

The deterministic correctness artifact is
[`recursive-temporal-parent-v1/receipt-v1.json`](../artifacts/recursive-temporal-parent-v1/receipt-v1.json).

## Remaining boundary

`temporal_parent_verified = true`. Multi-level tree construction, R-010
crossover measurements, a clean immutable receipt, whole-frontend
verification, and proof-system soundness remain open. The profiler/scaling
lane is producer-exhaustive at CPU/Metal 16/16; its installed V4 smoke and
fresh 1/2/4/max-worker scaling receipt remain open before performance
conclusions are promoted.
