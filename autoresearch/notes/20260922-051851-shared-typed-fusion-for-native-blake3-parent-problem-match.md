---
title: Shared typed fusion for native BLAKE3 parent problem match
author: Teddy Pender
created_utc: 2026-09-22T05:18:51Z
---

# Shared typed arithmetic fusion in the native BLAKE3 parent

Task: apply the measured existing dot4/FMA matches through one canonical lowering
implementation shared with detached recursion. Preserve authenticated graph inputs,
outputs, exports and public terms. No new arithmetic equations or heuristic matcher.

Selected transfer: extract detached_parent_arithmetic_v1.arithmeticRows into an
owned shared materializer parameterized by proof kind. Keep dot4-first reservation,
then FMA, original lowering invocations and exact use counts. Detached assembly
copies the shared result into its cohort; native assembly consumes the same rows.

Native integration: replace multiply AIR with existing qm31_mul_add_v1, append
existing dot4 AIR (19 total), retain inverse/linear selectors, derive geometry and
claims from the roster, and version the native key domain and artifact envelope.
Native public terms remain from the original lowering plan. Expected reduction:
29,488 -> 18,206 arithmetic rows; not an end-to-end speed prediction.

Validation: full native pipeline/proof/codec/independent verifier with wrong-key
and payload rejection, exact expected fused row counts and live/fixed metadata;
focused detached-parent preparation regressions after extraction. Preserve original
graph seals and reference validation; reject legacy native key/envelope versions.
Production defaults/security parameters stay unchanged. Larger fused PCS equations
beyond existing dot4/FMA remain subsequent work.
