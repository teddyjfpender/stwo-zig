---
title: Real STARK capture and typed verifier prefix
author: Teddy Pender
created_utc: 2026-09-21T22:24:49Z
---

# Real full-STARK capture and typed verifier transcript

Task: qualify the missing full verifier prefix against actual core STARK capture:
composition randomness, composition commitment, OODS seed, then PCS opening.
Reuse the existing transcript witness and channel. Extend the proof test helper
with an opt-in successful-capture observer; default gates keep ordinary verify.
The combined PCS proof itself supplies a real full-STARK capture. Reconstruct
its exact fixture prefix (trace commitments, universal draws, claims, interaction
root), append the core verifier sequence, and prove that transcript in a second
complete typed CPU proof. This second proof is transcript qualification, not a
claim that full STARK composition arithmetic has been recursively verified.
Validation: match real captured challenges/query positions and native counter,
independent fixed columns, exact composition-root substitution rejection, full
core verification. Capture published only after native verification succeeds.
No production suite/key changes. Full composition/OODS algebra and production
CPU/Metal/parent-of-parent admission remain required.
