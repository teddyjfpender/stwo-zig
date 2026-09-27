---
title: Actual PCS transcript in joined BLAKE3 FRI proof
author: Teddy Pender
created_utc: 2026-09-21T22:04:32Z
---

# Constrain the actual PCS opening transcript in the joined FRI proof

Task: extend the combined FRI gate with typed native PCS transcript constraints:
trace roots, sampled values, DEEP draw, each FRI root/alpha, terminal coefficients,
PoW verification, separate nonce absorption, then raw query draw.
Canonical match: deterministic transcript state machine; reuse native channel
as oracle and existing typed transcript witness. No new framing or hash rules.
Build a reusable opening-operation append helper accepting caller-owned channel
state and operation prefix, so a full STARK prefix can be supplied later.
Validate capture challenges/queries against exact native replay and record the
whole-block rejection attempt count for each secure draw. Preserve raw duplicates.
Inputs stay public where previously public but challenges and queries become
constrained transcript outputs in the same proof. Private FRI values remain
shared with arithmetic and all paths. No claim of private transcript payloads.
Tests: actual fold4 PCS capture, complete joined proof, altered alpha rejection,
exact wire ledger, explicit PoW/counter semantics. PCS DEEP/trace arithmetic and
outer STARK transcript prefix remain unfinished. No production/profile changes.
