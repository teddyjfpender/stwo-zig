---
title: Full-STARK PCS and composition arithmetic
author: Teddy Pender
created_utc: 2026-09-21T22:39:50Z
---

# Full-STARK PCS and composition in one arithmetic proof

Previous turn: progress, complete composition equation qualified against a real
STARK capture and proved separately from its transcript. Remaining PCS fixture
had only one tree/two columns/current-only masks.

Task: admit real four-tree PCS data into canonical DEEP/FRI arithmetic and prove
it together with composition. Match: existing typed DAG interpretation/lowering,
not a new quotient algorithm. Reuse sample_point_layout classification and
fri_arithmetic_capture; add an owned hash-independent DEEP capture adapter that
checks caller-admitted profile geometry, sample order, field encodings and raw
queries before copying. Complexity linear in input inventory; graph/proof cost
is measured qualification overhead, no performance prediction.

Integration: generalize the shared arithmetic proof fixture to multiple graph
lanes; retain single-graph wrapper and independently regenerated preprocessing.
Full-STARK fixture supplies composition, DEEP and FRI graphs to one proof. Their
inputs remain public values from the same native capture, not private joined
wires. Final parent still needs transcript/hash integration and trusted profiles.

Validation: native captured answers satisfy DEEP/FRI graphs, altered samples fail,
profile/sample-order mismatch fails admission, and complete BLAKE3 proof passes.
Run only combined and shared FRI proof gates, serialized ReleaseSafe. No production
suite/key switch or speed claim. Source authority: existing canonical circuits,
captured_fri_owned and generic verifier component mask generation in this repo.
