---
title: Reuse native AIR inversion scratch across cohorts
author: Teddy Pender
created_utc: 2026-09-22T07:04:58Z
---

# Reuse one inversion buffer across native AIR cohorts

Task: avoid overlapping logically dead per-AIR inversion buffers in the request
arena while preserving the canonical interaction generator and final columns.
This is scratch-buffer lifetime reuse, not a new algebraic algorithm.

Evidence: framework_interaction Runtime.Workspace owns one QM31 scratch slice;
requiredScratchElementCount derives exact geometry from each AIR's batch count
and log size. Native producer generates 20 AIR interactions serially. Outputs
must coexist through commitment, but inversion scratch has disjoint lifetimes.

Transfer: allocate the maximum required scratch once from the bounded worker
allocator, lend exact prefixes to typed Runtime.Workspace views, and free it at
the end of AIR interaction generation, before commitment. Expose the existing
column generator with caller-owned workspace; retain all internal preflight,
alias and fail-atomic checks. No alternate interaction equations.

Prediction: eliminate arena capacity growth caused by interleaving output and
per-AIR scratch allocations. Peak is bounded by maximum scratch rather than
retained arena chunks; measured worker peak decides the benefit. One allocation
per proof avoids making 20 allocations or retaining a large idle worker buffer.

Validation: column/row oracle parity with external scratch, invalid capacity and
scratch/output allocation failures, followed by focused native independent proofs
and worker budgets. No timing or production-profile claim.
