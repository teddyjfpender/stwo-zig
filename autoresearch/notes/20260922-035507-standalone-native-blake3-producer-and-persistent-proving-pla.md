---
title: Standalone native BLAKE3 producer and persistent proving plan
author: Teddy Pender
created_utc: 2026-09-22T03:55:07Z
---

# Standalone native BLAKE3 parent producer and persistent plan

Move proving out of the qualification harness. Reuse canonical row projection,
typed relation plans, PCS commitment and core proving. A stable heap-owned plan
retains authenticated AIR definitions/plans, expected row metadata and fixed
columns for one independently pinned key. Every request gets separate scratch
and scheme ownership; the returned proof must outlive both scratch and plan.
Validate row metadata against the plan before allocating/proving. No implicit
key selection or parameter escalation.

This is immutable preprocessing plus per-request materialization, matching the
original persistent-plan goal. Extract shared projection helpers rather than
copying fixture code. Qualify by producing through the standalone API, destroying
the plan, encoding/decoding the artifact, then independently verifying it. Reject
changed fixed metadata without a proof run. No speedup claim until measured;
commitment-tree reuse, bounded scheduling, Metal and stronger profiles remain.
