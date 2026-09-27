---
title: Transcript draw and query adapters forward final main columns
author: Teddy Pender
created_utc: 2026-09-22T08:34:11Z
---

# Query and draw adapters forward canonical main-column ranges

Mechanical integration of the qualified frame/hash destination into query batches,
bounded retry draws, and fixed/raw attempts. Preserve existing iteration, challenge
selection, counters, routing and fixed metadata. Each adapter validates total
geometry before writing, then slices by canonical draw-plan row counts. Public
state fixed draws use the hash sink directly; private state uses the frame sink.
Caller owns columns and generated metadata; returned receipts mark metadata-only
G/XOR rows. No new cryptographic algorithm or security parameters.

Prediction: these adapters can join parent-wide columns without full live G/XOR
row arrays. End-to-end impact remains unmeasured until aggregate integration.
Validate complete reconstructed rows against row-mode witnesses, independently
trusted metadata, smaller cohorts, retry results, lifetime and invalid geometry.
Existing allocation-failure tests continue to cover the shared builders.
