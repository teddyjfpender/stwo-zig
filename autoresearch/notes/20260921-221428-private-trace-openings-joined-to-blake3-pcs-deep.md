---
title: Private trace openings joined to BLAKE3 PCS DEEP
author: Teddy Pender
created_utc: 2026-09-21T22:14:28Z
---

# Private trace openings joined to PCS DEEP

Task: replace public queried-value inputs with authenticated lifted BLAKE3 paths
in the same PCS/FRI/transcript proof. Canonical mapping: each PCS base-field input
node emits (value,0,0,0) to arithmetic and canonical encoding; stable lifted
column order chooses the framed leaf payload. One extra read per queried input.
A dedicated one-main-field scalar producer prevents unconstrained extension
coordinates when only the first encoded word is hashed. Reuse existing encoding,
Merkle group/path and arithmetic components; no new hash primitive.
Fixture: mixed extended logs [6,4], 17 raw queries, one trace tree. Each trace
path has one two-word leaf. Derive input-node map/exports from admitted PCS graph.
Tests: pin scalar AIR identity and inspect exact tuple shape; native roots,
complete joined proof, exact wire ledger, changed scalar emission and OOM tests
already present where applicable. Keep full outer STARK prefix/composition and
production admission separate unfinished requirements. No speed/security claim.
