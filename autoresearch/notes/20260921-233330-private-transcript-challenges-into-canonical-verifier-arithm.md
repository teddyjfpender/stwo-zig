---
title: Private transcript challenges into canonical verifier arithmetic
author: Teddy Pender
created_utc: 2026-09-21T23:33:30Z
---

# Private transcript challenges into canonical verifier arithmetic

Task: replace per-proof public challenge copies in the joined BLAKE3 parent with
constrained transcript output wires. Existing typed scalar routing and weighted
QM31 packing supply exact tuple conservation; no new equations or AIR identities.
Inputs: accepted secure draw blocks, semantic protocol roles, composition input
node identities, and canonical DEEP/FRI input bindings. Require unique complete
coordinates and reject duplicates, mismatches, overlap, and missing roles.

Canonical match: sparse dataflow wiring with weighted multiset equality. Source
emits once; a scalar route consumes once and emits the exact number of downstream
reads. Secure consumers use weighted packing; scalar consumers use one route.
Reuse local scalar_wire_source and qm31_pack_wire. Public anchoring is the current
baseline but cannot support private challenge values with reusable preprocessing.
No general solver or new lookup protocol is needed. Mapping is linear in graph
bindings and challenge outputs, with indexed destinations (derived).

Sourced mechanism: https://eprint.iacr.org/2022/1530 . Integration inspiration:
https://github.com/0xPolygonHermez/zisk/releases/tag/v1.3.0-alpha explicitly lists
BLAKE3 recursion as an alternative testing configuration and dedicated compression.
No external code copied. Preserve single/bulk sampling and rejection semantics.

Prediction/falsifier: all parent secure challenge public boundaries disappear and
the complete joined native STARK still verifies; missing or swapped links fail.
No performance prediction. Validate fixed schedule independence from challenge
values, role/node admission negatives, and focused transcript plus parent proof
gates in one serial build. Rejection attempts, commitments, query geometry and
nonces remain per-capture; reusable production keys remain unqualified.
