---
title: Native BLAKE3 lifted leaf geometry
author: Teddy Pender
created_utc: 2026-09-21T21:05:43Z
---

# Native lifted leaf geometry

Source inspection: prover/vcs_lifted/leaves.zig lifts a column row with
((position >> (max_log - column_log + 1)) << 1) + (position & 1).
The low bit is preserved, not discarded by ordinary folding. Columns are sorted
by ascending log size and original index for ties (columns.zig and core lifted
verifier). Existing native verifier path capture supplies authenticated sibling
paths for a real multiproof.

Transfer: a checked leaf geometry plan exposing canonical column order and exact
column-row projection, plus ordering of already queried values for typed leaf
hash witnesses. Reuse existing path AIR/witness; no new hash or evaluator.
O(c log c) plan, O(c) leaf assembly. Reject unsupported logs, positions and shapes.

Gate: mixed logs with equal-size ties; compare projection to native decommitment
values at every row, verify real BLAKE3 multiproof/capture, then prove a typed
path to the native root with private siblings. This authenticates lifted leaf
geometry, not PCS DEEP equations or an entire FRI verifier. Queried payloads are
public statement coordinates in this gate. No performance claim.
