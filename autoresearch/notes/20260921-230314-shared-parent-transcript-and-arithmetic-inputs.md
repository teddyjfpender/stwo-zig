---
title: Shared parent transcript and arithmetic inputs
author: Teddy Pender
created_utc: 2026-09-21T23:03:14Z
---

# Shared parent arithmetic sources for transcript claims and samples

Previous turn: progress; routed transcript words/felts passed independent private
input proofs but full parent still used public absorption operations.
Task: connect parent claim and sampled-value absorption to composition graph input
wires through existing canonical field_bytes AIR. Reuse a single secure tuple:
arithmetic consumers plus one encoder read, with exact producer multiplicity.
Claims can become private because both composition and transcript consume the same
source. Sample values retain public arithmetic anchors until DEEP's scalar inputs
are joined; do not create unrelated private copies. No new AIR or digest needed.

Expose optional routed sampled-value source in PCS operation construction while
preserving public wrappers and transactional failures. Prefix preparation returns
input-read metadata and live/trusted encoder rows. Reject duplicate/incorrect input
bindings during parent assembly. Independently reconstruct encoder preprocessing.
Validate full joined parent and shared arithmetic regression; preserve false-key,
root-substitution and native transcript checks. No broad suite or speed claims.
Reusable keys remain blocked by other public challenge/query/root boundaries and
dynamic query/rejection scheduling; this step does not claim production admission.
