---
title: BLAKE3 Span canonical input preparation
author: Teddy Pender
created_utc: 2026-09-22T13:12:57Z
---

# BLAKE3 Span canonical input preparation

Added a verifier-assigned scalar-node plan that reuses the existing QM31 packing,
canonical M31 byte encoding and identity byte router. The plan rejects overlapping
circuit namespaces and duplicate scalar node assignments. It records all scalar
consumption multiplicities, including repeated last-coordinate padding; padded
byte outputs have zero fanout. Preparation uses fixed arrays without heap staging.

The focused statement-codec ReleaseSafe gate passed in 13 seconds (989 MB peak
RSS). The new exact recursion-wire ledger balances packing-to-encoding and
encoding-to-routing joins for both identity purposes. Substituting a routed byte
leaves an unmatched internal wire. This test excludes scalar and hash boundary
obligations and does not constitute a complete recursive proof. Existing typed
packing/encoding equations are reused without modification.

Integration still required: authenticate the source-node assignment against the
statement graph and augment producer fanout, connect the private hash graph and
full digest outputs, then production artifact/key admission and memory/continuation
migration. The job plan currently encodes all statement groups with zero fanout
for unused words; pruning that preparation is a later bounded optimization.
