---
title: BLAKE3 joined parent statement identity preparation
author: Teddy Pender
created_utc: 2026-09-22T13:19:58Z
---

# Joined parent statement-to-identity preparation

The parent authority now provides one preparation entry point for canonical input
rows and private hash rows, using the purpose and circuit namespaces stored by
its graph-derived plan. Callers retain the plan as verifier-owned authority.

A new differential lookup ledger compares augmented versus base row-11 input
emissions and joins the difference through QM31 packing, canonical field-byte
encoding, byte routing and full BLAKE3 G/XOR/boundary rows. No standalone byte
producer fixture supplies these hash inputs. Both statement and job hashes close
for a parent formed from distinct children. Substituted packed coordinates and
wrong high-bit digest claims leave unmatched recursion wires.

The final focused ReleaseSafe gate passed in 13 seconds (997 MB peak RSS).
The ledger cancels existing graph obligations; it is not a complete graph proof
and does not check every direct/range/bitwise constraint. Production STARK assembly,
shared job/statement fanout, public identity claim admission, memory/continuation
migration and multi-level recursion qualification remain pending. No performance
claim or default promotion follows from this check.
