---
title: BLAKE3 shared job and statement identity preparation
author: Teddy Pender
created_utc: 2026-09-22T13:21:55Z
---

# Shared job and statement identity preparation

Added joint parent identity preparation using one sealed statement-input schedule,
one scalar packing set and one canonical byte-encoding set. Statement and job
hashes occupy distinct circuit namespaces and consume shared encoded words.
Only byte output fanout increases; scalar consumption and statement provider
multiplicities remain those of the single identity plan.

The focused ReleaseSafe gate passed in 17 seconds (1 GB reported peak RSS).
The differential lookup ledger closes both full hashes against the augmented
statement-input rows and shared packing/encoding. Removing the job hash leaves
unmatched byte outputs. Namespace aliases are rejected. This tests combined
lookup accounting, not all AIR constraints or a complete STARK proof.

This removes duplicate canonical preparation from the two-identity assembly.
No timing improvement has been measured. Production proof assembly and claim
admission, remaining memory/continuation commitment migration, and multi-level
CPU/Metal qualification are still required before default promotion.
