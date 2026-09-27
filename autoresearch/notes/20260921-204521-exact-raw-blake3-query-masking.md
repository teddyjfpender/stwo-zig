---
title: Exact raw BLAKE3 query masking
author: Teddy Pender
created_utc: 2026-09-21T20:45:21Z
---

# Exact raw-u32 query masking

Task: constrain native core/queries.zig word & ((1 << log_domain_size) - 1),
without M31 reduction or field rejection. Exact match: bytewise AND with fixed
mask bytes, using the existing canonical bitwise table (operation 0). Four table
requests bound input/output bytes and implement AND; authenticated source and
output wires bind packed u32 values. No new table or bit decomposition needed.

Use packed bytes for output, not one M31 value: the valid index 2^31-1 would
otherwise alias zero. Support native domain logs 0..31. Reject larger logs rather
than shifting a u32 out of range. Source/destination namespaces must differ.
Complexity: four table requests per word, eight main columns, no direct roots.
Alternative full bit decomposition adds 32 Boolean witnesses unnecessarily.

Validate every domain log, boundary raw words including fffffffe/ffffffff,
canonical lookup membership, output-byte mutation rejection, semantic pin and
framework export. Ordered draw batching, counter transitions, deduplication,
folded indices and path admission remain integration work. No speed claim.
