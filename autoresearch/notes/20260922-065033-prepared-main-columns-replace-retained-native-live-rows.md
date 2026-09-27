---
title: Prepared main columns replace retained native live rows
author: Teddy Pender
created_utc: 2026-09-22T06:50:33Z
---

# Prepared native main columns replace retained live rows

Transfer final main projection into canonical preparation for all 20 AIRs. Once a
cohort's final committed-order columns exist, release its live logical-row list.
Prepared owns main column buffers/descriptors and fixed metadata, not duplicate
live rows. The producer borrows those columns for commitment, counters and
interactions, validates their lengths/logs and fixed metadata against its admitted
key, and performs no main projection. Existing fixed preprocessing is unchanged.

The shared project helper must clean appended columns on failure under an ordinary
allocator, preserving preexisting list entries. Prepared partial-transfer cleanup
covers main and fixed buffers. Handoff accounting includes column descriptors and
payloads. Row-parity tests become full main-column/fixed-metadata parity; metadata
mutation and malformed main-column checks retain explicit rejection coverage.

This removes retained live rows and producer projection, but assembly still emits
logical rows before final projection. Direct adapter emission is subsequent work.
Validate full native proofs, codec, lifetime/budget denials; no profile/key change.
