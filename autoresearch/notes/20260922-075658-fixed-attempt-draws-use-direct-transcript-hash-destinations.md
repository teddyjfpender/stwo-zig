---
title: Fixed-attempt draws use direct transcript hash destinations
author: Teddy Pender
created_utc: 2026-09-22T07:56:58Z
---

# Fixed-attempt draws share direct hash destinations

Extend the same owning/borrowed builder to fixed-attempt secure draws and raw
attempt export. Allocate checked exact G/XOR ranges using the shared canonical
draw layout and lend per-attempt ranges to frame/hash writers. Private state uses
frame destinations; public state uses the canonical hash destination with exact
public boundary rows. Fixed public preprocessing must use actual encoded bytes,
not length-only placeholders. Reuse one output plan across all attempts.

Preserve first-acceptance boundary constraints, raw-attempt export semantics,
consumption halves, state-use counts, public/private routing and checked counters.
Transcript fixed-attempt operations supply final unused G/XOR ranges. Temporary
encoding/boundaries and frame results are scoped through bounded backing; borrowed
hash storage must never be freed by result cleanup.

This is destination/lifetime reuse, not changed rejection sampling or security.
Validate public/private and raw/normal owning/borrowed parity, invalid geometry,
allocation failures and existing rejection/counter tests; qualify the complete
transcript proof plus native parent gates. No timing claim without comparison.
