---
title: Native interactions use main columns and authenticated metadata
author: Teddy Pender
created_utc: 2026-09-22T06:40:11Z
---

# Native interaction ingress from existing main columns

Use the producer's committed-order main columns plus its authenticated logical
fixed metadata to reconstruct one typed row at a time. Extend ColumnRows with an
optional metadata suffix and explicit main_count, validating metadata lengths and
memory aliasing. Full-column callers retain their default behavior. The producer
records each component's main-column range and uses this view for interactions,
without new column allocations or a second generation implementation. Padding stays
explicit. Full native independent verification must pass. Prepared logical rows
are still needed by preparation/counters; this is not full direct-witness completion.
