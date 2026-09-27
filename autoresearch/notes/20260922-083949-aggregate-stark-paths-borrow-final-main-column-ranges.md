---
title: Aggregate STARK paths borrow final main-column ranges
author: Teddy Pender
created_utc: 2026-09-22T08:39:49Z
---

# Aggregate STARK paths borrow final main columns

Mechanical forwarding through the existing opening builder: caller G/XOR metadata
views stand in for live growable lists; each group receives consecutive logical
column ranges. Fixed rows remain independently owned/generated. Smaller live rows
retain ordinary allocation ownership. Complete column geometry is validated before
writes, per-opening slices checked, and exact total consumption checked at finish.
Capture/root/leaf/direction validation and query-read rollback remain unchanged.

Prediction: no aggregate live G/XOR allocation or final row copy is needed for
this mode. Borrowed columns survive receipt destruction; failures may leave
unpublished columns written. Qualify actual captured STARK path reconstruction,
independent fixed rows, all smaller cohorts, and malformed-root rollback. Native
parent allocation/ownership transfer remains the next integration boundary.
