---
title: Bounded draws emit into transcript hash destinations
author: Teddy Pender
created_utc: 2026-09-22T07:51:15Z
---

# Bounded secure draws write through transcript hash destinations

Reuse exact G/XOR ranges for all fixed-capacity attempts. Every draw frame has
constant encoded length; one canonical hash plan supplies geometry and output
wire IDs across attempts, even when the private counter stops after acceptance.
Keep all capacity slots, retry selection, pending/count transitions and counter
constraints unchanged. Allocate or borrow exact total hash rows; frame writers
fill per-attempt ranges and transcript supplies its final unused list ranges.

Extract draw-frame plan/count helpers shared with raw query batches, avoiding
separate definitions of equal-length draw geometry. Owning and borrowed bounded
APIs share one builder and independently validate destination lengths. Smaller
rows remain arena-owned; temporary frame receipts have scoped backing ownership.

This is destination reuse and immutable plan reuse, not a new rejection algorithm.
No security parameter changes. Verify native rejected-first/accepted-second and
counter boundary cases, owning/borrowed parity and failure cleanup, then native
parent proofs. Record tracked memory without asserting a timing improvement.
