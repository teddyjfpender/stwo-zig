---
title: Project native hash source chunks without live concatenation
author: Teddy Pender
created_utc: 2026-09-22T07:09:38Z
---

# Project exact native hash cohorts without concatenating live rows

Task: remove parent-assembler live-row copies for G, XOR and byte-route cohorts.
These have exactly two canonical inputs, transcript then Merkle paths, known
before assembly. No later inventory or fusion reads their concatenated rows.

Transfer: shared column projection accepts ordered row chunks and writes each at
its logical offset using the existing committed-index permutation. Single-slice
projection delegates to the same path. Parent retains trusted fixed metadata,
checks every source metadata suffix as before, and projects original source chunks
without constructing intermediate live arrays. Zero padding and row order remain.

This is concatenation elimination with a segmented input view, a mechanical data
layout change. Time remains linear in projected input/domain and column count;
projection visits a domain per chunk (two here), so no timing win is promised.
Peak savings are conditional on later graph/fusion scratch overlap. This removes
assembler duplication, not the upstream adapters' logical witness generation.

Validate chunk projection against logical row coordinates including empty chunks
and padding, malformed log/oversized input rejection, then full native proof and
handoff parity. Preserve partial-allocation cleanup and independent fixed rows.
