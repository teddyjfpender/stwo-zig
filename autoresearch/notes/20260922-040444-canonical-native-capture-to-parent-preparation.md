---
title: Canonical native capture-to-parent preparation
author: Teddy Pender
created_utc: 2026-09-22T04:04:44Z
---

# Canonical native capture-to-parent preparation

Task: one ordered coordinator for the verified native BLAKE3 capture, transcript,
VM/DEEP/FRI graphs, public sums, paths and scalar/byte joins. Reuse all existing
validated adapters and final row assembler. Model the work as a fixed dependency
DAG with reverse-order ownership cleanup. A stable diagnostic State exposes
components for mutation tests; the normal prepare API returns only owned final
rows and pointer-free key context, releasing intermediate owners before return.
No alternate constraint or transcript path is introduced.

Replace test-local preparation calls with State access so the real proof and
mutation fleet exercise the canonical order. Preserve duplicate/missing source
checks. Check the compact API's final rows/context survive intermediate cleanup
and match the canonical state; prove through the standalone producer. This is
ownership/integration work, not a new algorithm or speedup claim.
