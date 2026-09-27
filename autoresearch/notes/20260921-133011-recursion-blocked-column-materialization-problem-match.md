---
title: Recursion blocked column materialization problem match
author: Teddy Pender
created_utc: 2026-09-21T13:30:11Z
---

# Recursive columns: blocked transpose composed with row permutation

Task: write a logical row-major matrix into column-major committed buffers using
committedRow(logical, log), leaving missing rows zero. This exact permutation is
part of the proof format and must not change. Existing loop scatters one word to
each column at widely separated physical rows. Stack sampling identifies these
writers and memory operations as material host costs.

Canonical match: matrix transpose plus a bijective index permutation (derived).
Use physical row tiles of 32, invert the existing core permutation once per row,
then gather each column from the same cache-resident source rows and write one
contiguous destination tile. Work remains O(rows * columns), bounded pointer/index
scratch O(32), no new allocation or protocol changes. Metadata-only padding is
skipped and the caller's initial zeros are retained.

Alternative: logical-order scatter (current oracle) avoids rereading source
cache lines but scatters every store; full transpose scratch doubles live memory.
Selected transfer: bounded tiling, informed by the cache-local execution principle
in https://ir.cwi.nl/pub/11098; actual crossover is hardware-specific hypothesis.
No imported code or dependency. Retain simple path for tiny traces if measurements
show a crossover. Predict lower fixed/main and typed-interaction staging time;
reject if complete-parent time or memory regresses.

Validation: compare both tree selectors against scalar committedRow oracle for
empty, partial, boundary and full traces, followed by byte-identical independently
verified complete parents. Separate experiment from packed ledger; record source
patch and binary identities for each.
