---
title: Native path adapter owns final row allocations
author: Teddy Pender
created_utc: 2026-09-22T06:17:25Z
---

# Individually owned rows in the native Merkle-path adapter

Task: remove retained ArrayList growth storage inside blake3_stark_paths without
changing Merkle authentication or query input linkage. Its six live/fixed row lists
currently allocate through the adapter's retained arena, including large G rows.

Selected transfer: use the backing allocator for final row lists, while link and
geometry data remain arena-owned. Prepared explicitly owns/free its row arrays;
Builder cleans unfinished lists, and finish cleans partial transfers on failure.
Each group remains independently validated and copied through the canonical append.
No new Merkle equations, direct-copy bypass or changed namespace is introduced.

This applies the measured final-buffer ownership improvement at the preceding
adapter layer. Full native source/root mutation, row parity, handoff, failure
cleanup and independent proof gates must pass. Compare preparation peak allocation;
final parent retention should remain unchanged. Group-to-adapter copying and direct
column generation remain separate unfinished work. No speed/profile change claimed.
