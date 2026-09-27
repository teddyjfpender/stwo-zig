---
title: Merkle groups forward native main-column hash destinations
author: Teddy Pender
created_utc: 2026-09-22T08:29:44Z
---

# Merkle groups forward main-column destinations

Task: mechanically carry the qualified hash/frame main-column destination through
canonical Merkle group construction. Inputs are admitted leaf/subtree/path geometry;
counts and existing traversal order remain authoritative. Each leaf and merge takes
consecutive metadata and physical-column logical-offset ranges. No hash, traversal,
or constraint algorithm changes. Complexity remains linear in emitted hash rows.

Preserve independent trusted preprocessing, digest-root routing and XOR metadata
use-count updates. Admit the complete destination before any leaf writes. Receipt
arenas never own caller columns. A returned flag explicitly identifies metadata-only
G/XOR rows. Compare reconstructed rows with owning group witnesses, trusted suffixes,
all smaller cohorts and roots; test both public and selected path directions,
nonzero offsets, malformed late-cohort shape before writes, and receipt destruction.
No timing improvement claimed until parent integration and full-profile measurement.
