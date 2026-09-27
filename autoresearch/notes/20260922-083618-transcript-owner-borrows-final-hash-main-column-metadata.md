---
title: Transcript owner borrows final hash main-column metadata
author: Teddy Pender
created_utc: 2026-09-22T08:36:18Z
---

# Transcript owner borrows final main-column metadata

Mechanical destination integration: retain canonical operation traversal and
producer indices while replacing G/XOR list allocation with caller metadata
views in explicit column mode. Each operation slices the validated parent view
at current logical row counts and forwards it to the already qualified adapter.
Smaller row cohorts and receipts retain existing allocator ownership. Borrowed
hash metadata is never resized or freed. Final used counts must match supplied
geometry; later semantic/count failures may leave unpublished columns written.

Plan entry validates fixed-plan identity and exact G/XOR counts before emission,
then independently fingerprints emitted metadata and receipts against fixed
preprocessing. Generated metadata never becomes key authority. Check row-mode
reconstruction, receipts, independent fingerprint admission, ownership after
receipt destruction and failure cleanup. No algorithm, parameter or timing claim.
