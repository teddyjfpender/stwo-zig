---
title: Merkle frames emit G and XOR directly into group storage
author: Teddy Pender
created_utc: 2026-09-22T07:15:36Z
---

# Emit frame G/XOR witnesses into their Merkle group destination

Task: remove per-frame G/XOR staging followed by group concatenation. A group has
leaf_count leaf frames and leaf_count-1+depth node frames in canonical order.
Canonical hash plans determine exact row counts from the two encoded lengths.

Transfer: preallocate checked final G/XOR slices once, lend exact nonoverlapping
ranges to each frame, and update XOR output multiplicities in those final ranges.
Frames retain ownership of their smaller boundary/routing metadata; borrowed hash
rows belong to the group. Both live and independently constructed fixed rows use
the destination API. Shared fixed-row writer preserves original equations.

This is exact-size destination allocation and concatenation elimination, not a
new hash or traversal algorithm. Existing node order, namespace checks, input
validation, root linking, payload use counts and boundary filtering remain.
Preallocation avoids invalidating node slices when later frames append. All size
arithmetic is checked and destination geometry is admitted before hash writes.

Prediction: eliminate the group's duplicate G/XOR buffers and their arena growth.
Actual preparation peak may instead be dominated by another adapter. No timing
claim without a dedicated comparison. This still emits logical rows at the group
boundary; final native columns and transcript emission are subsequent work.

Validation: borrowed/owned live and fixed frame parity, invalid destination
unchanged before writing, borrowed buffers surviving receipt destruction,
allocation failures; native independent parent proof and recorded memory metrics.
