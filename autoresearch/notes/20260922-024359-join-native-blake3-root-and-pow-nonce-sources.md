---
title: Join native BLAKE3 root and PoW nonce sources
author: Teddy Pender
created_utc: 2026-09-22T02:43:59Z
---

# Native BLAKE3 root and nonce source joins

Task: produce bounded private words for root and nonce transcript reads and path
root checks, retaining independent preprocessing-key authority. Reuse private_word
and boundary AIRs and canonical root slots. Verify root zero with the native
statement-derived preprocessed-root verifier; it becomes eight fixed boundary
rows. Other roots remain private. Root multiplicity=transcript reads+query paths.
Both interaction and PCS PoW nonces each require exactly one PoW receipt and one
integer-absorption receipt, with consistent values and exact word read totals.
Complexity O(roots+receipts); no new hashing/arithmetization. Inputs: concrete
verified BLAKE3 capture, native statement/config, interaction nonce, transcript.
Qualification: real capture, root/nonce value and fixed-row parity, changed root
and nonce operation rejected, missing receipt rejected. Full native parent and
public-boundary authority remain outstanding; no performance claim.
