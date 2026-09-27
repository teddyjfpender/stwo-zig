---
title: Transcript witness final row ownership
author: Teddy Pender
created_utc: 2026-09-22T06:21:29Z
---

# Transcript witness row ownership

Task: remove retained row-growth allocations in blake3_transcript_witness, applying
the independently qualified native/path ownership pattern to the transcript layer.
Eight large row lists currently share the returned metadata arena. Their completed
values contain M31 arrays, not pointers into transient storage.

Transfer: allocate row lists through backing, retain metadata/read vectors in the
arena, and transfer each exact row slice into Prepared with an explicit allocator.
Keep cleanup for unfinished lists and each completed slice on subsequent failure.
Do not change state replay, bounded retry scheduling, canonical row generation or
plan authentication. Both trusted and live preparation use the same implementation.

Validation: focused transcript-plan ownership tests and full native proofs. Compare
preparation peak and verify identical key/artifact size. This removes allocation
retention but does not eliminate per-operation witness generation or copying into
the final parent layout. No timing/security profile changes claimed.
