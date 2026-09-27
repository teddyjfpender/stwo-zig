---
title: Canonical resident BLAKE3 transcript mapping
author: Teddy Pender
created_utc: 2026-09-22T11:10:09Z
---

# Resident BLAKE3 transcript mapping

Task: execute exact canonical root/word/felt/integer absorption and secure-field
sampling on resident Metal data for FRI integration. Reuse the qualified BLAKE3
streaming hash; this is protocol transfer rather than a new hash algorithm.
State: eight digest words, two LE32 words for u64 n_draws, sticky error word.
Mapping: domains 1/2 carry u64 element counts; 3 carries integer LE64; 4 a full
root; 5 draws from digest plus LE64 counter. Absorption resets n_draws. A draw
accepts an entire eight-word block iff every word is <2*p, then reduces modulo
p; up to two QM31 values per block. Odd counts discard unused coordinates.
Exact variant: rejection sampling of uniform u32 into M31 with two preimages.
No retry cap is introduced. Counter exhaustion fails rather than wrapping.
Sources: src/core/channel/blake3.zig and blake3_frame.zig; BLAKE3 reference
https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs
State and buffer arithmetic use checked host spans; overlap is rejected.
Test plan: compare state and output with CPU across all admitted domains,
chunked payloads, odd/even draws, counter crossing 2^32, exhaustion and guards.
Limits: on failure output may be partially written; sticky error prevents reuse.
No end-to-end performance prediction until cascade integration is measured.
