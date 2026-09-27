---
title: Native rejected draw pinned for scheduler qualification
author: Teddy Pender
created_utc: 2026-09-22T00:11:29Z
---

# Native rejection evidence before scheduler replacement

Inspection found no genuine native rejected draw in the transcript proof gates;
previous negatives fabricated invalid words or tried to skip an accepted block.
A bounded eight-thread native-channel search (at most 2^31 seeds / 300 s per
worker) found seed 418109725. It checks the first raw draw after mixU64(seed).
The first word is 0xffffffff; the next two blocks accept. Search completed in
14 s after 417857536 evaluated seeds; seed discovery order is thread-dependent.

Task: pin seed/state/raw blocks as reproducible evidence, validate native single
and bulk consumption, and exercise the true retry branch in a complete transcript
proof. Reuse existing draw and sequence gates, without mining during tests. Exact
native rejection and counter semantics remain unchanged. This is deterministic
replay testing, not a new sampler or a production speed optimization.

The scheduler audit identifies three separate obligations: first-accepted-block
selection, private checked u64 counter transitions, and fixed-capacity scheduling
with an explicit overflow policy. Merely padding draw hashes or fixing the
number of attempts would change the protocol or leave output/counter authority
in the host. Preserve these distinctions for the next implementation stage.
