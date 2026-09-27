---
title: Replay native V2 transcript through canonical encoders
author: Teddy Pender
created_utc: 2026-09-22T01:39:23Z
---

# Native V2 BLAKE3 transcript adapter

Task: translate an already verified native V2 BLAKE3 capture into the existing
bounded recursive transcript witness. Canonical match: protocol replay through
an owning event sink, reusing exact native encoder functions rather than copying
their wire format. Native V2 uses configuration/public-data binding, authenticated
physical lookup manifest, trace roots, sharded main claims, interaction PoW,
native relation pairs, physical-layout interaction claims, interaction root and
the canonical core STARK/PCS suffix. It is not the fixture's universal prefix.

Use an owning recorder for temporary stack-backed encoder slices. Void mix APIs
latch allocation errors; checked draw/finalization paths propagate them. Delegate
hashing/draws to core BLAKE3. Route roots, interaction nonce and field-valued
interaction claims through explicit external ports; export native relation pairs
with a distinct semantic role. Keep public statement/config/shape encoding public
at this stage. Existing suffix builder owns its framing and capture comparisons.

Compile the reusable bounded plan, prepare live rows, and compare final digest
and counter with the independently verified native channel. Check native relation
draws against the captured VM context; validate capture and statement authority
before replay. Independently mutated claims must fail replay. No new AIR or native
protocol bytes. O(encoded bytes + admitted retry capacity) witness work; no speedup
prediction. Native input/public-boundary composition and parent joins remain
required; this adapter by itself does not qualify a full recursive native parent
or a statement-independent production key.
