---
title: BLAKE3 challenge block reduction and whole-block rejection
author: Teddy Pender
created_utc: 2026-09-21T20:10:43Z
---

# BLAKE3 challenge block reduction and rejection

Task: constrain the native channel's entire eight-word draw: reject the block if
any u32 is >= 2p (p=2^31-1), otherwise reduce every word modulo p. All eight must
be checked even when a single QM31 consumes only the first four.

Canonical match: bounded-byte integer predicate plus field reduction and a
Boolean conjunction. Source semantics: src/core/channel/blake3.zig sampleWord
and drawBaseFelts. Existing byte-pair tables bound input coordinates; authenticated
hash-output wires bind all 32 digest bytes. Output wires use scalar QM31-coordinate
representation (value,0,0,0), not packed-byte representation.

Derived exact predicate: for bounded bytes b0..b3, let
 t=(b0-254)(b0-255), d=t+765-b1-b2-b3.
Both summands are nonnegative integers and d < p; d=0 exactly for fffffffe or
ffffffff. Materialize t; constraints d*inverse=valid and d*(enable-valid)=0
make valid exactly the nonzero predicate without a high-degree zero test.
For accepted words, value=sum(256^i*b_i) in M31 is the required reduction.
Rejected word value is zero. A seven-step materialized product computes whole
block acceptance. Output field emissions are multiplied by that acceptance;
a separate status wire exposes acceptance to the future retry scheduler.

Alternative: bit-decompose every word or add a large comparison table. The
bounded nonnegative certificate uses the existing byte-pair table and only
quadratic direct roots. Native rejection probabilities are irrelevant to
soundness: both invalid words and invalid words in the unused half are tested.

Qualification plan: pinned typed definition, native threshold vectors and
random block parity, production table membership, validity/value/product
mutations, padding, exact output weights and framework compiler/export. Full
transcript retry ordering and binding to authenticated draw hashes remain
required integration work; this block alone cannot authorize skipping a draw.
