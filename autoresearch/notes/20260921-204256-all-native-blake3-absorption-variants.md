---
title: All native BLAKE3 absorption variants
author: Teddy Pender
created_utc: 2026-09-21T20:42:56Z
---

# Native absorption variants in one transcript sequence

Task: extend the existing deterministic transcript sequence with word, QM31 and
root absorption, preserving native framing and counter resets. Exact transfer:
use existing Frame.words/Frame.felts/Frame.root and the same state transition
assembly as integer absorption. Arrays and root values are public operation
payloads in this gate; intermediate channel states remain authenticated privately.
Root absorption introduces a bounded public digest source in its own namespace
and routes both state/root roles through the existing frame router. Words and
felts use the shared native serializer, including lengths and canonical M31 words.

No new algorithm, AIR or security parameter. Namespace accounting includes root
sources; exact root multiplicities come from the router. Alternative duplicate
absorption implementations would risk framing/reset drift and are rejected.
Validate native mixed-operation outputs, empty arrays, high-bit raw words/root,
nontrivial QM31 coordinates, fixed columns and complete CPU sequence proof.
Private payload admission, raw queries and PoW remain separate obligations.
