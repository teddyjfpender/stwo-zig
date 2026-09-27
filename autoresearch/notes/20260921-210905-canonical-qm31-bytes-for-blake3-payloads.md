---
title: Canonical QM31 bytes for BLAKE3 payloads
author: Teddy Pender
created_utc: 2026-09-21T21:09:05Z
---

# Canonical QM31-to-byte encoding

Task: bind a recursion-wire QM31 tuple to the unique little-endian byte encoding
of its four M31 coordinates. A field equality alone is insufficient: bytes for p
would alias zero. Exact certificate per coordinate: byte bounds plus high byte
AND 127 == high byte restrict the integer to [0,p]. Let d=892-sum(bytes); within
these bounds d=0 iff bytes encode p. Constrain d*inverse=1 and field reconstruction
to the authenticated coordinate. This excludes p and establishes canonicality.

Use existing range8_8 and bitwise tables; four coordinate reconstructions and
four inverse checks are quadratic direct constraints. Consume one QM31 wire and
emit four packed-word wires with verifier-owned copy counts. Zero padding uses
fixed enable=0. No new table, field reduction rule or handwritten evaluator.

Validate native boundary encodings, aliases p and high-bit words, byte/table and
value/inverse mutations, typed identity/export, then a complete hash proof that
consumes encoded field words through the existing private input bridge. Public
fixture source values are not production private payload admission. No speed claim.
