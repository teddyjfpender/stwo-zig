---
title: BLAKE3 paired identity arithmetic and table qualification
author: Teddy Pender
created_utc: 2026-09-22T13:26:01Z
---

# Paired identity arithmetic and table qualification

Added an exhaustive row check for the combined identity witness: authenticated
canonical direct-constraint programs evaluate every packing, encoding, routing,
BLAKE3 G/XOR and boundary row. Every active non-wire relation must be a recognized
byte-range or bitwise table request and must index a valid canonical table tuple.
Unexpected relation kinds fail the check rather than being silently ignored.

The focused ReleaseSafe gate passed in 21 seconds (1 GB reported peak RSS).
Forging an encoded byte fails direct constraints; forging an XOR output fails
table admission. Previous joined wire accounting and message-free fixed metadata
checks remain in the same gate. The new check uses existing canonical AIR and
table definitions, without handwritten replacement hash equations.

This strengthens component qualification but does not produce a STARK proof,
qualify the full statement semantics proof, or establish production admission.
Production assembly, identity claim/key binding, remaining Poseidon commitments,
and multi-level CPU/Metal recursion qualification remain outstanding.
