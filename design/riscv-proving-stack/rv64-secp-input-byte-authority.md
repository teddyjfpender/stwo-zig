# secp input-byte authority and retained relation metadata

Status: metadata/query schema separation qualified; canonical-input range
removal requires a distinct receiver-selected Word16 provider. No production
range query is removed by this foundation commit.

The product and linear providers retain 284 and 128 bytes per active row.
Those bytes serve two obligations: BYTE range queries and the LHS/RHS/RESULT
coordinates of Wire35. MAIN release cannot discard an operand merely because
its range query is later inherited from the closed wire relation. Metadata
extent and byte-to-column mapping therefore have their own layout authority,
independent of the BYTE query count/map. The parallel interaction recipe and
its scalar reference both reconstruct the full wire operands from that retained
metadata after MAIN is released.

The current Word16 bridge ranges all 32 BEFORE and AFTER bytes independently
(`secp256k1/word16_bridge/layout.zig: U8`). Every positive truth Wire35 producer
ranges its 32 RESULT bytes. With positive bounded producer weights, unit
consumer weights, and total mass below the field characteristic, closed Wire35
therefore transfers byte canonicality to the consumed operands. Nonwire RHS
operands are independently bound to canonical fixed small/modulus bytes by the
existing active-row constraints. RESULT and internal arithmetic ranges must
remain; replacing them would remove the producer anchor.

This premise is NOT true for every older accepting route. The legacy
`secp256k1/bridge/layout.zig` RANGE_COLUMNS excludes BEFORE/AFTER and its comment
explicitly relies on the arithmetic byte authority. Globally removing the
LHS/RHS byte queries would lose that anchor. A future variant must retain the
legacy default and select the canonical-input query schema only in receivers
that establish canonical positive Wire35 producers. A declared profile from an
untrusted proof cannot choose the premise.

Conditionally removing 64 duplicate operand queries changes product BYTE
284 -> 220 and INTER 384 -> 300; linear BYTE 128 -> 64 and INTER 176 -> 92.
Both MAIN layouts and the full metadata payload stay unchanged. Current
separate truth proofs are 4n and CPU proofs are already 2n; this does not claim
an improvement to the CPU proof's composition domain. Degree-three service
variants need separate accounting: stricter pair inverses may increase their
interaction width even while reducing composition points.

The source-level cost and Safe/Fast metadata qualification are recorded in
`vectors/reports/rv64-word16-execution-20261101/secp-query-metadata-separation-v1.json`.
Whole-protocol128-bit security and GPU execution are not established here.
