# secp input-byte authority and retained relation metadata

Status: metadata/query separation and the receiver-selected Word16
canonical-input provider are implemented. The legacy default retains all
operand range queries. See the separate qualification receipts below.

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
LHS/RHS byte queries would lose that anchor. The Word16 variant retains the
legacy default and selects the canonical-input query schema only in receivers
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

## Receiver authority and protocol boundary

`TruthSetup.byte_policy` is a trusted constant, never a field decoded from the
bundle. Both secp-only and mixed-service Word16 truth transcripts mix a local
query-schema version and digest before MAIN. The digest binds the policy,
query-to-column map, retained metadata extent, component widths and constraint
counts. This gives the changed truth protocol an explicit identity without
repurposing the CPU schema. `local` performs no additional transcript draw and
keeps legacy component defaults, query counts and equations unchanged.

The premise is a closed multiset obligation, not an execution-order induction:
every positive Wire35 occurrence has independently range-checked bytes, either
from a bridge BEFORE coordinate or an arithmetic RESULT. Truth operands consume
unit occurrences; producers have bounded nonnegative program multiplicity.
Existing admission retains its larger legacy BYTE mass bound conservatively.
All nonwire RHS coordinates are constrained to canonical program constants.
Only operand ranges are inherited: RESULT, carry, reduction and internal ranges
remain. This relies on the protocol's existing random relation soundness and
mass limits; it does not establish the separate 128-bit whole-protocol target.

## Adversarial and lifecycle gates

The closed Word16 test builds complete physical proofs with an actual MAIN
operand coordinate equal to 256 in an otherwise valid zero-product row. Its
interaction is computed from committed field coordinates, rather than the
honest retained `u8` cache. Both LHS and RHS variants pass local AIR verification
and are rejected by the aggregate receiver at `UnclosedSecpWire`. Altering the
declared claim to numerically close that debt is also rejected. These are
receiver tests, rather than constructor-only byte rejection.

The scalar/parallel test covers product and linear traces for ADD and DOUBLE,
zero/one/three calls, uneven three-worker partitioning and MAIN release. Full
metadata remains available and reference/parallel interactions agree exactly.
Static tests lock all RESULT anchors, every bridge BEFORE byte anchor, legacy
query compatibility and the distinct transcript identity. Safe/Fast focused
suites and a fresh Ethereum prefix receiver qualify the implementation; the
prefix is explicitly incomplete. Gate records, source delta and exact cell
savings are in
`vectors/reports/rv64-word16-execution-20261101/secp-canonical-input-byte-v1.json`.

The reduction is 84 interaction columns per arithmetic component, not a
whole-block multiplier: the retained reference block saves 61,071,360 native
cells (about 0.29 percent), plus 66,748,416 lifted opening cells before blowup.
CPU proofs remain on their existing separate 2n PCS; secp truth remains 4n.
No device execution, recursion leaf requalification or 128-bit security claim
is made by these CPU qualification gates.

## Next service-domain experiment (not selected)

For secp, a degree-three candidate pairs the linear BYTE denominators and
splits the three Wire fractions into a pair plus a singleton. After the input
trim this costs 448 product and 136 linear interaction columns, versus the
selected 300 and 92. Its approximate domain-point times column area is 54.6
percent (product) and 44.7 percent (linear) of the original full-range 4n lane.
However, committed native cells increase by 12,025,856 over that original lane
on the retained block, while lifted opening width increases as well. A real
candidate must degree-test every direct and interaction residual, qualify
physical closure and measure composition, commitment, opening and recursion
cost together. A smaller domain alone does not justify promotion.

The existing inactive Keccak pair2n prototype similarly trades domain work
for wider commitments: 1,925 MAIN plus 3,896 INTER versus selected 1,923 plus
2,596. Its point-column area is about 64.4 percent of the existing 4n shape,
but committed columns increase 28.8 percent. These truth proofs already use a
separate PCS; neither experiment halves CPU composition or CPU FRI work.
