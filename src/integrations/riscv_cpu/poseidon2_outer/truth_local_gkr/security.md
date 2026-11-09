# Schema2 additive security accounting

This is a source-derived engineering ledger under the existing documented
OM31, Poseidon2, PCS/FRI and Fiat–Shamir assumptions. It does not certify
whole-protocol security; `security_qualified` remains false.

The classic source lookup report remains conservative for tuple-compression,
rational-identity and pole terms: local GKR consumes exactly the original
Keccak chi/xor and secp byte fractions, with identical active and padded query
weights, source-owned table support and multiplicities. Unused power-of-two
GKR lanes are exactly0/1. They introduce no random lookup pole. Each proof's
positive integer mass is bounded below the M31 characteristic before allocation;
independent local scopes are not incorrectly combined into one characteristic
mass. Global RAM/KIO/Wire challenges and their joint mass/closure are unchanged.

Classic native MAIN equations are reused without modification. The replacement
has fewer local interaction columns/constraints, the same original MAIN masks
and at most two masks on each new binding column. Original Keccak degree5/4n
and secp degree3/2n bounds remain conservative. The old source report alone does
not account for the new GKR challenges and terminal binding.

`security.derive(declarations)` adds those terms using the source geometry before
constructing keys. For each eligible, nonempty three-role truth scope, let `v`
be its maximum row-plus-query variable count:

- Sumcheck rounds: `v(v−1)/2`; conservative degree weight `3*3*v(v−1)/2`.
- Instance/layer mixing weight: `(3+2)*v`.
- Late terminal-marginal mixing: three independently constrained targets.
- Degenerate Eq-point coordinates: twice the sum of the three row logs.

These are the existing OM31 candidate ledger formulas specialized to one
three-instance source scope. The Eq/prefix binding still requires the documented
multilinear-to-circle binding theorem and the native PCS/OODS assumptions; a
numerical degree ledger does not establish that theorem or a concrete ROM bound.
Fixed-four coefficient encoding changes no degrees or round counts.

For the actual338-call compact Keccak scope (logs13/13/10,1920/1/1 queries),
`v=24`,276 rounds,15,728,640 positive queries, and added degree weights are
2484/120/3/72. The helper also updates source-shape maxima to include three local
instances and the actual GKR variable count. It reports retired interaction
cells separately from cryptographic error terms.

Callers must retain `Bounds.deriveForOp`, then call `derive` and `augmentShape`
before source-shape admission. Add this report to the *full* existing algebraic
ledger with `addTo`; do not replace CPU GKR, global lookups, polynomial
compression, PCS/FRI, hash/FS or recursive proof accounting with this report.
The unit test's128-bit check covers only the added conditional terms, using the
existing candidate's conservative maximum-density envelope. For ideal uniform
OM31 challenges the raw-modulo envelope is weaker (therefore conservative);
this does not turn the Poseidon2 transcript into a raw Blake/random-oracle
construction or discharge its separate permutation/ROM assumptions.

Whole execution acceptance still requires exact ordered workers, source keys,
manifest/receipts, initial image, CPU adjacency, terminal43-byte output, global
RAM/KIO/Wire closure and the authenticated recursive root. Functional schema2
proof success is distinct from the security classification above.
