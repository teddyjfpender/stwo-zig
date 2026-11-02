# Bulk worker gates

Pinned PR308 input: `4e94b9dfc6efbd844b39645ee344c17479ba9b40`.
Includes its secp row, capture handoff/EEST and optional segment foundations.
The GKR scope continues to reject unsupported new truth/layout profiles.

This slice closes worker planning, complete cross-shard bulk RAM closure,
request-derived retention admission, and weighted JUMPDEST OWNER accounting.
The native bulk-only wire profile is explicit. Full Ethereum v3 candidate
admission remains closed while its other providers/layouts are integrated.

The qualification uses actual native OM31 physical proofs and fresh receivers,
not mock proofs. Correctness fixtures use q12 and make no new security claim.
See [the bounded review](../../../design/riscv-proving-stack/rv64-bulk-weighted-owner-review.md)
for authority, assumptions, characteristic and retention bounds.

Follow-on candidate gate: the two-shard JUMPDEST execution also passes with
beta2/q256/P0/fold4, independently constructed producer/receiver immutable fixed
leases, complete physical closure and a transport roundtrip. Safe check in
`beta2-candidate-safe.log`. This qualifies operation at the candidate parameters;
it does not certify composed security or admit the full Ethereum v3 roster.
