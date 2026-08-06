# Milestone receipts

This directory records reproducible evidence for typed-AIR milestones. A
receipt names an immutable evidence commit and tree, the tools and exact gates
run against a clean checkout, artifact identities, negative results, and the
claims that remain open.

A receipt is evidence, not authority. It does not activate generated code,
change the proof protocol, waive a failing gate, or promote any claim in the
[RISC-V verification ledger](../../../soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md).
The immutable commit named by a receipt is the subject of the evidence; the
later commit that adds the receipt is intentionally not self-referential.

## Receipts

- [`m3-compatibility-v1.json`](m3-compatibility-v1.json) records the M3
  compatibility-lowering checkpoint. All 17 typed shadow manifests and their
  runtime/formal projections are exact. The receipt deliberately leaves M3
  release promotion open because the broad prover-core gate exposes existing
  witness-rigidity findings.
- [`h007-poseidon-proof-equivalence-v1.json`](h007-poseidon-proof-equivalence-v1.json)
  records the H-007 proof-path checkpoint. Authenticated typed Poseidon main,
  and interaction artifacts enter their real CPU and Metal commitments;
  transcript and component claims enter the proof, and the returned claim is
  reconciled after proving. Both honest proofs verify through the unchanged
  production verifier. The path remains explicitly test-only, uses
  integration-test non-production-security PCS parameters, and leaves canonical
  cross-backend identity attestation to V-006.
- [`h009-poseidon2-cost-frontier-v1.json`](h009-poseidon2-cost-frontier-v1.json)
  records the isolated H-009 bounded materialization search. The complete
  declared one-edit neighbourhood is a structural cost plateau, with exact
  artifacts and regression gates pinned. It activates no layout and makes no
  timing, memory, proof-size, or global-optimality claim. H-010 subsequently
  measured representative cuts without selecting a layout.
- [`v006-poseidon-program-identity-v1.json`](v006-poseidon-program-identity-v1.json)
  records the final test-only backend-neutral semantic, layout, executor,
  relation, and combined Poseidon identities against one clean CPU/Metal
  evidence snapshot. The identity is locally co-attested beside verified
  proofs; it is not transcript-bound, part of the public statement, or checked
  by the production verifier.

## H-010 receipt publication

The
[H-010 receipt](h010-authenticated-poseidon-layout-benchmark-v1.json) records
clean implementation commit `82bf6b9cd5eb1ab48edd6fb7c0c88a3be687e8c6`, tree
`8cbb9300fa9b820baa079eeb94addf71db97f130`, and two independently
valid complete default reports retained locally as ignored evidence:

- `v2`: 337,144 bytes, SHA-256
  `98abdf472818e21e43ff0e3cc3d509598558a6df6c1c215ea789a997fb5bc25d`;
- `v3-confirm`: 337,146 bytes, SHA-256
  `eabeba5d67b26574dbe4246f8924411fe7c1df252452d078688ae6a0bcb5682a`.

Each report contains all 112 required fresh sample children with zero failures,
retries, or drops under the same executable and source-closure identities. The
reports show no meaningful repeatable layout regression; q0 and q100 log-14
witness directions flip within MAD/noise. The receipt therefore selects no
layout and preserves false proof, Metal-candidate, production-layout, and
promotion claims.

The checked vectors and readable index are protocol inputs, while the report
bytes remain local timing evidence pinned by size and SHA-256. Publishing the
receipt does not move either class into the proof transcript, public statement,
production verifier, or product authority.
