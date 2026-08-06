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
