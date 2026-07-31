# RISC-V soundness documentation

Start with
[`RISCV_FRONTEND_VERIFICATION_STATUS.md`](RISCV_FRONTEND_VERIFICATION_STATUS.md).
It is the single claim ledger and forward roadmap. In particular,
`whole_frontend_verified = false` until every blocking FV gate named there is
kernel-checked, reproduced, reviewed, and promoted.

## Normative contracts

- [`UNIVERSAL_AIR_SAIL_REFINEMENT.md`](UNIVERSAL_AIR_SAIL_REFINEMENT.md) —
  repository-wide AIR-to-generated-Sail refinement contract.
- [`AIR_IR_V2_CONTRACT.md`](AIR_IR_V2_CONTRACT.md) — production AIR wire and
  interpretation contract.
- [`SAIL_AIR_COMPOSITION.md`](SAIL_AIR_COMPOSITION.md) — generated-Sail
  composition boundary.
- [`INDEPENDENT_PROOF_SYSTEM_VALIDATION.md`](INDEPENDENT_PROOF_SYSTEM_VALIDATION.md)
  — proof-system validation boundary, which is separate from frontend
  refinement.
- [`SAIL_PROVISIONING.md`](SAIL_PROVISIONING.md) — reproducible pinned-Sail
  provisioning.

## Evidence and history

- [`../formal/riscv-refinement/checkpoints/issue-136/README.md`](../formal/riscv-refinement/checkpoints/issue-136/README.md)
  is the exact continuation handoff for the current FV-1/FV-2 checkpoint. Its
  source snapshots are explicitly non-gating.
- [`ROADMAP.md`](ROADMAP.md) is the dated engineering evidence log retained
  behind the current ledger; it is not a second roadmap.
- `TEAM_AB_INTERFACE.md` and `TEAM_B_SAIL_REFINEMENT_CONTRACT.md` are
  historical rollout records. Their contributor labels are not semantic
  partitions, verification grades, or current ownership boundaries.

Public claims, proof imports, and machine-readable publication evidence are
organized by verification layer and opcode family. Historical script or file
names may remain temporarily as compatibility inputs, but they cannot increase
the active proof count or appear as a publication classification.
