# Opcode publication layer

Downstream proof code imports `RiscvRefinement.Publication.Opcodes`. That module
exposes the exact 46-opcode *identity inventory* in manifest order and imports
the canonical, kernel-checkable proof prefixes. The identity theorem does not
assert that all 46 final publication implications exist; only an axiom-audited
receipt may make that claim.

The implementation is organized by ISA/AIR family:

- base ALU and comparisons;
- branches and control flow;
- shifts;
- loads and stores;
- multiplication and high multiplication; and
- division and remainder.

`Acceptance.lean` defines the accepted generated-AIR premise,
`Universal.lean` proves the production-program/admission/fixed-table inventory,
and `Coverage.lean` closes exact local manifest and theorem coverage.

Some implementation paths still carry historical team names so existing
proofs and receipts can be migrated without a flag day. They are private
compatibility structure: do not import them as a public API, derive a proof
grade from them, or add new team-partitioned evidence. New work belongs behind
the neutral `Opcodes.lean` surface and must preserve
`exactOpcodePublicationInventory`.

The complete in-progress issue-136 continuations are intentionally outside the
Lake library in `../../checkpoints/issue-136/`. See that directory's README for
the exact validated boundaries and resume instructions. Checkpoint files are
not imports and are not evidence.
