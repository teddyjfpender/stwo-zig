# RISC-V AIR-to-Sail refinement

This Lean project checks the RV32IM frontend against the repository's pinned,
generated Sail model. The public claim is organized by verification layer and
opcode family; contributor-team assignments have no semantic meaning.

The concise claim ledger and remaining roadmap are in
[`soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md`](../../soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md).
The detailed theorem contract is
[`soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md`](../../soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md).

## Claim boundary

The publication gate is designed to establish two local results for every one
of the 46 admitted RV32IM opcodes:

1. the pinned generated-Sail execute path normalizes to an exact architectural
   retirement; and
2. acceptance of the exact generated production AIR program implies that
   retirement under explicit row, state, profile, and admission bindings.

The gate also checks a premise-free framing theorem for the retained generated
full-step trace. It does not claim that an arbitrary full program trace exists
from a single row, or that local rows compose across the frontend's register,
memory, clock, interrupt, and trap machinery. Those are separate blocking
gates.

The repository therefore keeps:

```text
whole_frontend_verified = false
proof_system_soundness = false
```

until the word/field invariant, whole-trace composition, independent
reproduction, and any separate proof-system obligations are complete.

## Publication target and current checkpoint

The fail-closed publication target uses these public identities:

- `LeanRV32IM.Functions.complete_<OP>_normalizes`, once for each manifest
  opcode;
- `LeanRV32IM.Functions.generated_full_step_retirement_composition`;
- `LeanRV32IM.Publication.<OP>_accepted_air_refines`, once for each manifest
  opcode; and
- `LeanRV32IM.Publication.universal_publication_contract`.

The theorem inventory is fail-closed: exact manifest order, source digests,
fixed-table schemas, theorem names, axiom sets, non-vacuity evidence, and
mutation identities are receipt inputs. Adding a theorem-name string cannot
increase coverage.

The target is not yet fully published. The kernel-clean sources on the default
build and the complete continuation snapshots are itemized in
[`checkpoints/issue-136/README.md`](checkpoints/issue-136/README.md). In
particular, there is no current 46/46 FV-1/FV-2 receipt, and checkpoint files
outside the Lake library cannot contribute proof evidence.

## Repository layout

- `RiscvRefinement/Air/Generated/` — generated typed production constraint
  programs and exact manifest inventory.
- `RiscvRefinement/Air/Bridge/` — proofs interpreting accepted generated AIR
  programs.
- `RiscvRefinement/Opcodes/` — reusable family semantics, witnesses, and
  mutation controls.
- `RiscvRefinement/Publication/` — the exact accepted-AIR publication layer
  and universal coverage contract.
- `generated-sail-bridge/Pilot.lean` — the receipt-bound generated-Sail bridge
  currently carrying two normalized retirements plus exact input equations.
- `checkpoints/issue-136/{Pilot.fv1-kernel-clean,Composition.kernel-clean}.lean`
  — the checked expanded normalizer/full-step continuation, isolated until it
  can be promoted and receipted atomically.
- `checkpoints/issue-136/` — full, non-gating continuation sources and the
  exact proof handoff.
- `scripts/riscv_refinement.py` — primary generation, verification, and
  receipt entry point.
- `scripts/riscv_refinement_publication.py` — exact FV-1/FV-2 publication
  evidence validator.

Historical work-allocation documents and compatibility scripts are not
normative claim surfaces. The root Lean aggregator and publication receipt
must expose one neutral 46-opcode inventory.

## Reproduce

Select the pinned tools and prepare the Sail workspace:

```sh
python3 scripts/riscv_formal_tools.py prepare \
  --workspace /tmp/stwo-riscv-formal

python3 scripts/riscv_refinement.py prepare-sail \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
```

Generate the exact production and Sail inputs:

```sh
python3 scripts/riscv_refinement.py generate \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
```

Run the repository gate when working on promotion:

```sh
STWO_SAIL_RISCV_DIR=/tmp/stwo-riscv-formal/source/sail-riscv \
  zig build riscv-refinement-pilot
```

The gate freshly exports all 17 production AIR families and exactly 46
source-bound programs. It rejects manifest, schema, source, event-order,
expression, lookup, or fixed-table drift; differentially checks the shared
symbolic program against production evaluation; builds Lean; checks the exact
generated Sail bridge; scans for proof escapes; validates non-vacuity and
mutations; and audits theorem axioms.

At this checkpoint the command is intentionally fail-closed before promotion:
it must not report 46/46 while the public generated-Sail composition,
load/store, and division obligations named in the status ledger remain open.
For ordinary work outside formal refinement, the default Lean build and the
frontend's focused tests remain the usable local gates.

After committing every input and generated artifact, create and replay the
receipt:

```sh
python3 scripts/riscv_refinement.py receipt \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
python3 scripts/riscv_refinement.py verify-receipt
```

Receipt generation never accepts a carried or stale Sail result as fresh
evidence. The current generated bridge runner pins Lean's external source root
with `-R` and checks the receipt-bound Pilot against the pinned backend. The
two-module Pilot/Composition runner is preserved under the issue checkpoint
and must be promoted together with a fresh live-toolchain receipt.

## Generated inputs

Do not edit generated artifacts by hand. Important generated surfaces include:

- `generated/air/*.air-ir-v2.json`;
- `generated/sail/rv32im-zkvm-v1.json`;
- `generated/sail/definitions/*.lean`;
- `generated/sail/translation-receipt-v1.json`;
- `generated/sail/generated-monad-bridge-receipt-v1.json`;
- `RiscvRefinement/Air/Generated/*.lean`; and
- `generated-manifest.json`.

A semantic source change must flow through regeneration and invalidate the
corresponding digest, theorem audit, or receipt. Byte-identical regeneration
is part of the publication evidence.

## Review rule

Review claims in this order:

1. inspect the exact theorem signature and caller premises;
2. confirm it consumes `AcceptedProductionEvaluation` for the exact generated
   program rather than a handwritten `Holds` assumption;
3. confirm selector activation and live relations are derived and retained;
4. inspect the theorem's exact axiom list;
5. check its non-vacuity witness and mutation control; and
6. compare the machine-readable claim with the status ledger.

No coverage count or green workflow substitutes for those checks.
