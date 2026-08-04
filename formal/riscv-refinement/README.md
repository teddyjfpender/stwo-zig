# RISC-V AIR-to-Sail refinement

This Lean project checks the RV32IM frontend against the repository's pinned,
generated Sail model. The public claim is organized by verification layer and
opcode family; contributor-team assignments have no semantic meaning.

The concise claim ledger and remaining roadmap are in
[`soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md`](../../soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md).
The detailed theorem contract is
[`soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md`](../../soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md).
The temporary review exception and behavior-preserving split sequence for
oversized promotion proofs is recorded in
[`DECOMPOSITION_PLAN.md`](DECOMPOSITION_PLAN.md).

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

## Publication target and current status

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

The current Lean source closes the row-local FV-1/FV-2 theorem surface for all
46 opcodes: 46 generated-Sail retirement normalizers, 46 accepted-production-
AIR publication implications, the generated full-step framing theorem, and
the typed universal contract. The bridge audit inventory therefore contains
exactly 94 public theorems, and its machine-readable policy records
`constructive_row_local_execution = true`.

The regenerated generated-Sail bridge receipt binds this 46/46 source, the
exact 47-source digest closure, the 94-theorem axiom inventory, and the
constructive row-local policy. Minting and replaying the clean-tree top-level
release receipt remains a publication TODO. Historical continuation snapshots
are itemized in
[`checkpoints/issue-136/README.md`](checkpoints/issue-136/README.md); files
outside the Lake library cannot contribute proof evidence.

FV-3 (Word32/M31 representation), FV-4 (arbitrary-trace composition), and
FV-5 (independent reproduction and review) remain open and blocking. Thus the
46/46 result gates row-local opcode/AIR changes, but does not establish that a
whole frontend trace or an accepted cryptographic proof is sound.

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
  carrying the 46 exact opcode normalizers and observation erasure lemmas.
- `generated-sail-bridge/Composition.lean` — state-indexed decode, generated
  base-arm/full-step framing, and neutral public composition contracts.
- `generated-sail-bridge/ExecutionClosure.lean` — reusable constructors that
  turn componentwise state bindings into exact generated execution.
- `generated-sail-bridge/Decode*.lean` and `Publication*.lean` — split family
  certificates and the 46-opcode public theorem surface.
- `checkpoints/issue-136/` — historical, non-gating continuation snapshots;
  checkpoint files never contribute to the current proof count.
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

Generate the exact production and Sail inputs with live Sail evidence:

```sh
python3 scripts/riscv_refinement.py generate \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
```

Focused repository-Lean and publication-policy checks are below. The live gate
later in this section additionally compiles the external generated-Sail bridge
closure and audits its exact 94-theorem inventory.

```sh
python3 -m unittest scripts.tests.test_riscv_refinement_sail_policy -v
python3 -m unittest scripts.tests.test_riscv_refinement_publication -v
(cd formal/riscv-refinement && lake build)
(cd formal/riscv-refinement && \
  lake env lean RiscvRefinement/AxiomAudit.lean)
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

The full live command reports the bounded claim as 46/46 normalized
retirements and 46/46 row-local publication implications while retaining
`whole_frontend_verified = false` and `proof_system_soundness = false`. Any
later source or artifact identity drift fails closed rather than silently
reusing an old receipt.

After committing every input and generated artifact, create and replay the
receipt:

```sh
python3 scripts/riscv_refinement.py receipt \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
python3 scripts/riscv_refinement.py verify-receipt \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
```

Receipt generation never accepts a carried or stale Sail result as fresh
evidence. The generated bridge runner pins Lean's external source root with
`-R`, creates a fresh temporary olean directory, and compiles all 47 sources in
the ordered `BRIDGE_SOURCES` dependency closure before checking the public
entrypoint. The receipt binds every source path and digest, so changing or
omitting a decoder, execution, arithmetic, or publication module invalidates
the evidence.

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
