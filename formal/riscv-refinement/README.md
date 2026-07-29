# RISC-V LUI/ADDI refinement pilot

This Lean project contains the Level-1 LUI/ADDI refinement pilot and Team A's
production AIR IR v2 source binding. It kernel-checks the normalized LUI and
ADDI row predicates against a generated normalized capsule bound to the exact
pinned Sail `execute_UTYPE`/`execute_ITYPE` slices by a checked, fail-closed AST
translation receipt. A separate cross-project Lean check imports the exact
generated backend and proves that its LUI/ADDI execute-clause monads normalize
to that capsule, including the shared sequential next-PC write and `tick_pc`
fragment. All 17 production families and all 46 opcode selectors now
round-trip through the shared production `ConstraintProgram`.

The LUI and ADDI AIR bridges now interpret their generated production programs
directly, derive constraints and ordered relation lookups from evaluated
events, enforce every live fixed-table request, rule out M31 clock wraparound,
and prove the resulting typed rows satisfy `LuiHolds` and `AddiHolds`.
Concrete witnesses pass through those same interpreters. The direct bridge
closes the generated execute-clause boundary, but does not yet cover fetch,
interrupt, trap, counter, or later-step framing in the full generated Sail
step loop. Accordingly, the repository still reports `2/46` as normalized
pilot coverage and does not count either pilot as a publication-level opcode.

## Theorems

- `RiscvRefinement.Opcodes.lui_refines`
- `RiscvRefinement.Opcodes.addi_refines`
- `RiscvRefinement.Air.Bridge.Lui.sound`
- `RiscvRefinement.Air.Bridge.Lui.lookup_projection`
- `RiscvRefinement.Air.Bridge.Lui.acceptance_nonvacuous`
- `RiscvRefinement.Air.Bridge.Addi.sound`
- `RiscvRefinement.Air.Bridge.Addi.lookup_projection`
- `RiscvRefinement.Air.Bridge.Addi.acceptance_nonvacuous`
- `RiscvRefinement.Air.Bridge.Mutations.luiLowLimb_strictly_weaker`
- `RiscvRefinement.Air.Bridge.Mutations.addiCarry_strictly_weaker`
- `RiscvRefinement.Air.Bridge.Mutations.immediateRange_strictly_weaker`
- `RiscvRefinement.Air.Bridge.Mutations.selectorRelabel_strictly_weaker`
- `RiscvRefinement.Air.Bridge.Mutations.reordered_strictly_weaker`
- `RiscvRefinement.NonVacuity.lui_exists`
- `RiscvRefinement.NonVacuity.addi_exists`

The ADDI proof derives its 32-bit result from the four byte equations and four
one-bit carries. The LUI proof derives its word from the four constrained
destination limbs. Neither theorem accepts an aggregate “correct result”
hypothesis.

## Reproduce

Install or select Sail `0.20.2`, Lean is selected by `lean-toolchain`, and
prepare the pinned formal workspace:

```sh
python3 scripts/riscv_formal_tools.py prepare \
  --workspace /tmp/stwo-riscv-formal

python3 scripts/riscv_refinement.py prepare-sail \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
```

The second command recursively applies the repository's normative RV32IM
overrides to the generated RV32 base configuration, validates the resulting
configuration with the pinned simulator, requires the ISA string `rv32im`,
and generates the Sail Lean theorem backend from that exact configuration.

Generate the committed capsules and run the complete pilot gate:

```sh
python3 scripts/riscv_refinement.py generate \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv

STWO_SAIL_RISCV_DIR=/tmp/stwo-riscv-formal/source/sail-riscv \
  zig build riscv-refinement-pilot
```

The gate freshly exports all 17 production symbolic-AIR families plus exactly
46 source-bound AIR IR v2 programs. It rejects manifest, schema, source, event,
or expression drift and differentially checks the shared symbolic program
against the QM31 production evaluator. It then compares every generated file
byte-for-byte, runs coverage and negative controls, runs the Python
infrastructure tests, builds Lean (including strict LUI decode and active/
inactive evaluation guards), scans for proof escapes, and audits every
exported theorem's axioms.

The Stage A2 mutation bundle is checked in Lean against the interpreted
production programs. It proves architectural counterexamples for the free LUI
low limb, deleted ADDI high carry, and ADDI/XORI selector relabel. It also
proves strict loss of the raw immediate-range request and exact event-order
projection. The generated-Sail side of the joint Level-2 gate remains open.
The execute-clause monad and sequential PC/tick fragment are now kernel
checked; the open portion is the wider generated step-loop framing.

After committing all inputs and generated artifacts, create the evidence
receipt:

```sh
python3 scripts/riscv_refinement.py receipt \
  --sail-riscv-dir /tmp/stwo-riscv-formal/source/sail-riscv
python3 scripts/riscv_refinement.py verify-receipt
```

Receipt generation never accepts `--no-export-air`. It records the source
revision and dirty paths, complete generated-manifest digest, exact theorem
axioms, negative controls, coverage, tool binary identities, and the Level-1
claim boundary.

## Generated files

Do not edit these by hand:

- `generated/air/{lui,addi}.json`
- `generated/air/{all 46 manifest mnemonics}.air-ir-v2.json`
- `generated/sail/rv32im-zkvm-v1.json`
- `generated/sail/definitions/{execute_UTYPE,execute_ITYPE}.lean`
- `generated/sail/translation-receipt-v1.json`
- `generated/sail/generated-monad-bridge-receipt-v1.json`
- `RiscvRefinement/Air/Generated/Pilot.lean`
- `RiscvRefinement/Air/Generated/LuiProgram.lean`
- `RiscvRefinement/Sail/Generated/Pilot.lean`
- `generated-manifest.json`

The detailed theorem contract, trusted-base analysis, rollout order, and
publication definition of done are in
[`soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md`](../../soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md).
The exact production AIR wire and interpretation contract is
[`soundness/AIR_IR_V2_CONTRACT.md`](../../soundness/AIR_IR_V2_CONTRACT.md).
