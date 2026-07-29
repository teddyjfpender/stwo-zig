# RISC-V LUI/ADDI refinement pilot

This Lean project contains the Level-1 LUI/ADDI refinement pilot and the first
Team A Level-2 AIR-side binding for LUI. It kernel-checks the normalized LUI
and ADDI row predicates against a reviewed normalized capsule of the pinned
Sail definitions. Separately, LUI's production `ConstraintProgram` now
round-trips through canonical AIR IR v2 and a strict Lean M31,
event/projection, and fixed-table interpreter.

The AIR-side round trip does not yet prove that the interpreted production
program implies the normalized `LuiHolds` predicate, and the full generated
Sail monad does not yet reduce to the reviewed capsule. Those composition and
Team B bindings remain Level-2 promotion gates. Accordingly, the repository
still reports `2/46` as normalized pilot coverage and does not count LUI as a
publication-level opcode.

## Theorems

- `RiscvRefinement.Opcodes.lui_refines`
- `RiscvRefinement.Opcodes.addi_refines`
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

The gate freshly exports all 17 production symbolic-AIR families plus the
source-bound LUI AIR IR v2 program. It rejects schema, source, event, or
expression drift and differentially checks the shared symbolic program
against the QM31 production evaluator. It then compares every generated file
byte-for-byte, runs coverage and negative controls, runs the Python
infrastructure tests, builds Lean (including strict LUI decode and active/
inactive evaluation guards), scans for proof escapes, and audits every
exported theorem's axioms.

The current mutations check weakened-row counterexamples and exact-shape
validator sensitivity. They do not yet invoke pinned Sail on the counterexample
or feed a mutated predicate through Lean; those are explicit Level-2 gates.

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
- `generated/air/lui.air-ir-v2.json`
- `generated/sail/rv32im-zkvm-v1.json`
- `RiscvRefinement/Air/Generated/Pilot.lean`
- `RiscvRefinement/Air/Generated/LuiProgram.lean`
- `RiscvRefinement/Sail/Generated/Pilot.lean`
- `generated-manifest.json`

The detailed theorem contract, trusted-base analysis, rollout order, and
publication definition of done are in
[`soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md`](../../soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md).
The exact production AIR wire and interpretation contract is
[`soundness/AIR_IR_V2_CONTRACT.md`](../../soundness/AIR_IR_V2_CONTRACT.md).
