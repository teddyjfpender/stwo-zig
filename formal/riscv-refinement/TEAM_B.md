# Team B rollout status

Team B of the Universal AIR → Sail refinement plan (issue #137) owns 22 of the
46 admitted RV32IM opcodes, across six AIR families, plus the generated-Sail
normalization obligation.

Normative contract: [`../../soundness/TEAM_B_SAIL_REFINEMENT_CONTRACT.md`](../../soundness/TEAM_B_SAIL_REFINEMENT_CONTRACT.md).
Machine-readable status: [`team-b-coverage.json`](team-b-coverage.json).

## What is claimed

**Coverage is 1/22 proved.** Every other entry is `refined`: it has a
refinement theorem and tuple projections, and usually a non-vacuity witness, but
no Lean mutation control, so it does not count.

**No entry is publication-level.** The architectural side of every Team B
theorem is a *reviewed normalized capsule*, not a generated-Sail theorem,
because the pinned Sail toolchain is not provisioned in the environment these
proofs were developed in. Each such file says so in its header. Replacing those
capsules with generated Sail definitions, together with a checked translation
receipt, is the open obligation — the same one the existing LUI/ADDI capsule
carries.

## Certificate states

| State | Meaning | Required fields |
| --- | --- | --- |
| `open` | nothing yet | — |
| `capsule-only` | AIR capsule exists, no refinement theorem | — |
| `refined` | refinement theorem and tuple projections | refinement, tuple |
| `proved` | plus a witness and a load-bearing mutation | refinement, tuple, non-vacuity, mutation |

A state cannot overstate what exists: `scripts/riscv_team_b.py coverage`
refuses a certificate claiming a state without the fields that state requires,
and `theorems` refuses a certificate naming a theorem that is not in the Lean
sources.

## Families

| Family | Opcodes | Capsule | Notes |
| --- | --- | --- | --- |
| `shifts_reg` | SLL, SRL, SRA | `Air/Family/Shifts.lean` | shares the `shift_common` layer with the immediate family |
| `shifts_imm` | SLLI, SRLI, SRAI | `Air/Family/Shifts.lean` | |
| `load_store` | LB, LH, LW, LBU, LHU, SB, SH, SW | `Air/Family/LoadStore.lean` | LH is the Stage B2 stress gate |
| `mul` | MUL | `Air/Family/Multiply.lean` | the one `proved` entry |
| `mulh` | MULH, MULHSU, MULHU | `Air/Family/Multiply.lean` | |
| `div` | DIV, DIVU, REM, REMU | `Air/Family/Div.lean` | the Stage B3 stress gate |

Each capsule records the SHA-256 of the exported production AIR it was
transcribed from. `scripts/riscv_team_b.py ir-digests` recomputes those digests
from a fresh `zig build riscv-refinement-ir` export and fails closed on any
difference, so a production AIR change invalidates the transcription rather than
silently diverging from it.

## Two things the stress gates surfaced

**Address wrap is not reachable in an admitted row.** The production
`load_store` AIR bounds addresses twice: the base-address `range_check_m31`
forces the high limb of `rs1` below 128, and the aligned-address
`range_check_20` request carries `aligned / 4`, so `aligned < 2^22`. A true
32-bit address wrap therefore cannot occur in an admitted production row.
Architectural wrap is real and the Sail side defines it; the AIR narrows it
away. An LH theorem must carry that range premise explicitly rather than claim
the AIR derives wrap behaviour.

**Alignment is enforced by a range check, not an equation.** For LH, LHU, SH,
LW and SW the only thing forcing natural alignment is that same
`range_check_20` on `aligned / 4`. The Lean capsule encodes this structurally,
carrying `alignedQuarter` with `alignedAddress = 4 * alignedQuarter`, rather
than asserting an alignment equation the AIR does not contain.

## Gates

Run from the repository root.

```sh
# Export the production symbolic AIR the capsules are bound to.
zig build riscv-refinement-ir -Driscv-refinement-ir-dir=zig-out/team-b-ir

# Coverage, certificates, profile claims, and AIR bindings.
python3 scripts/riscv_team_b.py check --air-ir-dir zig-out/team-b-ir

# Non-vacuity witnesses checked against the production AIR, not the capsule.
python3 scripts/riscv_team_b_witnesses.py --air-ir-dir zig-out/team-b-ir

# Every theorem, and the axiom audit.
cd formal/riscv-refinement && lake build
lake env lean RiscvRefinement/AxiomAudit.lean
```

Hosted equivalent: `.github/workflows/riscv-team-b-refinement.yml`. It has no
skip path — toolchain provisioning is verified against `lean-toolchain` rather
than inferred from a later step succeeding — and a scheduled clean-room job
rebuilds everything from empty caches and re-checks the environment through
`leanchecker`.

## Why the witnesses are checked twice

A Lean non-vacuity theorem proves a row satisfies the *transcribed capsule*. If
the transcription drifted, that row could be unreachable in production and the
"honest witness" would be honest about the wrong system.
`scripts/riscv_team_b_witnesses.py` evaluates the same witnesses against the
*exported production* AIR — every constraint root over M31 and every active
range request against the widths the production tables actually provide. A
witness that passes both is reachable in the shipped AIR and satisfies the
capsule.

It is a cross-check, not a substitute for either: it cannot prove the
transcription is faithful, only refute a witness that is not reachable.
