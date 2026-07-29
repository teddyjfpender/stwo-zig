# Team B rollout status

Team B of the Universal AIR → Sail refinement plan (issue #137) owns 22 of the
46 admitted RV32IM opcodes, across six AIR families, plus the generated-Sail
normalization obligation.

Normative contract: [`../../soundness/TEAM_B_SAIL_REFINEMENT_CONTRACT.md`](../../soundness/TEAM_B_SAIL_REFINEMENT_CONTRACT.md).
Machine-readable status: [`team-b-coverage.json`](team-b-coverage.json).

## What is claimed

**Coverage is 16/22 proved** — DIV, DIVU, LH, MUL, MULH, MULHSU, MULHU, SB, SH, SLL, SLLI, SRA, SRAI, SRL, SRLI, SW.
Each carries a refinement theorem, tuple projections, a non-vacuity
witness, and a load-bearing mutation control whose soundness hypothesis is
**discharged in-file**, so every `*_is_load_bearing` corollary is
unconditional. The remaining 6 are `refined`, each for a stated reason that
must survive any future change to the numbers: REM and REMU have **no
mutation control at all**; LB, LW, LBU and LHU have controls only at
**family granularity** — no control exhibits a witness row carrying their own
selector, so per-opcode `proved` credit was refused rather than inherited
from the family.

**No entry is publication-level.** The architectural side of every Team B
theorem is a *reviewed normalized capsule*, not a generated-Sail theorem,
because the pinned Sail toolchain is not provisioned in the environment these
proofs were developed in. Each capsule under `RiscvRefinement/Sail/Reviewed/`
says so in its header; no mechanical check enforces that headers exist or stay
accurate (see contract §0 for the enforcement gap and the proposed check). The
Team B capsules are the same epistemic *class* as the existing LUI/ADDI
capsule (`RiscvRefinement/Sail/Generated/Pilot.lean`) but not the same status:
Pilot.lean is generator output pinned to SHA-256 digests of real generated
Sail text, while the Team B capsules are hand-written, with no generator, no
digest, and no derivation from any Sail artifact. Replacing them with
generated Sail definitions, together with a checked translation receipt, is
the open obligation; for the LUI/ADDI capsule the narrower remaining gap is
the generated-monad theorem.

Hosted Sail provisioning now exists —
`.github/workflows/riscv-sail-formal.yml`, normative in
[`../../soundness/SAIL_PROVISIONING.md`](../../soundness/SAIL_PROVISIONING.md) —
so "no Sail compiler is available" is a retired excuse, not a standing one.
It upgrades nothing here: per that document, no file stops saying "reviewed
capsule" because the provisioning job is green. The capsules stay reviewed
until the generated slices are extracted, digest-pinned, and every
`*_refines` theorem is re-proved against them unchanged.

## Certificate states

| State | Meaning | Required fields |
| --- | --- | --- |
| `open` | nothing yet | — |
| `capsule-only` | AIR capsule exists, no refinement theorem | — |
| `refined` | refinement theorem and tuple projections | refinement, tuple |
| `proved` | plus a witness and a named, load-bearing Lean mutation control | refinement, tuple, non-vacuity, mutation, mutation_theorem |

A state cannot overstate what exists: `scripts/riscv_team_b.py coverage`
refuses a certificate claiming a state without the fields that state requires,
and `theorems` refuses a certificate naming a theorem that is not in the Lean
sources.

## The mutation-control discipline

A `proved` certificate requires a load-bearing mutation control in the
`MutationControl` form of `RiscvRefinement/Mutation.lean`: a copy of the
family row predicate with exactly **one** constraint field deleted, a concrete
row that satisfies everything left, and a proof that the row gets an
architectural conclusion wrong. With the constraint the conclusion follows;
without it, here is the counterexample. Reference implementations:
`Opcodes/DivMutation.lean` and `Opcodes/StoreMutation.lean`.

Three requirements on the conclusion were learned the hard way, and every
control in the repository now satisfies them:

1. **Row-parameterised.** Stated against the row's own consumed values
   (`row.memoryBefore`, `row.operandBefore`, ...), never a literal constant.
   A constant conclusion is false of essentially every honest row, which
   makes the soundness hypothesis below false and the corollary vacuous.
2. **Guarded on its selector.** Gated on `row.isLh`, `row.isSb`, and so on.
   An unguarded conclusion is refuted by an honest row of another opcode or
   width, which again falsifies the soundness hypothesis.
3. **Not a restatement of the deleted constraint.** Otherwise the control is
   circular: it proves only that deleting a constraint makes that constraint
   false.

And the corollary must be **unconditional**. `MutationControl.strictly_weaker`
takes the soundness hypothesis `∀ row, Holds row → Conclusion row`, and a
corollary conditional on an unproved — or false — hypothesis certifies
nothing. Every `*_is_load_bearing` theorem in this repository discharges that
hypothesis in the same file; none assumes it.

This discipline exists because it was violated and caught twice:

- Adversarial verification found the original LH control vacuous: its
  conclusion pinned `row.result` to one specific constant word, so the
  soundness hypothesis was false and
  `lh_high_half_selection_is_load_bearing` proved nothing. The repaired
  conclusion, `LhRetiresHighHalf` — LH-guarded, stated with the
  architectural sign extension, independent of the deleted byte-level
  constraint — has its hypothesis discharged by
  `loadStoreHolds_retires_high_half` in `Opcodes/LoadStoreMutation.lean`.
- A later audit proved three corollaries in
  `Opcodes/LoadStoreMutationExtra.lean` vacuous: `partial_store_preserve`
  and `source_read_only` pinned their conclusions to literal constants, and
  `half_shift_id` dropped its halfword guard. `partial_store_preserve` was
  restated row-relative — the masked word built from the row's own
  `memoryBefore` — and `half_shift_id` regained its guard, each with its
  soundness hypothesis then proved in-file. `source_read_only` could not be
  repaired that way and took the fallback described next.

The fallback is the honest route whenever the architectural claim and the
deleted constraint coincide, and it is the only route that was open here. On a
load, memory preservation *is* the `sourceReadOnly` constraint, so any
conclusion strong enough to be refuted by a witness restates the deletion —
which requirement 3 forbids. For that case
`Mutation.strictly_weaker_of_not_original` proves `¬ Holds witness` directly
and derives strictness with no architectural conclusion at all. It cannot be
vacuous, but it is weaker — it shows the constraint is not *redundant*, not
that it is load-bearing for a specific architectural fact — and the control
must say so in a comment, as `source_read_only_is_strict` does.

Writing a new control, in order:

1. copy the family predicate to `HoldsWithout<Field>`, deleting exactly one
   field and changing nothing else — deleting two would let the
   counterexample be blamed on the wrong deletion;
2. prove the deletion is a real weakening (a `*_weakens_*` lemma), so the
   control cannot rest on an accidentally unsatisfiable predicate;
3. exhibit a concrete row satisfying the weakened predicate;
4. state the architectural conclusion under requirements 1–3 and prove the
   witness refutes it;
5. package both as a `MutationControl` and derive the `strictly_weaker`
   corollary, proving the soundness hypothesis in the same file — or, if
   step 4 is impossible for the honest reason above, publish the
   `strictly_weaker_of_not_original` form and label it as the weaker claim.

## Families

| Family | Opcodes | Capsule | Notes |
| --- | --- | --- | --- |
| `shifts_reg` | SLL, SRL, SRA | `Air/Family/Shifts.lean` | shares the `shift_common` layer with the immediate family |
| `shifts_imm` | SLLI, SRLI, SRAI | `Air/Family/Shifts.lean` | |
| `load_store` | LB, LH, LW, LBU, LHU, SB, SH, SW | `Air/Family/LoadStore.lean` | LH is the Stage B2 stress gate; `proved`, mutation `lh-wrong-high-half` |
| `mul` | MUL | `Air/Family/Multiply.lean` | `proved`; mutation `mul-free-low-limb` |
| `mulh` | MULH, MULHSU, MULHU | `Air/Family/Multiply.lean` | |
| `div` | DIV, DIVU, REM, REMU | `Air/Family/Div.lean` | the Stage B3 stress gate |

Each capsule records the SHA-256 of the exported production AIR it was
transcribed from. `scripts/riscv_team_b.py ir-digests` recomputes those digests
from a fresh `zig build riscv-refinement-ir` export and fails closed on any
difference, so a production AIR change invalidates the transcription rather than
silently diverging from it.

## Three things the stress gates surfaced

**Address wrap is not reachable in an admitted row.** The production
`load_store` AIR bounds addresses twice: the base-address `range_check_m31`
forces the high limb of `rs1` below 128, and the aligned-address
`range_check_20` request carries `aligned / 4`, so `aligned < 2^22`. A true
32-bit address wrap therefore cannot occur in an admitted production row.
Architectural wrap is real and the Sail side defines it; the AIR narrows it
away. An LH theorem must carry that range premise explicitly rather than claim
the AIR derives wrap behaviour.

**The production AIR admits an address-aliasing row.** The effective address is
computed as `composeU32(rs1.next) + imm_felt` in the M31 *base field*, not modulo
`2^32`, and the only bound on the base is the `range_check_m31` forcing its high
limb below 128. So a base just under the field modulus plus a small displacement
wraps the field and lands on a small address that satisfies the aligned-address
range check, while the architectural address is elsewhere. Concretely, base
`0x7FFFFFFB` with displacement `+8` is architecturally `0x80000003` — not even
word-aligned, so the architectural access would trap — yet the AIR admits a
clean aligned read of `0x00000004`, satisfying every constraint and every range
check.

This is a property of the shipped AIR, not of anything Team B controls; it is
filed as issue #140 (see the section below). The Lean
load theorems carry an explicit `baseInFieldRange` premise to exclude it, which
means **they do not cover every AIR-admitted row**, and that limitation is stated
here rather than buried. `scripts/riscv_team_b_witnesses.py` tracks the row: it
reports the gap while it exists and *fails* if the row stops being admitted, so
fixing the AIR forces this note and the Lean premise to be revisited rather than
left stale. Of the two candidate fixes — bounding the base, or doing the
address arithmetic modulo `2^32` — [PR #142](https://github.com/teddyjfpender/stwo-zig/pull/142)
proposes the bound: a single degree-2 constraint pinning the base's high limb
to zero on active rows, which bounds the base below `2^24` (strictly tighter
than the `M31 - 4096` bound the issue suggested, with no new columns, tables,
or lookups) and loses no honest row.

**Alignment is enforced by equality constraints together with the range check,
and the Lean proofs derive it.** For LH, LHU and SH the intra-word offset is
pinned by genuine equations: C20, `opcode_h * (1 - shift_id) * (5 - shift_id)
= 0`, pins `shift_id ∈ {1, 5}`, and C15's halfword branch (`2 * shift_amount +
1 = shift_id` over the canonical representatives) then forces `shift_amount ∈
{0, 2}`; for LW and SW, C15's word branch forces `shift_amount = 0`. The
`range_check_20` on `aligned / 4` is additional, not the sole mechanism: it
pins the bus address to a canonical multiple of four below `2^22`, which is
what makes the base-field decomposition `address = 4 * aligned_quarter +
shift_amount` meaningful. The Lean transcription carries both — `alignedQuarter`
with `alignedAddress = 4 * alignedQuarter`, plus the C15/C20 fields of
`LoadStoreHolds` — and *derives* natural alignment from them (`lh_shift` and
`half_access_aligned` in `RiscvRefinement/Opcodes/LoadStore.lean`) rather than
assuming it.

## Filed AIR defect: issue #140

The address-aliasing gap above is filed as
[issue #140](https://github.com/teddyjfpender/stwo-zig/issues/140)
(*load_store AIR admits an address-aliasing row: base-field address arithmetic
is not modulo 2^32*). Status as of 2026-07-29: the issue is **open**, and
[PR #142](https://github.com/teddyjfpender/stwo-zig/pull/142) (*Bound the
load_store base so its effective address cannot alias*) is **open, unmerged**,
proposing the high-limb bound described above. On this branch the AIR is
unchanged and the aliasing row is still admitted.

While it stays open, three artifacts keep the claim honest:

- the Lean load theorems carry the `baseInFieldRange` premise
  (`RiscvRefinement/Opcodes/LoadStore.lean`), so they exclude the row and
  therefore do not cover every AIR-admitted row;
- `scripts/riscv_team_b_witnesses.py` (`report_address_aliasing`) re-derives
  the row against every fresh production export and *fails* if the row stops
  being admitted, so an AIR fix forces the premise and this section to be
  revisited rather than left stale;
- `scripts/tests/test_riscv_team_b_witnesses.py::TrackedAirGapTest` pins the
  shape of that tracked report.

When #140 is fixed, the closure order is: witness gate fails → drop or
discharge `baseInFieldRange` from the AIR's new bound → delete this section and
the aliasing note above.

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
