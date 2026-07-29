# Team B contract: generated Sail binding and complete normalized retirement

Status: **Stage B0 freeze, proposed.** This document is the Team B half of the
joint contract required by issue #137 Stage B0. It is normative for the Team B
side of the interface and advisory for Team A's side until both DRIs sign it.

Normative parent plan: [`UNIVERSAL_AIR_SAIL_REFINEMENT.md`](UNIVERSAL_AIR_SAIL_REFINEMENT.md).
Composition premise this closes, jointly with Team A: SA-1 premise 5 in
[`SAIL_AIR_COMPOSITION.md`](SAIL_AIR_COMPOSITION.md).

## 0. What is and is not claimed today

Read this section before quoting any other section.

The repository pins Sail 0.20.2 and the `rv32im-zkvm-v1` profile, generates the
Sail Lean theorem backend from that exact configuration, and kernel-checks LUI
and ADDI against a normalized capsule of the generated definitions. A direct
cross-project Lean bridge now proves that the exact generated LUI/ADDI execute
clauses, followed by the shared sequential next-PC write and `tick_pc`, equal
the normalized executions. It does **not** yet prove the surrounding fetch,
interrupt, trap, counter, or later-step framing of the full generated Sail
loop.

Consequently:

- Nothing in this document licenses reporting any opcode as publication-level.
- The architectural capsules Team B adds for the load/store, shift, multiply
  and division families remain reviewed normalized capsules, explicitly
  **not** generated-Sail theorems. They are no longer the same epistemic class
  as the LUI/ADDI pilot: that capsule is generator output pinned to exact
  generated Sail text and now has a kernel-checked generated-clause monad
  bridge. The Team B capsules are hand-written, with no generated-definition
  receipt or derivation from a Sail artifact.
- Each of the four capsule files under `RiscvRefinement/Sail/Reviewed/`
  carries a header saying so. Hand-written architectural content **outside**
  that directory has carried the boundary header inconsistently: a 2026-07-29
  audit found four such files with no header — the mutation-control files
  `Opcodes/{MultiplyMutation,ShiftsMutation,DivMutation,LoadStoreMutation}.lean`,
  annotated since — and the prediction that review-only enforcement rots has
  already come true: as of the same date, four *newer* hand-written
  mutation-control files —
  `Opcodes/{StoreMutation,ShiftsRegMutation,LoadStoreMutationExtra,MultiplyMutationExtra}.lean`
  — carry no boundary marker at all (their prose references the reviewed
  capsules, but nothing states the file's own epistemic class). **Nothing
  enforces the header claim mechanically.** Review alone (§11.1, Team B DRI
  item 4) was supposed to keep it true — which is exactly the kind of claim
  that quietly becomes false, and for those four files already has. The
  proposed mechanical check is a total classification: fail
  `riscv_team_b.py check` unless every `.lean` under `RiscvRefinement/`
  carries, in its first comment block, one of the markers `GENERATED FILE`,
  `REVIEWED NORMALIZED CAPSULE`, `REVIEWED TRANSCRIPTION`,
  `REVIEWED-CAPSULE BOUNDARY`, or an explicit `-- No architectural claim`
  disclaimer for pure infrastructure:

  ```sh
  cd formal/riscv-refinement
  for f in $(find RiscvRefinement -name '*.lean'); do
    head -40 "$f" | grep -qiE 'GENERATED FILE|REVIEWED (NORMALIZED CAPSULE|TRANSCRIPTION)|REVIEWED-CAPSULE BOUNDARY|No architectural claim' \
      || { echo "unclassified: $f"; exit 1; }
  done
  ```

  A total check cannot rot the way a "files that state architectural
  semantics" filter can, because a new file fails it until its author declares
  an epistemic class. The check has **not** landed in `riscv_team_b.py check`;
  adopting it requires adding the one-line infrastructure disclaimer to the
  files that today carry no marker and boundary headers to the four newer
  mutation-control files above. Until then, "every file carries a header" is
  not merely unenforced — for those four files it is currently **false**, and
  only the class-wide boundary stated here and in each capsule's own header
  keeps the claim honest.

## 1. Frozen identity of the pinned Sail side

These remain fail-closed exactly as `scripts/riscv_refinement_lib/sail.py`
already enforces them. Team B may extend the checks; it may not relax them.

| Item | Authority | Enforcement |
| --- | --- | --- |
| Sail model repository and revision | `conformance/riscv/rv32im-sail-profile.json` | `sail.py` rejects a checkout whose `git rev-parse HEAD` differs |
| Sail compiler version | pinned `0.20.2` | `--version` parse, exact equality |
| Working-tree state | clean, or exactly the reviewed RVFI transport byte substitution | `_checkout_state` |
| Model entry and configuration | generated `rv32d_v256_e32.json` deep-merged with the two repository overrides, in order | `exact_configuration`, then `--validate-config` and `--print-isa-string` must report `rv32im` |
| Theorem-backend generation | the exact `sail --lean ...` invocation, cwd `model/` | `prepare_exact_backend` |
| Generated definition identity | SHA-256 of each extracted `def execute_*` block | pinned equality against `GENERATED_DEFINITION_HASHES` |
| Sail source slice identity | SHA-256 of the corresponding `.sail` source region | pinned equality against `SOURCE_SLICE_HASHES` |

The RVFI transport entry patch is a differential-testing transport change. It is
not an ISA semantic rule and must never enter the theorem model.

## 2. Complete normalized retirement

Frozen in `formal/riscv-refinement/RiscvRefinement/Common.lean`. This type is
**jointly versioned**: a change requires both DRIs and replay of every
already-counted opcode.

```lean
structure MemoryRead where
  address : Word            -- aligned word bus address
  value   : Word            -- complete word observed on the bus

structure MemoryWrite where
  address : Word            -- aligned word bus address
  mask    : ByteMask        -- byte enables, bit i selects little-endian byte i
  value   : Word            -- complete post-state word

structure Retirement where
  nextPc : Word
  write  : Option RegisterWrite
  read   : Option MemoryRead  := none
  store  : Option MemoryWrite := none

inductive Outcome where
  | retired (retirement : Retirement)
  | rejected
```

`read` and `store` default to `none`. That default is the literal claim "this
transition has no memory effect", which is why register-only families keep their
two-field syntax. It is safe because every refinement theorem **states** the
value of all four fields; a memory family that forgot to populate a field could
not prove its theorem.

**No other externally visible state change may be claimed.** A family that needs
a fifth observable must amend this type through the joint change process, not
work around it.

## 3. Raw Sail state to normalized pre-state and retirement

The generated model's architectural state is far larger than one zkVM
transition. The normalization boundary is:

| Normalized object | Raw Sail source | Notes |
| --- | --- | --- |
| `PreState.pc` | `PC` | |
| `PreState.registers` | `x` register file via `rX_bits` | `x0` is pinned to zero by `PreState.x0IsZero` |
| `Retirement.nextPc` | `nextPC` after the step | for the Team B families this is always `pc + 4` |
| `Retirement.write` | the `wX_bits rd` effect | erased to `none` when `rd = x0`, matching `architecturalWrite` |
| `Retirement.read` | the load's memory read effect | aligned word address and complete observed word |
| `Retirement.store` | the store's memory write effect | aligned word address, byte-enable mask, complete post-state word |
| `Outcome.retired` | `RETIRE_SUCCESS` | anything else normalizes to `Outcome.rejected` |

## 4. Inventory of erasable Sail state

The bridge may erase the following, and only the following, and only after the
corresponding obligation in section 5 is discharged.

1. **Interpreter and logging bookkeeping** — trace output, instruction counters,
   step counters, and any state written only for diagnostics.
2. **Inactive extension state** — everything belonging to A, F, D, B, V, and the
   disabled `Z*`/`S*` extensions. The profile sets these unsupported, so no
   admitted instruction reads or writes them.
3. **Reservations** — the LR/SC reservation set. The A extension is unsupported,
   so no admitted instruction establishes or consumes a reservation.
4. **Privileged and CSR state** — `misa` (pinned non-writable), `mstatus`,
   trap vectors, PMP configuration (0 entries), and the supervisor/user modes
   (S and U unsupported). No admitted instruction is a CSR access, because Zicsr
   is unsupported.
5. **Address translation state** — the profile declares one flat 4 GiB
   executable main-memory region, so no translation state is consulted.
6. **Misaligned-access tagged options** — reinstated as `AlignmentException` by
   the repository's tagged-options override. Admitted rows carry an alignment
   premise, so the exception branch is outside the admitted subset.

## 5. Proof obligations for erased fields

For each erased field `f` the bridge must discharge, for every admitted opcode:

- **Non-reading.** The generated execution of the instruction does not read `f`,
  so the normalized retirement is independent of `f`'s pre-state value.
- **Non-writing, or invisibly writing.** Either the execution does not write
  `f`, or the value it writes is a function of state that is itself erased, so
  no later admitted transition can observe the difference.

The composition of these two facts is the "no erased raw-Sail field changes a
later observable transition" obligation in Stage B1. It is currently **open**:
the pilot bridge now reaches the generated execute clauses and sequential
PC/tick fragment, but does not yet frame fetch, interrupts, traps, counters, or
later admitted transitions.

### 5.1 What the translation receipt can discharge mechanically, and what stays hand proof

The receipt machinery now exists:
`scripts/riscv_refinement_lib/sail_translation.py` (schema
`stwo-sail-translation-receipt-v1`, parser `sail-lean-subset-parser-v1`). It
parses a generated `execute_*` definition slice into a typed AST and normalizes
it to per-selector observable effects, refusing every construct outside its
whitelist: in value position only the readers `rX_bits`, `get_arch_pc`,
`mem_read` and a fixed list of pure combinators; in statement position only
`wX_bits`, `set_next_pc`, `mem_write_value`, and a terminal
`pure RETIRE_SUCCESS`/`RETIRE_FAIL`.

The pilot receipt is now derived from the exact generated
`execute_UTYPE`/`execute_ITYPE` slices whose enclosing `InstsEnd.lean` digest is
already bound by the committed manifest. The slices and canonical receipt are
committed under `formal/riscv-refinement/generated/sail/`; carried-evidence
verification re-hashes both slices, re-parses them, re-derives the receipt, and
requires byte-identical reproduction. This mechanically binds the normalized
LUI and ADDI execute-clause effects to actual generated output. It remains
carried evidence on hosts without Sail and cannot mint a release receipt.

The direct bridge in
`formal/riscv-refinement/generated-sail-bridge/Pilot.lean` goes beyond that
receipt: it imports the exact generated Lean project and proves the clause
monads and sequential PC/tick fragment equal the normalized LUI/ADDI
executions. Its separate canonical receipt records the four theorem names,
complete generated-source closure, and approved axiom inventory. It
deliberately records full fetch/interrupt/trap/counter and later-step framing
as false.

Hosted Sail provisioning exists —
`.github/workflows/riscv-sail-formal.yml`, normative in
[`SAIL_PROVISIONING.md`](SAIL_PROVISIONING.md) — but that workflow
must still regenerate the backend and re-derive this receipt with the live
pinned toolchain. Translation receipts for the remaining Team B execute
families have not been captured, so the category analysis below remains
conditional for those opcodes.
Per erased-state category of section 4:

**Mechanically dischargeable by a verified receipt** (the refusal-on-unknown
rule is the mechanism: any read or write of the category would surface as a
non-whitelisted function name in the slice and the receipt would refuse to
verify, so a verified receipt *is* the machine check that the execute clause
touches none of it):

- **Category 2, inactive extension state** — both the non-reading and the
  non-writing half, at the granularity of the execute clause body.
- **Category 3, reservations** — the non-reading half and the
  direct-writing half within the clause. Not the indirect half; see below.
- **Category 4, privileged and CSR state** — the clause-level halves: no
  admitted I/M execute clause may name a CSR or privilege accessor and verify.
- **Category 1, bookkeeping** — only the clause-level halves, which are the
  uninteresting ones; see below.

**Still hand proof even with a verified receipt:**

- **Primitive closure (cuts across categories 3, 4, 5).** The receipt treats
  `rX_bits`, `mem_read`, `wX_bits`, `set_next_pc`, `mem_write_value` as opaque
  observations and effects; it never descends into their generated bodies.
  Translation-state consultation (category 5), PMP/privilege checks inside the
  memory primitives (category 4), and reservation cancellation on the store
  path (category 3) all live in that closure and are invisible to the receipt.
  Each needs a hand proof against the generated primitive bodies, or a jointly
  reviewed extension of the receipt to the callee closure.
- **Category 5, address translation state — entirely hand proof.** It is
  consulted only inside the memory primitives, so the receipt discharges
  nothing; the hand argument is the profile's single flat 4 GiB region.
- **Category 6, misaligned-access tagged options — the receipt refuses rather
  than discharges.** A realistic generated load/store clause carries the
  `AlignmentException` branch, and the parser subset has no conditional or
  exception constructs, so such a slice fails to parse. Discharging this
  category requires either a jointly reviewed parser/rule extension covering
  the exception branch, or the hand proof that the admitted row's alignment
  premise puts execution on the non-exception branch of the generated monad.
- **Category 1, bookkeeping — the load-bearing half is out of scope.** Trace
  output and instruction/step counters are written by the fetch-execute loop,
  not by the `execute_*` slices the receipt covers, so the "invisibly writing"
  argument is a statement about the loop and stays hand proof.
- **The Stage B1 composition itself.** Turning per-clause facts into "no
  erased raw-Sail field changes a later observable transition" needs the
  step-loop framing between retirements, which the receipt never sees.

The receipt's own recorded claim boundary agrees: it is evidence about the
translation only, not a proof about the pinned Sail model, and it must be
re-derived from the generated `InstsEnd.lean` on a host carrying the pinned
Sail compiler before it counts as Sail evidence.

## 6. Decode and admission boundary

The zkVM language is a **conservative subset** of the pinned model's language.
The admission predicate narrows; it never alters the semantics of an admitted
instruction.

- The admitted set is exactly the 46 `proof(...)` entries in
  `src/frontends/riscv/opcode_manifest.zig`. Team B owns 22 of them.
- **FENCE.I is excluded.** The pinned model retires `FENCE.I` (word `0x0000100F`)
  despite `extensions.Zifencei.supported = false`. The zkVM rejects it. This is
  recorded in the profile's `decode_exclusions` with the disposition
  "retires despite extensions.Zifencei.supported=false". The admission theorem
  must express this as an ingress restriction and must not claim alternate
  semantics for it.
- **Rejection is not a trap.** `Outcome.rejected` means "outside the admitted
  language, so this repository proves nothing about it". It does not assert that
  the pinned model traps. Conflating the two would let a rejection claim stand in
  for an architectural claim.

## 7. Memory model contract

Frozen in `formal/riscv-refinement/RiscvRefinement/Memory.lean`.

- Memory is a little-endian array of aligned 32-bit words.
- Every access names an **aligned word bus address**; a sub-word access is an
  aligned word plus a byte-enable mask, never a narrow bus transaction.
  `busAddress` clears the two low address bits; `busAddress_isWordAligned` and
  `busAddress_of_wordAligned` are proved.
- The effective address is `rs1 + signExtend(imm12)` under 32-bit modular
  arithmetic. **Address wrap is architectural, not an error**
  (`effectiveAddress_toNat`).
- On the architectural side, natural alignment is a premise of the admitted
  access: `isHalfAligned` for halfword accesses, `isWordAligned` for word
  accesses. `halfAligned_byteOffset` proves a half-aligned address has byte
  offset 0 or 2, so its selector bit determines the offset completely. (On the
  AIR side the delivered load/store proofs *derive* alignment from the
  transcribed constraints; see the production-AIR note below.)
- Little-endian selection: `WordBytes.lowHalf` / `WordBytes.highHalf` are proved
  equal to bits 15:0 and 31:16 of the word (`lowHalf_extract`,
  `highHalf_extract`), so the AIR's `Nat`-valued limb equations and bit-level
  reasoning agree.
- Width extension is explicit and proved on both branches:
  `signExtendHalf_negative`, `signExtendHalf_nonnegative`, `signExtendHalf_low`,
  and the byte analogues.
- Masks: `wordMask`, `halfMask selector`, `byteMask offset`. `applyMask` commits
  a masked word, and the four `applyMask_limb*_preserved` lemmas are the store
  preservation obligation, stated once and reused at every store width.

**Production-AIR note.** In the production `load_store` AIR natural alignment
is enforced by equality constraints together with a range check, and the
delivered Lean theorems derive it rather than assume it. C20,
`opcode_h * (1 - shift_id) * (5 - shift_id) = 0`, pins `shift_id ∈ {1, 5}` on
halfword rows and C15's halfword branch then forces the byte offset into
`{0, 2}`; C15's word branch forces offset `0` on word rows. The
`range_check_20((src_addr_selector + dst_addr_selector - r2_idx) / 4)` request
is additional, not the sole mechanism: it pins the bus address to a canonical
multiple of four below `2^22`, which is what makes the base-field address
decomposition meaningful. C69 additionally pins the base register's high limb
to zero on active rows, which keeps every signed-12-bit address sum inside
M31. `half_access_aligned` in
`RiscvRefinement/Opcodes/LoadStore.lean` derives `Memory.isHalfAligned` from
exactly these transcribed constraints, and `base_add_4096_lt_modulus` derives
the address headroom. `LoadStoreEnvironment` has no separate machine premise.
(An earlier revision of this note claimed the range check was the sole
alignment mechanism and required explicit alignment and address-range
premises; those claims are now obsolete.)

## 8. Theorem signature compatibility with Team A

Team B does not own production AIR meaning and may not restate production
constraints in a private Lean predicate. The shared shapes are:

- The row environment binds the AIR row to a `PreState`, an instruction word,
  and (for memory families) the pre-state memory word, exactly as
  `LuiEnvironment` and `AddiEnvironment` do today.
- The refinement statement is a structure of named obligations —
  `decode`, `retirement`, and one field per relation tuple — so that a missing
  obligation is a visible hole rather than a silently weaker theorem.
- Relation tuples are `ProgramTuple`, `StateTuple`, `RegisterTuple` and
  `MemoryTuple` in `Common.lean`. `MemoryTuple.addr` is the aligned word bus
  address, matching the production memory lookup argument.
- Access clocks are `accessClock clock ordinal = (clock - 1) * 4 + ordinal`,
  with the ordinal a bare `Nat`: the production ordinals `1`, `2`, `3` yield
  `4c-3`, `4c-2`, `4c-1`.
- The per-opcode certificate binds manifest ID, family, selector, AIR digest,
  Sail digest, refinement theorem, tuple theorem, non-vacuity theorem, mutation
  identity, axioms, and proof time.

### 8.1 Mutation-control obligations

A certificate may claim `proved` only with a named Lean mutation control in
the `MutationControl` form of `RiscvRefinement/Mutation.lean`: the family row
predicate with exactly **one** constraint field deleted, a proof that the
deletion is a real weakening, a concrete row satisfying what is left, and a
refutation of an architectural conclusion on that row. The conclusion must
be:

- **row-parameterised** — a literal-constant conclusion is false of
  essentially every honest row, so the soundness hypothesis is false and the
  corollary vacuous;
- **guarded on the opcode's selector** — an unguarded conclusion is refuted
  by an honest row of another opcode or width;
- **not a restatement of the deleted constraint** — a restated conclusion
  makes the control circular.

The `strictly_weaker` corollary must be **unconditional**: its soundness
hypothesis `∀ row, Holds row → Conclusion row` is proved in the same file,
never assumed. Where the architectural claim and the deleted constraint
coincide, the only honest form is `Mutation.strictly_weaker_of_not_original`
— strictness without an architectural conclusion — and the control must say
in a comment that it establishes non-redundancy, not load-bearing-ness.

These are not stylistic preferences: three corollaries, and earlier the
first LH control, were once vacuous for exactly these reasons and were
caught by audit. The repair history and a step-by-step recipe are recorded
in [`formal/riscv-refinement/TEAM_B.md`](../formal/riscv-refinement/TEAM_B.md)
(section "The mutation-control discipline"); reference implementations are
`Opcodes/DivMutation.lean` and `Opcodes/StoreMutation.lean`.

## 9. Sail-side trusted computing base

Trusted:

1. The Lean 4 kernel at the pinned toolchain, and the three approved axioms
   `propext`, `Classical.choice`, `Quot.sound`.
2. The Sail compiler 0.20.2 and its Lean theorem backend, as a translator.
3. The pinned `sail-riscv` model as the definition of RV32IM.
4. The repository's profile normalization — that the merged configuration is the
   intended `rv32im-zkvm-v1` profile. This is checked by the simulator's own
   `--validate-config` and ISA-string report, but the *intent* is reviewed, not
   proved.

Not trusted, and therefore proved or checked: the AIR-to-architecture refinement
itself, the normalization bridge, decode and admission, and every arithmetic
decomposition. Z3 may discover lemmas or counterexamples; **no final theorem may
accept solver output as an axiom.**

## 10. Fallback criterion

A hand-written Sail-like semantics layer is **prohibited** as the final
authority. If the pinned Sail revision cannot be compiled into usable Lean, the
only sanctioned fallback is a generated normalized capsule plus a **checked
translation receipt from the Sail AST**, and that fallback requires independent
approval recorded in this document. The receipt *machinery* now exists
(`scripts/riscv_refinement_lib/sail_translation.py`, section 5.1), and an exact
generated-output receipt is committed for the LUI/ADDI pilot. That pilot
receipt is not independent approval, no approval is recorded here, and it does
not cover the remaining Team B execute families. The separate direct bridge
covers only the pilot execute-clause monads and sequential PC/tick fragment,
not the full generated step loop.

Hand-transcribing instruction functions and validating them only with test
vectors is never acceptable as the final theorem. The reviewed capsules that
exist today are a Level-1 device with an explicit expiry: they are replaced by
the generated binding, not blessed by it.

## 11. Sign-off

Stage B0 exits when all five signatures are present.

| Role | Name | Date | Signature |
| --- | --- | --- | --- |
| Team B DRI (Sail/profile) | | | |
| Team A AIR DRI | | | |
| LH representative | | | |
| DIV representative | | | |
| Independent formal reviewer | | | |

Until then this document is proposed, and the claim boundary in section 0
governs every statement made elsewhere in the repository about Team B's work.

### 11.1 What each signer must verify before signing

Each list is meant to be worked through literally, on the commit being signed,
from a clean checkout. A signer who cannot check an item does not sign.

**Team B DRI (Sail/profile).**

1. `python3 scripts/riscv_team_b.py check --air-ir-dir <fresh export>` exits 0,
   where the export comes from a fresh
   `zig build riscv-refinement-ir -Driscv-refinement-ir-dir=<dir>` on the same
   commit.
2. The section 1 identity table matches `scripts/riscv_refinement_lib/sail.py`
   verbatim: pinned revision, compiler `0.20.2`,
   `GENERATED_DEFINITION_HASHES`, `SOURCE_SLICE_HASHES`, and the
   `rv32d_v256_e32.json` base-configuration path.
3. The profile facts hold in `conformance/riscv/rv32im-sail-profile.json`:
   `xlen` 32, extensions exactly `I` and `M`, `decode_exclusions` naming only
   FENCE.I word `0x0000100F` with a disposition recording that the pinned model
   retires it, and `Zifencei`/`Zicsr` set unsupported in the override.
4. Every file under `RiscvRefinement/Sail/Reviewed/` carries the
   reviewed-normalized-capsule boundary header, and no file in the development
   claims generated-Sail or publication-level status. Until the §0
   total-classification check lands in `riscv_team_b.py check`, this item is
   the only enforcement the header claim has, so it must also cover
   hand-written files *outside* `Sail/Reviewed/` that state architectural
   content — the mutation-control files in particular.
5. The section 4 erasure inventory still covers every raw-Sail state category
   the pinned model carries; anything new in the pinned model since the last
   review is either normalized (section 3) or added to section 4 with a
   section 5 obligation.

**Team A AIR DRI.**

1. `python3 scripts/riscv_team_b.py ir-digests --air-ir-dir <fresh export>`
   exits 0 on the same commit: every family capsule digest
   (`loadStoreIrDigest`, `shiftsImmIrDigest`, `shiftsRegIrDigest`,
   `mulIrDigest`, `mulhIrDigest`, `divIrDigest`) equals the fresh production
   export.
2. The shared shapes in section 8 match `RiscvRefinement/Common.lean` as built:
   `ProgramTuple`, `StateTuple`, `RegisterTuple`, `MemoryTuple` fields, and
   `accessClock` yielding `4c-3`, `4c-2`, `4c-1` for ordinals 1, 2, 3.
3. No Team B Lean file restates a production constraint in a private
   predicate; every AIR-side fact is used through the transcribed family
   capsules in `RiscvRefinement/Air/Family/`.
4. The issue #140 source fix is present on this branch: C69 bounds the base's
   high limb to zero on active rows, the capsule pins the fresh export digest,
   and the load/store theorems derive field headroom without a
   `baseInFieldRange` premise. The historical aliasing row is rejected by an
   exact-root regression gate.

**LH representative.**

1. `lake env lean RiscvRefinement/Opcodes/LoadStore.lean` succeeds, and
   `#print axioms` on `lh_refines`, `lh_high_negative_exists`, and
   `lh_high_half_selection_is_load_bearing` reports nothing outside `propext`,
   `Classical.choice`, `Quot.sound`.
2. `lh_refines` hypothesises only the transcribed AIR (`LoadStoreHolds`), the
   decoding environment, and the `LH` selector. Halfword alignment is
   *derived* from the AIR's equality constraints — C20 (`halfShiftId`) with
   C15's halfword branch (`halfShiftAmount`) — via `lh_shift` and
   `half_access_aligned`. C69 supplies the address bound through
   `base_add_4096_lt_modulus`; there is no separate machine premise (see the
   §7 production-AIR note).
3. Sign extension is proved on both branches (`signExtendHalf_negative`,
   `signExtendHalf_nonnegative`) and half selection agrees with bits 15:0 and
   31:16 (`lowHalf_extract`, `highHalf_extract`), including the
   `rd = rs1` overlap case.
4. `python3 scripts/riscv_team_b_witnesses.py --air-ir-dir <fresh export>`
   exits 0 and its LH line reports all LH witnesses reachable in the exported
   production AIR, including a witness with a negative (high-bit-set) loaded
   half.
5. The `lh-wrong-high-half` mutation certificate names a theorem that fails on
   the mutated capsule — i.e. the high-half selection is load-bearing, not
   decorative.

**DIV representative.**

1. `lake env lean RiscvRefinement/Opcodes/Div.lean` succeeds, and
   `#print axioms` on `div_refines`, `divu_refines`, `rem_refines`,
   `remu_refines` reports only the three approved axioms.
2. The four divisor-zero conventions and the signed overflow case
   (`INT_MIN / -1`) are each stated and proved, and division truncates toward
   zero — not floored — as fixed in `RiscvRefinement/Arith/Division.lean`.
3. The four certificate non-vacuity theorems (`divWitnessOverflow_holds`,
   `divWitnessHighBitUnsigned_holds`, `divWitnessNegativeRemainder_holds`,
   `divWitnessZeroDivisor_holds`) exist and are family-level honest witnesses
   covering zero divisor, overflow, negative remainder, and high-bit unsigned.
4. The DIV line of `riscv_team_b_witnesses.py` reports its witnesses reachable
   in the exported production AIR on the same commit.

**Independent formal reviewer.**

1. From a clean clone at the signed commit: `lake build` succeeds and
   `lake env lean RiscvRefinement/AxiomAudit.lean` reports every audited
   theorem depending on nothing outside `propext`, `Classical.choice`,
   `Quot.sound` — in particular no `_native.bv_decide.ax`.
2. No `.lean` file under `formal/riscv-refinement/RiscvRefinement/` contains
   `sorry`, `admit`, `axiom`, `unsafe`, or `native_decide` outside `--`
   comments.
3. The certificate index cannot overstate: hand-editing a certificate to claim
   `proved` without a `mutation` field, or to name a nonexistent theorem,
   makes `riscv_team_b.py coverage` (respectively `theorems`) fail.
4. Section 0's boundary is consistent with every public claim: `TEAM_B.md`,
   `team-b-coverage.json`'s `claim_boundary`, and the PR description report
   the same proved set and the same open obligations, and nothing anywhere
   reports an opcode as publication-level.
5. The #140 regression behaves as documented:
   `scripts/tests/test_riscv_team_b_witnesses.py::AddressAliasingRegressionTest`
   passes, and the witness gate fails unless the historical row is rejected by
   production constraint root 69 alone.
6. The hosted gate `.github/workflows/riscv-team-b-refinement.yml` has no path
   that passes with the Lean leg skipped, and its scheduled clean-room job
   rebuilds from empty caches and runs `leanchecker`.
