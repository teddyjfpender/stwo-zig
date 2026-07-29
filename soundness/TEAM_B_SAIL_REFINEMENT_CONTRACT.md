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
and ADDI against a **reviewed normalized capsule** of the generated definitions.
It does **not** yet prove that the capsule is the observable result of the
generated Sail monad. That is the second open translation obligation and it is
still open after this document.

Consequently:

- Nothing in this document licenses reporting any opcode as publication-level.
- The architectural capsules Team B adds for the load/store, shift, multiply and
  division families have exactly the same epistemic status as the existing
  LUI/ADDI capsule: reviewed, digest-pinned against generated Sail where a
  generated definition exists, and explicitly **not** a generated-Sail theorem.
- Every such file carries a header saying so. A file that does not say so is a
  bug in this contract's enforcement, not a stronger claim.

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
it can only be discharged against the generated monad, which is the open
translation obligation from section 0.

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
- Natural alignment is a premise of the admitted row, not a derived fact:
  `isHalfAligned` for halfword accesses, `isWordAligned` for word accesses.
  `halfAligned_byteOffset` proves a half-aligned address has byte offset 0 or 2,
  so its selector bit determines the offset completely.
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

**Production-AIR note.** In the production `load_store` AIR the alignment of
halfword and word accesses is enforced only by the
`range_check_20((src_addr_selector + dst_addr_selector - r2_idx) / 4)` request,
not by an equation. A Team B load/store theorem must therefore carry the
alignment premise explicitly and must not claim the AIR derives it from an
equality constraint.

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
- Access clocks are `accessClock clock ordinal`, with the production ordinals:
  `.first = 4c-3`, `.second = 4c-2`, `.third = 4c-1`.
- The per-opcode certificate binds manifest ID, family, selector, AIR digest,
  Sail digest, refinement theorem, tuple theorem, non-vacuity theorem, mutation
  identity, axioms, and proof time.

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
approval recorded in this document.

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
