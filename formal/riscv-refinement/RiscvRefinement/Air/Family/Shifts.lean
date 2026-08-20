import RiscvRefinement.Common

/-!
# Shared shift-family AIR capsule: SLLI/SRLI/SRAI and SLL/SRL/SRA

Reviewed transcription of the production symbolic AIR exported for the two shift
families. The Zig source of record is the typed evaluator pair
`typed_shifts_imm_authority.zig` and `typed_shifts_reg_authority.zig`, dispatched
by `air/constraint_program.zig`; the exported symbolic DAGs are pinned by
`shiftsImmIrDigest` and `shiftsRegIrDigest` below.

Both families share `shift_common.zig`, so this file carries one `ShiftRow` /
`ShiftHolds` layer holding the shared hot-one markers, byte carries and result
limbs, and the two family rows below embed it. Every architectural consequence
that either family needs is proved once, here, from `ShiftHolds`.

## Normalization of the marker columns

The production row commits eight boolean `bit_markers` and four boolean
`limb_markers`, each group summing to the enabler, plus three boolean selectors
`is_sll`/`is_srl`/`is_sra` summing to one. `shift_selector_hot`,
`bit_markers_hot` and `limb_markers_hot` below prove that those constraints --
transcribed exactly -- pin down a unique shift kind, a unique bit offset
`bitIndex < 8` and a unique limb offset `limbIndex < 4`, and that the derived
`bit_multiplier` and `shift_amount` columns then equal `2 ^ bitIndex` and
`8 * limbIndex + bitIndex`. `ShiftRow` therefore stores the hot indices rather
than the twelve marker columns: that is a change of representation licensed by
those three theorems, not an added assumption.

## Boundary

This is a reviewed capsule of the production AIR, not a machine-checked export.
The digests pin the exact symbolic DAG the transcription was read from.
-/

namespace RiscvRefinement.Air.Family

open RiscvRefinement

/-- sha256 of the pinned `shifts_imm` symbolic AIR export
(56 columns, 349 nodes, 72 constraints, 16 lookups, 7 unmodelled requests). -/
def shiftsImmIrDigest : String :=
  "723c3a5b4d198bb49b0bb46a832f990d2c1014d413654cdfdd9f714d1930c1ec"

/-- Sparse-polynomial identity shared by the reviewed and typed exports. -/
def shiftsImmPolynomialDigest : String :=
  "5ab0474ce963462428f39a96a2bd95af1d1ff1cf71311e7444348015af741333"

/-- sha256 of the pinned `shifts_reg` symbolic AIR export
(66 columns, 372 nodes, 76 constraints, 20 lookups, 9 unmodelled requests). -/
def shiftsRegIrDigest : String :=
  "948b7cee5ca12e55f77ee4d14dde784715320cdd6c74dae4910c5017121a9ef3"

/-- Sparse-polynomial identity shared by the reviewed and typed exports. -/
def shiftsRegPolynomialDigest : String :=
  "9cb6442de50707263fd4d9ecf10640e2d15638c292b61489c7b79fd97d8a1ed3"

inductive ShiftKind
  | sll
  | srl
  | sra
deriving DecidableEq, Repr

/-! ## Hot-one normalization of the committed marker columns -/

/-- Constraints 1-3 (`bit(is_sll)`, `bit(is_srl)`, `bit(is_sra)`) together with
the placement constraint `is_sll + is_srl + is_sra = 1` force exactly one shift
selector. Constraint 0, `bit(is_sll + is_srl + is_sra)`, is implied. -/
theorem shift_selector_hot
    (isSll isSrl isSra : Nat)
    (sllBit : isSll = 0 ∨ isSll = 1)
    (srlBit : isSrl = 0 ∨ isSrl = 1)
    (sraBit : isSra = 0 ∨ isSra = 1)
    (placement : isSll + isSrl + isSra = 1) :
    (isSll = 1 ∧ isSrl = 0 ∧ isSra = 0) ∨
      (isSll = 0 ∧ isSrl = 1 ∧ isSra = 0) ∨
      (isSll = 0 ∧ isSrl = 0 ∧ isSra = 1) := by
  omega

/-- Constraints 6-13 (`bit(bit_markers_i)`) and constraint 18
(`Σ bit_markers_i = enabler = 1`) force exactly one hot bit marker. The two
derived sums are the production `bit_multiplier` and `bit_shift` columns. -/
theorem bit_markers_hot
    (m0 m1 m2 m3 m4 m5 m6 m7 : Nat)
    (bit0 : m0 = 0 ∨ m0 = 1)
    (bit1 : m1 = 0 ∨ m1 = 1)
    (bit2 : m2 = 0 ∨ m2 = 1)
    (bit3 : m3 = 0 ∨ m3 = 1)
    (bit4 : m4 = 0 ∨ m4 = 1)
    (bit5 : m5 = 0 ∨ m5 = 1)
    (bit6 : m6 = 0 ∨ m6 = 1)
    (bit7 : m7 = 0 ∨ m7 = 1)
    (hotOne : m0 + m1 + m2 + m3 + m4 + m5 + m6 + m7 = 1) :
    ∃ bitIndex,
      bitIndex < 8 ∧
        m0 + 2 * m1 + 4 * m2 + 8 * m3 + 16 * m4 + 32 * m5 + 64 * m6 +
            128 * m7 = 2 ^ bitIndex ∧
        m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 =
          bitIndex := by
  refine ⟨m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7,
    by omega, ?_, rfl⟩
  have choice :
      m0 = 1 ∨ m1 = 1 ∨ m2 = 1 ∨ m3 = 1 ∨
        m4 = 1 ∨ m5 = 1 ∨ m6 = 1 ∨ m7 = 1 := by
    omega
  rcases choice with h | h | h | h | h | h | h | h
  · rw [show m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 = 0 from
      by omega]
    omega
  · rw [show m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 = 1 from
      by omega]
    omega
  · rw [show m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 = 2 from
      by omega]
    omega
  · rw [show m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 = 3 from
      by omega]
    omega
  · rw [show m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 = 4 from
      by omega]
    omega
  · rw [show m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 = 5 from
      by omega]
    omega
  · rw [show m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 = 6 from
      by omega]
    omega
  · rw [show m1 + 2 * m2 + 3 * m3 + 4 * m4 + 5 * m5 + 6 * m6 + 7 * m7 = 7 from
      by omega]
    omega

/-- Constraints 14-17 (`bit(limb_markers_i)`) and constraint 19
(`Σ limb_markers_i = enabler = 1`) force exactly one hot limb marker; the
derived sum is the production `limb_shift` column. -/
theorem limb_markers_hot
    (l0 l1 l2 l3 : Nat)
    (bit0 : l0 = 0 ∨ l0 = 1)
    (bit1 : l1 = 0 ∨ l1 = 1)
    (bit2 : l2 = 0 ∨ l2 = 1)
    (bit3 : l3 = 0 ∨ l3 = 1)
    (hotOne : l0 + l1 + l2 + l3 = 1) :
    ∃ limbIndex, limbIndex < 4 ∧ l1 + 2 * l2 + 3 * l3 = limbIndex :=
  ⟨l1 + 2 * l2 + 3 * l3, by omega, rfl⟩

/-! ## The shared shift row -/

/-- The `shift_common.zig` witness block, with the marker columns replaced by
the hot indices they determine. -/
structure ShiftRow where
  /-- `semantic_rs1_previous_*`. -/
  rs1Previous : WordBytes
  /-- `semantic_rs1_next_*`, the limbs the shift actually computes on. -/
  rs1Next : WordBytes
  /-- `semantic_rs1_sign`. -/
  rs1Sign : Bool
  /-- The hot selector among `is_sll` / `is_srl` / `is_sra`. -/
  kind : ShiftKind
  /-- The hot `limb_markers` index; `limb_shift` in the Zig source. -/
  limbIndex : Nat
  /-- The hot `bit_markers` index; `bit_shift` in the Zig source. -/
  bitIndex : Nat
  /-- `semantic_carries_0..3`. -/
  carry0 : Nat
  carry1 : Nat
  carry2 : Nat
  carry3 : Nat
  /-- `semantic_result_0..3`. -/
  result : WordBytes
  /-- `semantic_rd_addr`. -/
  rd : RegisterIndex
  /-- `semantic_rd_previous_*`. -/
  rdPrevious : WordBytes
  /-- `semantic_rd_next_*`. -/
  rdNext : WordBytes
  /-- `semantic_destination_nonzero`. -/
  rdNonzero : Bool
deriving DecidableEq, Repr

/-- The derived `bit_multiplier` column, `Σ bit_markers_i * 2 ^ i`. -/
def ShiftRow.multiplier (row : ShiftRow) : Nat := 2 ^ row.bitIndex

/-- `semantic_rs1_sign` as the field element the AIR multiplies by. -/
def ShiftRow.signNat (row : ShiftRow) : Nat := if row.rs1Sign then 1 else 0

/-- The derived `shift_amount` column, `8 * limb_shift + bit_shift`. -/
def ShiftRow.shiftAmount (row : ShiftRow) : Nat :=
  8 * row.limbIndex + row.bitIndex

/-- Left-shift byte/carry movement, constraints 22-37 specialized to the hot
limb marker. `mult` is `bit_multiplier_left = is_sll * bit_multiplier`. -/
def shiftLeftEquations
    (limbIndex mult : Nat)
    (source result : WordBytes)
    (carry0 carry1 carry2 carry3 : Nat) : Prop :=
  match limbIndex with
  | 0 =>
      result.limb0.toNat + 256 * carry0 = mult * source.limb0.toNat ∧
      result.limb1.toNat + 256 * carry1 = mult * source.limb1.toNat + carry0 ∧
      result.limb2.toNat + 256 * carry2 = mult * source.limb2.toNat + carry1 ∧
      result.limb3.toNat + 256 * carry3 = mult * source.limb3.toNat + carry2
  | 1 =>
      result.limb0.toNat = 0 ∧
      result.limb1.toNat + 256 * carry0 = mult * source.limb0.toNat ∧
      result.limb2.toNat + 256 * carry1 = mult * source.limb1.toNat + carry0 ∧
      result.limb3.toNat + 256 * carry2 = mult * source.limb2.toNat + carry1
  | 2 =>
      result.limb0.toNat = 0 ∧
      result.limb1.toNat = 0 ∧
      result.limb2.toNat + 256 * carry0 = mult * source.limb0.toNat ∧
      result.limb3.toNat + 256 * carry1 = mult * source.limb1.toNat + carry0
  | _ =>
      result.limb0.toNat = 0 ∧
      result.limb1.toNat = 0 ∧
      result.limb2.toNat = 0 ∧
      result.limb3.toNat + 256 * carry0 = mult * source.limb0.toNat

/-- Right-shift byte/carry movement, constraints 38-53 specialized to the hot
limb marker. `mult` is `bit_multiplier_right = (is_srl + is_sra) *
bit_multiplier`, and `sign` is `rs1_sign`: the `256 * sign * (mult - 1)` term of
the top-input equation is the arithmetic sign fill, and `255 * sign` is the
byte-level fill of the limbs that fall entirely off the top. -/
def shiftRightEquations
    (limbIndex mult sign : Nat)
    (source result : WordBytes)
    (carry0 carry1 carry2 carry3 : Nat) : Prop :=
  match limbIndex with
  | 0 =>
      mult * result.limb0.toNat + carry0 = source.limb0.toNat + 256 * carry1 ∧
      mult * result.limb1.toNat + carry1 = source.limb1.toNat + 256 * carry2 ∧
      mult * result.limb2.toNat + carry2 = source.limb2.toNat + 256 * carry3 ∧
      mult * result.limb3.toNat + carry3 + 256 * sign =
        source.limb3.toNat + 256 * sign * mult
  | 1 =>
      mult * result.limb0.toNat + carry1 = source.limb1.toNat + 256 * carry2 ∧
      mult * result.limb1.toNat + carry2 = source.limb2.toNat + 256 * carry3 ∧
      mult * result.limb2.toNat + carry3 + 256 * sign =
        source.limb3.toNat + 256 * sign * mult ∧
      result.limb3.toNat = 255 * sign
  | 2 =>
      mult * result.limb0.toNat + carry2 = source.limb2.toNat + 256 * carry3 ∧
      mult * result.limb1.toNat + carry3 + 256 * sign =
        source.limb3.toNat + 256 * sign * mult ∧
      result.limb2.toNat = 255 * sign ∧
      result.limb3.toNat = 255 * sign
  | _ =>
      mult * result.limb0.toNat + carry3 + 256 * sign =
        source.limb3.toNat + 256 * sign * mult ∧
      result.limb1.toNat = 255 * sign ∧
      result.limb2.toNat = 255 * sign ∧
      result.limb3.toNat = 255 * sign

/-- The shared shift constraints of `shift_common.zig`, all 65 of them, in the
normalized hot-index representation. -/
structure ShiftHolds (row : ShiftRow) : Prop where
  /-- `limb_markers_hot`. -/
  limbIndexRange : row.limbIndex < 4
  /-- `bit_markers_hot`. -/
  bitIndexRange : row.bitIndex < 8
  /-- Constraint 5, `(1 - is_sra) * rs1_sign = 0`: only an arithmetic right
  shift may carry a sign witness, so every other kind zero-fills. -/
  signIsLogicalZero : row.kind ≠ ShiftKind.sra → row.rs1Sign = false
  /-- Lookup 15 / 19, `range_check_m31 (0, rs1_next_3 - 128 * rs1_sign)`: the
  residue is a seven-bit value, so `rs1_sign` is exactly bit 31 of the operand.
  Requested only on `is_sra` rows. -/
  signLowerBound :
    row.kind = ShiftKind.sra → 128 * row.signNat ≤ row.rs1Next.limb3.toNat
  signUpperBound :
    row.kind = ShiftKind.sra →
      row.rs1Next.limb3.toNat < 128 * row.signNat + 128
  /-- `carryRangePairs`: `range_check_8_8 (carry_k, bit_multiplier - carry_k -
  1)` makes both components bytes, which on an active row is exactly
  `carry_k < bit_multiplier`. -/
  carry0Range : row.carry0 < row.multiplier
  carry1Range : row.carry1 < row.multiplier
  carry2Range : row.carry2 < row.multiplier
  carry3Range : row.carry3 < row.multiplier
  /-- Constraints 61-64, `readOnlyAccessConstraints(rs1, enabler)`. -/
  sourceReadOnly : row.rs1Next = row.rs1Previous
  /-- Constraints 22-37. -/
  leftMovement :
    row.kind = ShiftKind.sll →
      shiftLeftEquations row.limbIndex row.multiplier row.rs1Next row.result
        row.carry0 row.carry1 row.carry2 row.carry3
  /-- Constraints 38-53. -/
  rightMovement :
    row.kind ≠ ShiftKind.sll →
      shiftRightEquations row.limbIndex row.multiplier row.signNat
        row.rs1Next row.result row.carry0 row.carry1 row.carry2 row.carry3
  /-- Constraints 54-56, `destinationConstraints`. -/
  destinationFlag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
  /-- Constraints 57-60, `destinationResultConstraints`. -/
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.rdNonzero then row.result.limb0 else WordBytes.zero.limb0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.rdNonzero then row.result.limb1 else WordBytes.zero.limb1
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.rdNonzero then row.result.limb2 else WordBytes.zero.limb2
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.rdNonzero then row.result.limb3 else WordBytes.zero.limb3

/-! ## Elementary consequences -/

theorem ShiftRow.multiplier_pos (row : ShiftRow) : 0 < row.multiplier :=
  Nat.pow_pos (by omega)

theorem shift_amount_lt_32 (row : ShiftRow) (holds : ShiftHolds row) :
    row.shiftAmount < 32 := by
  have hl := holds.limbIndexRange
  have hb := holds.bitIndexRange
  simp only [ShiftRow.shiftAmount]
  omega

theorem shift_multiplier_le (row : ShiftRow) (holds : ShiftHolds row) :
    row.multiplier ≤ 128 := by
  have hb := holds.bitIndexRange
  simp only [ShiftRow.multiplier]
  have bound : (2 : Nat) ^ row.bitIndex ≤ 2 ^ 7 :=
    Nat.pow_le_pow_right (by omega) (by omega)
  simpa using bound

/-- Distributing a scalar across the little-endian limb decomposition. -/
theorem mul_word_value (mult : Nat) (bytes : WordBytes) :
    mult * bytes.value =
      mult * bytes.limb0.toNat + 256 * (mult * bytes.limb1.toNat) +
        65536 * (mult * bytes.limb2.toNat) +
        16777216 * (mult * bytes.limb3.toNat) := by
  simp only [WordBytes.value]
  simp [Nat.mul_add, Nat.mul_left_comm]

theorem shift_pow_split (row : ShiftRow) :
    (2 : Nat) ^ row.shiftAmount = 2 ^ (8 * row.limbIndex) * row.multiplier := by
  simp only [ShiftRow.shiftAmount, ShiftRow.multiplier, Nat.pow_add]

theorem shift_limb_cases (row : ShiftRow) (holds : ShiftHolds row) :
    row.limbIndex = 0 ∨ row.limbIndex = 1 ∨ row.limbIndex = 2 ∨
      row.limbIndex = 3 := by
  have := holds.limbIndexRange
  omega

/-! ## Byte and carry movement reconstructs the shifted word

The three theorems below are the load-bearing content of the shared family: on
an active row the committed `result` limbs are forced to be the architectural
shift of the committed `rs1_next` limbs by `shift_amount`, with the correct
zero- or sign-fill. -/

/-- Left shift: the committed result is `rs1_next * 2 ^ shift_amount` truncated
to 32 bits, `overflow` being the discarded high part. -/
theorem shift_left_value
    (row : ShiftRow)
    (holds : ShiftHolds row)
    (kind : row.kind = ShiftKind.sll) :
    ∃ overflow,
      row.result.value + 4294967296 * overflow =
        2 ^ row.shiftAmount * row.rs1Next.value := by
  have hleft := holds.leftMovement kind
  have hdist := mul_word_value row.multiplier row.rs1Next
  have hs := shift_pow_split row
  rcases shift_limb_cases row holds with h | h | h | h
  · rw [h] at hleft hs
    simp only [shiftLeftEquations] at hleft
    simp only [Nat.mul_zero, Nat.pow_zero, Nat.one_mul] at hs
    obtain ⟨e0, e1, e2, e3⟩ := hleft
    refine ⟨row.carry3, ?_⟩
    rw [hs, hdist]
    simp only [WordBytes.value]
    omega
  · rw [h] at hleft hs
    simp only [shiftLeftEquations] at hleft
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    obtain ⟨e0, e1, e2, e3⟩ := hleft
    refine ⟨row.carry2 + row.multiplier * row.rs1Next.limb3.toNat, ?_⟩
    rw [hs, Nat.mul_assoc, hdist]
    simp only [WordBytes.value]
    omega
  · rw [h] at hleft hs
    simp only [shiftLeftEquations] at hleft
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    obtain ⟨e0, e1, e2, e3⟩ := hleft
    refine ⟨row.carry1 + row.multiplier * row.rs1Next.limb2.toNat +
      256 * (row.multiplier * row.rs1Next.limb3.toNat), ?_⟩
    rw [hs, Nat.mul_assoc, hdist]
    simp only [WordBytes.value]
    omega
  · rw [h] at hleft hs
    simp only [shiftLeftEquations] at hleft
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    obtain ⟨e0, e1, e2, e3⟩ := hleft
    refine ⟨row.carry0 + row.multiplier * row.rs1Next.limb1.toNat +
      256 * (row.multiplier * row.rs1Next.limb2.toNat) +
      65536 * (row.multiplier * row.rs1Next.limb3.toNat), ?_⟩
    rw [hs, Nat.mul_assoc, hdist]
    simp only [WordBytes.value]
    omega

/-- Zero-filled right shift: the committed result is the exact quotient
`rs1_next / 2 ^ shift_amount`. This is the only movement available to `SRL`,
because constraint 5 forbids a non-zero `rs1_sign` on any non-`SRA` row. -/
theorem shift_right_logical_value
    (row : ShiftRow)
    (holds : ShiftHolds row)
    (kind : row.kind ≠ ShiftKind.sll)
    (sign : row.rs1Sign = false) :
    ∃ remainder,
      remainder < 2 ^ row.shiftAmount ∧
        2 ^ row.shiftAmount * row.result.value + remainder =
          row.rs1Next.value := by
  have hsign : row.signNat = 0 := by simp [ShiftRow.signNat, sign]
  have hright := holds.rightMovement kind
  rw [hsign] at hright
  have hdist := mul_word_value row.multiplier row.result
  have hs := shift_pow_split row
  have b0 := row.rs1Next.limb0.isLt
  have b1 := row.rs1Next.limb1.isLt
  have b2 := row.rs1Next.limb2.isLt
  have b3 := row.rs1Next.limb3.isLt
  simp only [Nat.reducePow] at b0 b1 b2 b3
  have c0 := holds.carry0Range
  have c1 := holds.carry1Range
  have c2 := holds.carry2Range
  have c3 := holds.carry3Range
  rcases shift_limb_cases row holds with h | h | h | h
  · rw [h] at hright hs
    simp only [Nat.mul_zero, Nat.pow_zero, Nat.one_mul] at hs
    simp only [shiftRightEquations] at hright
    obtain ⟨e0, e1, e2, e3⟩ := hright
    refine ⟨row.carry0, ?_, ?_⟩
    · rw [hs]; exact c0
    · rw [hs, hdist]
      simp only [WordBytes.value]
      omega
  · rw [h] at hright hs
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    simp only [shiftRightEquations] at hright
    obtain ⟨e0, e1, e2, e3⟩ := hright
    have p3 : row.multiplier * row.result.limb3.toNat = 0 := by
      rw [e3]; omega
    refine ⟨256 * row.carry1 + row.rs1Next.limb0.toNat, ?_, ?_⟩
    · rw [hs]; omega
    · rw [hs, Nat.mul_assoc, hdist]
      simp only [WordBytes.value]
      omega
  · rw [h] at hright hs
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    simp only [shiftRightEquations] at hright
    obtain ⟨e0, e1, e2, e3⟩ := hright
    have p2 : row.multiplier * row.result.limb2.toNat = 0 := by
      rw [e2]; omega
    have p3 : row.multiplier * row.result.limb3.toNat = 0 := by
      rw [e3]; omega
    refine ⟨65536 * row.carry2 + 256 * row.rs1Next.limb1.toNat +
      row.rs1Next.limb0.toNat, ?_, ?_⟩
    · rw [hs]; omega
    · rw [hs, Nat.mul_assoc, hdist]
      simp only [WordBytes.value]
      omega
  · rw [h] at hright hs
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    simp only [shiftRightEquations] at hright
    obtain ⟨e0, e1, e2, e3⟩ := hright
    have p1 : row.multiplier * row.result.limb1.toNat = 0 := by
      rw [e1]; omega
    have p2 : row.multiplier * row.result.limb2.toNat = 0 := by
      rw [e2]; omega
    have p3 : row.multiplier * row.result.limb3.toNat = 0 := by
      rw [e3]; omega
    refine ⟨16777216 * row.carry3 + 65536 * row.rs1Next.limb2.toNat +
      256 * row.rs1Next.limb1.toNat + row.rs1Next.limb0.toNat, ?_, ?_⟩
    · rw [hs]; omega
    · rw [hs, Nat.mul_assoc, hdist]
      simp only [WordBytes.value]
      omega

/-- Sign-filled right shift. `rs1_sign = 1` is only reachable on an `SRA` row,
and the `256 * rs1_sign * (bit_multiplier - 1)` term of the top-input equation
plus the `255 * rs1_sign` fill of the discarded limbs make the committed result
the exact arithmetic shift: `2 ^ s * result = rs1_next + 2 ^ 32 * (2 ^ s - 1) -
remainder`. -/
theorem shift_right_signed_value
    (row : ShiftRow)
    (holds : ShiftHolds row)
    (kind : row.kind ≠ ShiftKind.sll)
    (sign : row.rs1Sign = true) :
    ∃ remainder,
      remainder < 2 ^ row.shiftAmount ∧
        2 ^ row.shiftAmount * row.result.value + remainder + 4294967296 =
          row.rs1Next.value + 4294967296 * 2 ^ row.shiftAmount := by
  have hsign : row.signNat = 1 := by simp [ShiftRow.signNat, sign]
  have hright := holds.rightMovement kind
  rw [hsign] at hright
  have hdist := mul_word_value row.multiplier row.result
  have hs := shift_pow_split row
  have b0 := row.rs1Next.limb0.isLt
  have b1 := row.rs1Next.limb1.isLt
  have b2 := row.rs1Next.limb2.isLt
  have b3 := row.rs1Next.limb3.isLt
  simp only [Nat.reducePow] at b0 b1 b2 b3
  have c0 := holds.carry0Range
  have c1 := holds.carry1Range
  have c2 := holds.carry2Range
  have c3 := holds.carry3Range
  rcases shift_limb_cases row holds with h | h | h | h
  · rw [h] at hright hs
    simp only [Nat.mul_zero, Nat.pow_zero, Nat.one_mul] at hs
    simp only [shiftRightEquations] at hright
    obtain ⟨e0, e1, e2, e3⟩ := hright
    refine ⟨row.carry0, ?_, ?_⟩
    · rw [hs]; exact c0
    · rw [hs, hdist]
      simp only [WordBytes.value]
      omega
  · rw [h] at hright hs
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    simp only [shiftRightEquations] at hright
    obtain ⟨e0, e1, e2, e3⟩ := hright
    have p3 : row.multiplier * row.result.limb3.toNat =
        255 * row.multiplier := by
      rw [e3]; omega
    refine ⟨256 * row.carry1 + row.rs1Next.limb0.toNat, ?_, ?_⟩
    · rw [hs]; omega
    · rw [hs, Nat.mul_assoc, hdist]
      simp only [WordBytes.value]
      omega
  · rw [h] at hright hs
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    simp only [shiftRightEquations] at hright
    obtain ⟨e0, e1, e2, e3⟩ := hright
    have p2 : row.multiplier * row.result.limb2.toNat =
        255 * row.multiplier := by
      rw [e2]; omega
    have p3 : row.multiplier * row.result.limb3.toNat =
        255 * row.multiplier := by
      rw [e3]; omega
    refine ⟨65536 * row.carry2 + 256 * row.rs1Next.limb1.toNat +
      row.rs1Next.limb0.toNat, ?_, ?_⟩
    · rw [hs]; omega
    · rw [hs, Nat.mul_assoc, hdist]
      simp only [WordBytes.value]
      omega
  · rw [h] at hright hs
    simp only [Nat.reduceMul, Nat.reducePow] at hs
    simp only [shiftRightEquations] at hright
    obtain ⟨e0, e1, e2, e3⟩ := hright
    have p1 : row.multiplier * row.result.limb1.toNat =
        255 * row.multiplier := by
      rw [e1]; omega
    have p2 : row.multiplier * row.result.limb2.toNat =
        255 * row.multiplier := by
      rw [e2]; omega
    have p3 : row.multiplier * row.result.limb3.toNat =
        255 * row.multiplier := by
      rw [e3]; omega
    refine ⟨16777216 * row.carry3 + 65536 * row.rs1Next.limb2.toNat +
      256 * row.rs1Next.limb1.toNat + row.rs1Next.limb0.toNat, ?_, ?_⟩
    · rw [hs]; omega
    · rw [hs, Nat.mul_assoc, hdist]
      simp only [WordBytes.value]
      omega

/-! ## Bit-vector form of the movement theorems -/

theorem shift_left_word
    (row : ShiftRow)
    (holds : ShiftHolds row)
    (kind : row.kind = ShiftKind.sll) :
    row.result.word = row.rs1Next.word <<< row.shiftAmount := by
  obtain ⟨overflow, hover⟩ := shift_left_value row holds kind
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_shiftLeft]
  simp only [WordBytes.word_toNat, Nat.shiftLeft_eq, Nat.reducePow]
  have hres := row.result.value_lt
  simp only [Nat.reducePow] at hres
  rw [Nat.mul_comm row.rs1Next.value (2 ^ row.shiftAmount)]
  omega

theorem shift_right_logical_word
    (row : ShiftRow)
    (holds : ShiftHolds row)
    (kind : row.kind ≠ ShiftKind.sll)
    (sign : row.rs1Sign = false) :
    row.result.word = row.rs1Next.word >>> row.shiftAmount := by
  obtain ⟨remainder, hlt, heq⟩ :=
    shift_right_logical_value row holds kind sign
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.toNat_ushiftRight]
  simp only [WordBytes.word_toNat, Nat.shiftRight_eq_div_pow]
  rw [← heq, Nat.mul_add_div (Nat.pow_pos (by omega)),
    Nat.div_eq_of_lt hlt, Nat.add_zero]

/-- `rs1_sign = 0` on an `SRA` row forces the seven-bit residue lookup to bind
the top limb below 128, i.e. the operand is architecturally non-negative. -/
theorem shift_source_msb_false
    (row : ShiftRow)
    (holds : ShiftHolds row)
    (kind : row.kind = ShiftKind.sra)
    (sign : row.rs1Sign = false) :
    row.rs1Next.word.msb = false := by
  have hb := holds.signUpperBound kind
  have hsign : row.signNat = 0 := by simp [ShiftRow.signNat, sign]
  rw [hsign] at hb
  have b0 := row.rs1Next.limb0.isLt
  have b1 := row.rs1Next.limb1.isLt
  have b2 := row.rs1Next.limb2.isLt
  simp only [Nat.reducePow] at b0 b1 b2
  rw [BitVec.msb_eq_decide]
  simp only [WordBytes.word_toNat, WordBytes.value, decide_eq_false_iff_not,
    Nat.reducePow, Nat.reduceSub]
  omega

/-- `rs1_sign = 1` on an `SRA` row forces the top limb to at least 128, i.e. the
operand is architecturally negative, so the sign-fill path is correct. -/
theorem shift_source_msb_true
    (row : ShiftRow)
    (holds : ShiftHolds row)
    (kind : row.kind = ShiftKind.sra)
    (sign : row.rs1Sign = true) :
    row.rs1Next.word.msb = true := by
  have hb := holds.signLowerBound kind
  have hsign : row.signNat = 1 := by simp [ShiftRow.signNat, sign]
  rw [hsign] at hb
  rw [BitVec.msb_eq_decide]
  simp only [WordBytes.word_toNat, WordBytes.value, decide_eq_true_eq,
    Nat.reducePow, Nat.reduceSub]
  omega

theorem shift_right_arithmetic_word
    (row : ShiftRow)
    (holds : ShiftHolds row)
    (kind : row.kind = ShiftKind.sra) :
    row.result.word = row.rs1Next.word.sshiftRight row.shiftAmount := by
  have notLeft : row.kind ≠ ShiftKind.sll := by rw [kind]; decide
  cases sign : row.rs1Sign with
  | false =>
    rw [BitVec.sshiftRight_eq_of_msb_false
      (shift_source_msb_false row holds kind sign)]
    exact shift_right_logical_word row holds notLeft sign
  | true =>
    rw [BitVec.sshiftRight_eq_of_msb_true
      (shift_source_msb_true row holds kind sign)]
    obtain ⟨remainder, hlt, heq⟩ :=
      shift_right_signed_value row holds notLeft sign
    have hpos : 0 < 2 ^ row.shiftAmount := Nat.pow_pos (by omega)
    have hres := row.result.value_lt
    have hsrc := row.rs1Next.value_lt
    simp only [Nat.reducePow] at hres hsrc
    apply BitVec.eq_of_toNat_eq
    rw [BitVec.toNat_not, BitVec.toNat_ushiftRight, BitVec.toNat_not]
    simp only [WordBytes.word_toNat, Nat.shiftRight_eq_div_pow, Nat.reducePow,
      Nat.reduceSub]
    have hprod :
        2 ^ row.shiftAmount * row.result.value +
            2 ^ row.shiftAmount * (4294967295 - row.result.value) =
          2 ^ row.shiftAmount * 4294967295 := by
      rw [← Nat.mul_add]
      congr 1
      omega
    have hquot :
        4294967295 - row.rs1Next.value =
          2 ^ row.shiftAmount * (4294967295 - row.result.value) +
            (2 ^ row.shiftAmount - 1 - remainder) := by
      omega
    rw [hquot, Nat.mul_add_div hpos, Nat.div_eq_of_lt (by omega)]
    omega

/-! ## Destination writeback -/

/-- Constraints 54-60: the committed `rd_next` limbs are the result limbs gated
by the exact `x0` write-enable. -/
theorem shift_destination_value
    (row : ShiftRow)
    (holds : ShiftHolds row) :
    row.rdNext.word = architecturalValue row.rd row.result.word := by
  by_cases isZero : row.rd = zeroRegister
  · have flag : row.rdNonzero = false := by
      rw [holds.destinationFlag]
      simp [isZero]
    rw [isZero, architecturalValue_zero]
    apply BitVec.eq_of_toNat_eq
    simp only [WordBytes.word_toNat]
    simp [
      WordBytes.value,
      holds.destinationLimb0,
      holds.destinationLimb1,
      holds.destinationLimb2,
      holds.destinationLimb3,
      flag,
      WordBytes.zero,
      zeroWord,
    ]
  · have flag : row.rdNonzero = true := by
      rw [holds.destinationFlag]
      simp [isZero]
    rw [architecturalValue]
    simp only [isZero, ↓reduceIte]
    apply BitVec.eq_of_toNat_eq
    simp only [WordBytes.word_toNat]
    simp [
      WordBytes.value,
      holds.destinationLimb0,
      holds.destinationLimb1,
      holds.destinationLimb2,
      holds.destinationLimb3,
      flag,
    ]

/-! ## Program-relation opcode identifiers

`shifts_imm.zig` emits `16 * is_sll + 17 * is_srl + 18 * is_sra`;
`shifts_reg.zig` emits `2 * is_sll + 6 * is_srl + 7 * is_sra`. -/

def shiftsImmOpcodeId : ShiftKind → Nat
  | ShiftKind.sll => 16
  | ShiftKind.srl => 17
  | ShiftKind.sra => 18

def shiftsRegOpcodeId : ShiftKind → Nat
  | ShiftKind.sll => 2
  | ShiftKind.srl => 6
  | ShiftKind.sra => 7

/-! ## The shift-immediate family row: SLLI / SRLI / SRAI -/

structure ShiftsImmRow where
  pc : Word
  clock : Nat
  rs1 : RegisterIndex
  rs1PreviousClock : Nat
  rdPreviousClock : Nat
  /-- `imm_truncated`, the committed shift-amount operand. -/
  immTruncated : Nat
  semantic : ShiftRow
  claimedNextPc : Word
deriving DecidableEq, Repr

structure ShiftsImmHolds (row : ShiftsImmRow) : Prop where
  core : ShiftHolds row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 2)
  /-- Constraint 65: `imm_truncated - shift_amount = 0`. -/
  immediateBinds : row.immTruncated = row.semantic.shiftAmount
  nextPcResult : row.claimedNextPc = nextPc row.pc

def shiftsImmRetirement (row : ShiftsImmRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.semantic.rd row.semantic.rdNext.word

def shiftsImmProgramTuple (row : ShiftsImmRow) : ProgramTuple where
  pc := row.pc
  opcodeId := shiftsImmOpcodeId row.semantic.kind
  rd := row.semantic.rd.toNat
  rs1 := row.rs1.toNat
  operand := row.immTruncated

structure ShiftsImmRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  sourceConsume : RegisterTuple
  sourceEmit : RegisterTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def shiftsImmRelations (row : ShiftsImmRow) : ShiftsImmRelations where
  program := shiftsImmProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  sourceConsume := {
    addr := row.rs1
    clock := row.rs1PreviousClock
    value := row.semantic.rs1Previous.word
  }
  sourceEmit := {
    addr := row.rs1
    clock := accessClock row.clock 1
    value := row.semantic.rs1Next.word
  }
  destinationConsume := {
    addr := row.semantic.rd
    clock := row.rdPreviousClock
    value := row.semantic.rdPrevious.word
  }
  destinationEmit := {
    addr := row.semantic.rd
    clock := accessClock row.clock 2
    value := row.semantic.rdNext.word
  }

/-! ## The shift-register family row: SLL / SRL / SRA -/

structure ShiftsRegRow where
  pc : Word
  clock : Nat
  rs1 : RegisterIndex
  rs1PreviousClock : Nat
  rs2 : RegisterIndex
  rs2PreviousClock : Nat
  rs2Previous : WordBytes
  rs2Next : WordBytes
  rdPreviousClock : Nat
  semantic : ShiftRow
  claimedNextPc : Word
deriving DecidableEq, Repr

structure ShiftsRegHolds (row : ShiftsRegRow) : Prop where
  core : ShiftHolds row.semantic
  clockPositive : 0 < row.clock
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  secondSourceClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  /-- Constraints 65-68, `readOnlyAccessConstraints(rs2, enabler)`. -/
  secondSourceReadOnly : row.rs2Next = row.rs2Previous
  /-- Lookup 9, `range_check_20 (7 - (rs2_next_0 - shift_amount) * 32⁻¹)`:
  the
  requested value is a non-negative integer only when `rs2_next_0` exceeds
  `shift_amount` by a multiple of 32, and the `range_check_20` domain caps the
  quotient at 7 because `rs2_next_0` is a byte. That is exactly the RISC-V
  five-bit mask on the register shift amount. -/
  shiftAmountBinds :
    ∃ high,
      high ≤ 7 ∧
        row.rs2Next.limb0.toNat = 32 * high + row.semantic.shiftAmount
  nextPcResult : row.claimedNextPc = nextPc row.pc

/-- The committed `shift_amount` is exactly `rs2 & 31`. -/
theorem shifts_reg_amount_is_masked
    (row : ShiftsRegRow)
    (holds : ShiftsRegHolds row) :
    row.semantic.shiftAmount = row.rs2Next.word.toNat % 32 := by
  obtain ⟨high, hhigh, hlimb⟩ := holds.shiftAmountBinds
  have hlt := shift_amount_lt_32 row.semantic holds.core
  simp only [WordBytes.word_toNat, WordBytes.value]
  omega

def shiftsRegRetirement (row : ShiftsRegRow) : Retirement where
  nextPc := row.claimedNextPc
  write := architecturalWrite row.semantic.rd row.semantic.rdNext.word

def shiftsRegProgramTuple (row : ShiftsRegRow) : ProgramTuple where
  pc := row.pc
  opcodeId := shiftsRegOpcodeId row.semantic.kind
  rd := row.semantic.rd.toNat
  rs1 := row.rs1.toNat
  operand := row.rs2.toNat

structure ShiftsRegRelations where
  program : ProgramTuple
  stateConsume : StateTuple
  stateEmit : StateTuple
  sourceConsume : RegisterTuple
  sourceEmit : RegisterTuple
  secondSourceConsume : RegisterTuple
  secondSourceEmit : RegisterTuple
  destinationConsume : RegisterTuple
  destinationEmit : RegisterTuple
deriving DecidableEq, Repr

def shiftsRegRelations (row : ShiftsRegRow) : ShiftsRegRelations where
  program := shiftsRegProgramTuple row
  stateConsume := { pc := row.pc, clock := row.clock }
  stateEmit := { pc := nextPc row.pc, clock := row.clock + 1 }
  sourceConsume := {
    addr := row.rs1
    clock := row.rs1PreviousClock
    value := row.semantic.rs1Previous.word
  }
  sourceEmit := {
    addr := row.rs1
    clock := accessClock row.clock 1
    value := row.semantic.rs1Next.word
  }
  secondSourceConsume := {
    addr := row.rs2
    clock := row.rs2PreviousClock
    value := row.rs2Previous.word
  }
  secondSourceEmit := {
    addr := row.rs2
    clock := accessClock row.clock 2
    value := row.rs2Next.word
  }
  destinationConsume := {
    addr := row.semantic.rd
    clock := row.rdPreviousClock
    value := row.semantic.rdPrevious.word
  }
  destinationEmit := {
    addr := row.semantic.rd
    clock := accessClock row.clock 3
    value := row.semantic.rdNext.word
  }

end RiscvRefinement.Air.Family
