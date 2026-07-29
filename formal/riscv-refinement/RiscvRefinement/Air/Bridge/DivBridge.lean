-- The AIR-interpreter bridge for the DIV/DIVU/REM/REMU family.
--
-- Same statement shape as `MulBridge.lean` and `MulhBridge.lean`, over the
-- largest Team B family: 73 columns, 434 nodes, 85 constraint roots, 25
-- lookups. Under `DivHolds row` every constraint root of the *encoded
-- production node table* evaluates to zero, every live fixed-table request
-- lands inside its table, and every lookup tuple is the tuple Team B's
-- `divRelations` describes.
--
-- Two things are worth recording up front, because the O1 feasibility report
-- guessed differently about both.
--
--   * The four-way selector sum is NOT a case split. Constraint 78 is
--     `(is_div + is_divu + is_rem + is_remu) - 1`, so the active-row expression
--     is pinned to one exactly the way `mul`'s `enabler` is pinned by its
--     constraint 16. `DivHolds.selectorUnique` discharges it, and every root
--     that mentions the sum then simplifies without any split. A four-way split
--     is needed in exactly one place, constraint 79 (the opcode identifier on
--     the program bus), and `Air/Family/Div.lean` already provides it as
--     `div_selector_cases`.
--   * `DivRow` is further from a complete AIR row than `MulRow` was. Eleven of
--     the 73 columns have no counterpart in the transcription: the five
--     prover-chosen inverse witnesses (`c_sum_inv`, `r_sum_inv`, `r_inv_0..3`),
--     `destination_inverse`, and the six materialised `bus_value_*` columns.
--     `divColumns` synthesises all of them; the inverses come from the tables
--     in `DivProgram.lean`, checked by evaluation.
--
-- The pc-wrap side condition of the `mul` bridge recurs here verbatim and is
-- carried explicitly as `DivRowFits`; see the comment on that structure.

import RiscvRefinement.Air.Bridge.DivProgram
import RiscvRefinement.Air.Bridge.EvaluatorSpec
import RiscvRefinement.Air.Bridge.MulBridge
import RiscvRefinement.Air.Family.Div

namespace RiscvRefinement.Air.Bridge

open RiscvRefinement
open RiscvRefinement.Air.Family

set_option maxRecDepth 20000

/-! ## The `M31` layer this family adds

`MulBridge.lean` already proves the congruence-arithmetic layer
(`reduce_add`, `reduce_mul`, `reduce_sub`, `reduce_sub_eq_zero`, `sub_self`,
`zero_mul`, `mul_zero`, `reduce_shift`) and it is imported, not restated. What
`div` needs on top is a negation (the magnitude scan runs in the direction
selected by the divisor sign, so half its residuals are multiplied by `-1`) and
an inverse (five columns are prover-chosen field inverses). -/

namespace M31

theorem reduce_congr {left right : Nat} (congruent : left % modulus = right % modulus) :
    M31.reduce left = M31.reduce right := by
  apply eq_of_val
  simp only [val_reduce, congruent]

theorem sub_expand (left right : Nat) :
    M31.reduce left - M31.reduce right =
      M31.reduce (left % modulus + modulus - right % modulus) := rfl

theorem reduce_sub_of_lt {left right : Nat}
    (leftBound : left < modulus) (rightBound : right < modulus) :
    M31.reduce left - M31.reduce right = M31.reduce (left + modulus - right) := by
  rw [sub_expand, Nat.mod_eq_of_lt leftBound, Nat.mod_eq_of_lt rightBound]

theorem zero_add (value : M31) : 0 + value = value := by
  apply eq_of_val
  simp only [val_add, val_zero, Nat.zero_add]
  exact Nat.mod_eq_of_lt value.isLt

theorem add_zero (value : M31) : value + 0 = value := by
  apply eq_of_val
  simp only [val_add, val_zero, Nat.add_zero]
  exact Nat.mod_eq_of_lt value.isLt

theorem sub_zero (value : M31) : value - 0 = value := by
  apply eq_of_val
  simp only [val_sub, val_zero, Nat.sub_zero, modulus, m31Modulus]
  have := value.isLt
  simp only [m31Modulus] at this
  omega

/-- `(modulus - 1) * (modulus - value) = value` in the field: multiplication by
`-1` negates. This is what turns the divisor-sign orientation factor
`1 - 2 * c_sign` into a plain sign flip. -/
theorem negate (value : Nat) (bound : value < modulus) :
    M31.reduce (modulus - 1) * M31.reduce (modulus - value) = M31.reduce value := by
  rw [reduce_mul]
  apply reduce_congr
  have small : value < m31Modulus := bound
  have expand : (modulus - 1) * (modulus - value) = modulus * (modulus - value - 1) + value := by
    simp only [modulus, m31Modulus] at small ⊢
    omega
  rw [expand, Nat.mul_add_mod]

/-- A checked table entry really is a field inverse. -/
theorem mul_inverse {value inverse : Nat}
    (inverts : (value * inverse) % m31Modulus = 1) :
    M31.reduce value * M31.reduce inverse = M31.reduce 1 := by
  rw [reduce_mul]
  apply reduce_congr
  simpa [modulus] using inverts

end M31

/-! ## The synthesised inverse columns -/

/-- `flagValue` (imported from `MulBridge.lean`) is `Bool.toNat`. -/
theorem flagValue_eq_toNat (flag : Bool) : flagValue flag = flag.toNat := by
  cases flag <;> rfl

/-- The four-byte limb sum the AIR's `c_sum` / `r_sum` nodes compute. -/
def limbSum (bytes : WordBytes) : Nat :=
  bytes.limb0.toNat + bytes.limb1.toNat + bytes.limb2.toNat + bytes.limb3.toNat

theorem limbSum_lt (bytes : WordBytes) : limbSum bytes < 1021 := by
  have b0 := bytes.limb0.isLt
  have b1 := bytes.limb1.isLt
  have b2 := bytes.limb2.isLt
  have b3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at b0 b1 b2 b3
  simp only [limbSum]
  omega

theorem limbSum_pos {bytes : WordBytes} (nonzero : bytes.value ≠ 0) : 0 < limbSum bytes := by
  simp only [limbSum]
  simp only [WordBytes.value] at nonzero
  omega

/-- `c_sum_inv` / `r_sum_inv`: the field inverse of a four-byte limb sum. -/
def limbSumInverse (bytes : WordBytes) : M31 :=
  M31.reduce (tableAt limbSumInverseTable (limbSum bytes))

/-- `r_inv_i`: the field inverse of `r_abs_i - 256`. -/
def absLimbInverse (limb : Byte) : M31 :=
  M31.reduce (tableAt absInverseTable limb.toNat)

theorem limbSumInverse_spec (bytes : WordBytes) (nonzero : bytes.value ≠ 0) :
    M31.reduce (limbSum bytes) * limbSumInverse bytes = M31.reduce 1 := by
  refine M31.mul_inverse ?_
  have covered : limbSum bytes < limbSumInverseTable.length := by
    rw [limbSumInverseTable_length]
    exact limbSum_lt bytes
  have positive : 0 < 0 + limbSum bytes := by
    simpa using limbSum_pos nonzero
  have step :=
    inverseOk_spec limbSumInverseTable 0 (limbSum bytes) limbSumInverseTable_ok
      covered positive
  simpa using step

theorem absLimbInverse_spec (limb : Byte) :
    (M31.reduce limb.toNat - M31.reduce 256) * absLimbInverse limb = M31.reduce 1 := by
  have small : limb.toNat < 256 := by simpa using limb.isLt
  have covered : limb.toNat < absInverseTable.length := by
    rw [absInverseTable_length]; exact small
  have positive : 0 < m31Modulus - 256 + limb.toNat := by
    simp only [m31Modulus]; omega
  have step :=
    inverseOk_spec absInverseTable (m31Modulus - 256) limb.toNat absInverseTable_ok
      covered positive
  rw [M31.reduce_sub_of_lt (by simp only [M31.modulus, m31Modulus]; omega)
    (by simp only [M31.modulus, m31Modulus]; omega)]
  refine M31.mul_inverse ?_
  have rearrange : limb.toNat + M31.modulus - 256 = m31Modulus - 256 + limb.toNat := by
    simp only [M31.modulus, m31Modulus]; omega
  rw [rearrange]
  exact step

/-! ## The column assignment

`DivRow` laid out as the 73 columns of `div.json`. Eleven entries are
synthesised; they are the ones with a comment. -/

def divColumns (row : DivRow) : List M31 :=
  [ M31.reduce row.clock,                             -- 0  clock
    M31.reduce row.pc.toNat,                          -- 1  pc
    M31.reduce row.rd.toNat,                          -- 2  rd_addr
    M31.reduce row.rdPrevious.limb0.toNat,            -- 3  rd_previous_0
    M31.reduce row.rdPrevious.limb1.toNat,            -- 4  rd_previous_1
    M31.reduce row.rdPrevious.limb2.toNat,            -- 5  rd_previous_2
    M31.reduce row.rdPrevious.limb3.toNat,            -- 6  rd_previous_3
    M31.reduce row.rdPreviousClock,                   -- 7  rd_previous_clock
    M31.reduce row.rdNext.limb0.toNat,                -- 8  rd_next_0
    M31.reduce row.rdNext.limb1.toNat,                -- 9  rd_next_1
    M31.reduce row.rdNext.limb2.toNat,                -- 10 rd_next_2
    M31.reduce row.rdNext.limb3.toNat,                -- 11 rd_next_3
    M31.reduce row.rs1.toNat,                         -- 12 rs1_addr
    M31.reduce row.rs1Previous.limb0.toNat,           -- 13 rs1_previous_0
    M31.reduce row.rs1Previous.limb1.toNat,           -- 14 rs1_previous_1
    M31.reduce row.rs1Previous.limb2.toNat,           -- 15 rs1_previous_2
    M31.reduce row.rs1Previous.limb3.toNat,           -- 16 rs1_previous_3
    M31.reduce row.rs1PreviousClock,                  -- 17 rs1_previous_clock
    M31.reduce row.rs1Next.limb0.toNat,               -- 18 rs1_next_0
    M31.reduce row.rs1Next.limb1.toNat,               -- 19 rs1_next_1
    M31.reduce row.rs1Next.limb2.toNat,               -- 20 rs1_next_2
    M31.reduce row.rs1Next.limb3.toNat,               -- 21 rs1_next_3
    M31.reduce row.rs2.toNat,                         -- 22 rs2_addr
    M31.reduce row.rs2Previous.limb0.toNat,           -- 23 rs2_previous_0
    M31.reduce row.rs2Previous.limb1.toNat,           -- 24 rs2_previous_1
    M31.reduce row.rs2Previous.limb2.toNat,           -- 25 rs2_previous_2
    M31.reduce row.rs2Previous.limb3.toNat,           -- 26 rs2_previous_3
    M31.reduce row.rs2PreviousClock,                  -- 27 rs2_previous_clock
    M31.reduce row.rs2Next.limb0.toNat,               -- 28 rs2_next_0
    M31.reduce row.rs2Next.limb1.toNat,               -- 29 rs2_next_1
    M31.reduce row.rs2Next.limb2.toNat,               -- 30 rs2_next_2
    M31.reduce row.rs2Next.limb3.toNat,               -- 31 rs2_next_3
    M31.reduce (flagValue row.zeroDivisor),           -- 32 zero_divisor
    M31.reduce (flagValue row.rZero),                 -- 33 r_zero
    M31.reduce row.quotient.limb0.toNat,              -- 34 q_0
    M31.reduce row.quotient.limb1.toNat,              -- 35 q_1
    M31.reduce row.quotient.limb2.toNat,              -- 36 q_2
    M31.reduce row.quotient.limb3.toNat,              -- 37 q_3
    M31.reduce row.remainder.limb0.toNat,             -- 38 r_0
    M31.reduce row.remainder.limb1.toNat,             -- 39 r_1
    M31.reduce row.remainder.limb2.toNat,             -- 40 r_2
    M31.reduce row.remainder.limb3.toNat,             -- 41 r_3
    M31.reduce (flagValue row.bSign),                 -- 42 b_sign
    M31.reduce (flagValue row.cSign),                 -- 43 c_sign
    M31.reduce (flagValue row.qSign),                 -- 44 q_sign
    M31.reduce (flagValue row.signXor),               -- 45 sign_xor
    limbSumInverse row.rs2Next,                       -- 46 c_sum_inv     (synthesised)
    limbSumInverse row.remainder,                     -- 47 r_sum_inv     (synthesised)
    M31.reduce row.remainderAbs.limb0.toNat,          -- 48 r_abs_0
    M31.reduce row.remainderAbs.limb1.toNat,          -- 49 r_abs_1
    M31.reduce row.remainderAbs.limb2.toNat,          -- 50 r_abs_2
    M31.reduce row.remainderAbs.limb3.toNat,          -- 51 r_abs_3
    absLimbInverse row.remainderAbs.limb0,            -- 52 r_inv_0       (synthesised)
    absLimbInverse row.remainderAbs.limb1,            -- 53 r_inv_1       (synthesised)
    absLimbInverse row.remainderAbs.limb2,            -- 54 r_inv_2       (synthesised)
    absLimbInverse row.remainderAbs.limb3,            -- 55 r_inv_3       (synthesised)
    M31.reduce (flagValue row.ltMarker0),             -- 56 lt_markers_0
    M31.reduce (flagValue row.ltMarker1),             -- 57 lt_markers_1
    M31.reduce (flagValue row.ltMarker2),             -- 58 lt_markers_2
    M31.reduce (flagValue row.ltMarker3),             -- 59 lt_markers_3
    M31.reduce row.ltDiff,                            -- 60 lt_diff
    M31.reduce (flagValue row.isDiv),                 -- 61 is_div
    M31.reduce (flagValue row.isDivu),                -- 62 is_divu
    M31.reduce (flagValue row.isRem),                 -- 63 is_rem
    M31.reduce (flagValue row.isRemu),                -- 64 is_remu
    M31.reduce (flagValue row.destinationNonzero),    -- 65 destination_nonzero
    registerInverse row.rd,                           -- 66 destination_inverse (synthesised)
    M31.reduce (divOpcodeId row),                     -- 67 bus_value_67  (synthesised)
    M31.reduce row.claimedNextPc.toNat,               -- 68 bus_value_68  (synthesised)
    M31.reduce (row.clock + 1),                       -- 69 bus_value_69  (synthesised)
    M31.reduce (accessClock row.clock 1),             -- 70 bus_value_70  (synthesised)
    M31.reduce (accessClock row.clock 2),             -- 71 bus_value_71  (synthesised)
    M31.reduce (accessClock row.clock 3) ]            -- 72 bus_value_72  (synthesised)

/-- The side condition the transcription does not carry, identical to
`MulRowFits`.

`DivRow.pc` is a `BitVec 32` and `nextPc` wraps at `2 ^ 32`; the AIR's `pc` is
one field element and its next-pc node is `pc + 4` in `M31`. The two disagree
exactly when `pc.toNat + 4 ≥ 2 ^ 32`, and `DivHolds` does not rule that out.
This is a real gap in the capsule, not an artefact of the bridge -- every family
with a `nextPc` obligation has it -- and it is carried here explicitly rather
than assumed quietly. -/
structure DivRowFits (row : DivRow) : Prop where
  programCounter : row.pc.toNat + 4 < 4294967296


/-! ## Row facts the constraint proofs consume

`DivHolds` speaks about `Bool`s and `Nat`s; the AIR speaks about `M31`. Each
lemma below is one translation, and each is used by between one and eight of
the 85 constraint roots. -/

private theorem bool_of_toNat_zero {flag : Bool} (zero : flag.toNat = 0) : flag = false := by
  cases flag <;> simp_all

/-- Constraint 78 pins the four-way selector sum to one, so the "active row"
expression that 14 other roots multiply by is the constant `1`. This is why the
`div` bridge needs no four-way case split outside constraint 79. -/
private theorem activeOne (row : DivRow) (holds : DivHolds row) :
    M31.reduce (flagValue row.isDiv) + M31.reduce (flagValue row.isDivu) +
        M31.reduce (flagValue row.isRem) + M31.reduce (flagValue row.isRemu) =
      M31.reduce 1 := by
  simp only [flagValue_eq_toNat, M31.reduce_add, holds.selectorUnique]

private theorem signedNat (row : DivRow) (holds : DivHolds row) :
    row.isDiv.toNat + row.isRem.toNat = row.isSigned.toNat := by
  rcases div_selector_cases row holds with
    ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ <;>
    simp [DivRow.isSigned, a, c]

/-- `is_div + is_rem` is the AIR's spelling of `DivRow.isSigned`. -/
private theorem signedSum (row : DivRow) (holds : DivHolds row) :
    M31.reduce (flagValue row.isDiv) + M31.reduce (flagValue row.isRem) =
      M31.reduce (flagValue row.isSigned) := by
  simp only [flagValue_eq_toNat, M31.reduce_add, signedNat row holds]

private theorem divisionNat (row : DivRow) (holds : DivHolds row) :
    row.isDiv.toNat + row.isDivu.toNat = row.isDivision.toNat := by
  rcases div_selector_cases row holds with
    ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ <;>
    simp [DivRow.isDivision, a, b]

/-- `is_div + is_divu` is the AIR's spelling of `DivRow.isDivision`. -/
private theorem divisionSum (row : DivRow) (holds : DivHolds row) :
    M31.reduce (flagValue row.isDiv) + M31.reduce (flagValue row.isDivu) =
      M31.reduce (flagValue row.isDivision) := by
  simp only [flagValue_eq_toNat, M31.reduce_add, divisionNat row holds]

private theorem boolVanishes (flag : Bool) :
    M31.reduce (flagValue flag) * (M31.reduce 1 - M31.reduce (flagValue flag)) = 0 := by
  cases flag with
  | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
  | true => simp only [flagValue]; rw [M31.sub_self, M31.mul_zero]

private theorem boolVanishesFlipped (flag : Bool) :
    M31.reduce (flagValue flag) * (M31.reduce (flagValue flag) - M31.reduce 1) = 0 := by
  cases flag with
  | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
  | true => simp only [flagValue]; rw [M31.sub_self, M31.mul_zero]

private theorem pairBoolVanishes (left right : Bool) (exclusive : left = true → right = false) :
    (M31.reduce (flagValue left) + M31.reduce (flagValue right)) *
      (M31.reduce 1 - (M31.reduce (flagValue left) + M31.reduce (flagValue right))) = 0 := by
  cases hl : left with
  | false => cases hr : right <;> decide
  | true => rw [exclusive hl]; decide

/-- `selector * value = 0`: the selector is off, or the value is. -/
private theorem gatedLimbVanishes (flag : Bool) (limb : Byte) (zero : flag = true → limb = 0) :
    M31.reduce (flagValue flag) * M31.reduce limb.toNat = 0 := by
  cases hf : flag with
  | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
  | true => rw [zero hf]; decide

/-- `selector * (value - constant) = 0`. -/
private theorem gatedConstVanishes (flag : Bool) (limb : Byte) (value : Nat)
    (equal : flag = true → limb.toNat = value) :
    M31.reduce (flagValue flag) * (M31.reduce limb.toNat - M31.reduce value) = 0 := by
  cases hf : flag with
  | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
  | true => rw [equal hf, M31.sub_self, M31.mul_zero]

/-- `(1 - is_signed) * sign = 0`. -/
private theorem unsignedSignVanishes (signed flag : Bool) (forced : signed = false → flag = false) :
    (M31.reduce 1 - M31.reduce (flagValue signed)) * M31.reduce (flagValue flag) = 0 := by
  cases hs : signed with
  | false => rw [forced hs]; simp only [flagValue, M31.reduce_zero, M31.mul_zero]
  | true => simp only [flagValue]; rw [M31.sub_self, M31.zero_mul]

/-- `(1 - sign_xor) * (r_abs - r) = 0`. -/
private theorem absSameVanishes (signXor : Bool) (absLimb limb : Byte)
    (same : signXor = false → absLimb.toNat = limb.toNat) :
    (M31.reduce 1 - M31.reduce (flagValue signXor)) *
      (M31.reduce absLimb.toNat - M31.reduce limb.toNat) = 0 := by
  cases hs : signXor with
  | false => rw [same hs, M31.sub_self, M31.mul_zero]
  | true => simp only [flagValue]; rw [M31.sub_self, M31.zero_mul]

private theorem limbSumImage (bytes : WordBytes) :
    M31.reduce bytes.limb0.toNat + M31.reduce bytes.limb1.toNat +
        M31.reduce bytes.limb2.toNat + M31.reduce bytes.limb3.toNat =
      M31.reduce (limbSum bytes) := by
  simp only [M31.reduce_add, limbSum]

private theorem limbSumVanishes (bytes : WordBytes) (zero : bytes.value = 0) :
    M31.reduce bytes.limb0.toNat + M31.reduce bytes.limb1.toNat +
        M31.reduce bytes.limb2.toNat + M31.reduce bytes.limb3.toNat = 0 := by
  rw [limbSumImage]
  have collapse : limbSum bytes = 0 := by
    simp only [limbSum]
    simp only [WordBytes.value] at zero
    omega
  rw [collapse, M31.reduce_zero]

/-- The AIR spells a carry as `(previous + limb + absLimb) * 256⁻¹`; the
transcription spells the same fact as `previous + limb + absLimb = 256 * carry`.
`8388608 = 256⁻¹ mod (2 ^ 31 - 1)`, so the two agree. Used sixteen times, once
per residual of the two's-complement negation chain. -/
private theorem carryImage (previous limb absLimb : Nat) (carry : Bool)
    (equation : previous + limb + absLimb = 256 * carry.toNat) :
    (M31.reduce previous + M31.reduce limb + M31.reduce absLimb) * M31.reduce 8388608 =
      M31.reduce carry.toNat := by
  rw [M31.reduce_add, M31.reduce_add, equation, M31.reduce_mul]
  exact M31.reduce_shift _

/-- The magnitude-scan guard. `scanTotal` makes every prefix sum at most one, so
either the guard is zero or the scan has not fired yet and the limb difference
must vanish. -/
private theorem guardRootVanishes (sum : Nat) (rest : M31)
    (small : sum ≤ 1) (zeroCase : sum = 0 → rest = 0) :
    (M31.reduce 1 - M31.reduce sum) * rest = 0 := by
  cases sum with
  | zero => rw [zeroCase rfl, M31.mul_zero]
  | succ smaller =>
      have collapse : smaller = 0 := by omega
      subst collapse
      rw [M31.sub_self, M31.zero_mul]

private theorem compareDiff_zero {row : DivRow} {divisorLimb absLimb : Byte}
    (zero : divCompareDiff row divisorLimb absLimb = 0) :
    divisorLimb.toNat = absLimb.toNat := by
  unfold divCompareDiff at zero
  split at zero <;> omega

/-- `lt_markers[i] * (lt_diff - diffs[i]) = 0`. The orientation factor
`1 - 2 * c_sign` is `1` or `-1`, and `M31.negate` is what makes the `-1` case a
plain sign flip rather than a wrap. -/
private theorem scanMarkerVanishes (row : DivRow) (marker : Bool)
    (divisorLimb absLimb : Byte)
    (equation : marker = true →
      (row.ltDiff : Int) = divCompareDiff row divisorLimb absLimb) :
    M31.reduce (flagValue marker) *
        (M31.reduce row.ltDiff -
          (M31.reduce 1 - M31.reduce (flagValue row.cSign) * M31.reduce 2) *
            (M31.reduce divisorLimb.toNat - M31.reduce absLimb.toNat)) = 0 := by
  cases hm : marker with
  | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
  | true =>
      have relation := equation hm
      have divisorBound : divisorLimb.toNat < 256 := by simpa using divisorLimb.isLt
      have absBound : absLimb.toNat < 256 := by simpa using absLimb.isLt
      cases hc : row.cSign with
      | false =>
          simp only [divCompareDiff, hc, Bool.false_eq_true, if_false] at relation
          have order : absLimb.toNat ≤ divisorLimb.toNat := by omega
          have gap : row.ltDiff = divisorLimb.toNat - absLimb.toNat := by omega
          simp only [flagValue, M31.reduce_zero, M31.zero_mul, M31.sub_zero]
          rw [M31.reduce_sub _ _ order, ← gap, M31.reduce_mul, Nat.one_mul, M31.sub_self,
            M31.mul_zero]
      | true =>
          simp only [divCompareDiff, hc, if_true] at relation
          have order : divisorLimb.toNat ≤ absLimb.toNat := by omega
          have gap : row.ltDiff = absLimb.toNat - divisorLimb.toNat := by omega
          have small : row.ltDiff < M31.modulus := by
            simp only [M31.modulus, m31Modulus]; omega
          simp only [flagValue]
          rw [show M31.reduce 1 - M31.reduce 1 * M31.reduce 2 = M31.reduce (M31.modulus - 1) from
            by decide]
          rw [M31.reduce_sub_of_lt (by simp only [M31.modulus, m31Modulus]; omega)
            (by simp only [M31.modulus, m31Modulus]; omega)]
          rw [show divisorLimb.toNat + M31.modulus - absLimb.toNat = M31.modulus - row.ltDiff from
            by simp only [M31.modulus, m31Modulus]; omega]
          rw [M31.negate row.ltDiff small, M31.sub_self, M31.mul_zero]

/-- `rd_next[i] - destination_nonzero * (is_division * q[i] + (1 - is_division) * r[i])`. -/
private theorem destinationResultVanishes (destinationNonzero division : Bool)
    (next quotientLimb remainderLimb : Byte)
    (equation : next =
      if destinationNonzero then (if division then quotientLimb else remainderLimb) else 0) :
    M31.reduce next.toNat -
        M31.reduce (flagValue destinationNonzero) *
          (M31.reduce (flagValue division) * M31.reduce quotientLimb.toNat +
            (M31.reduce 1 - M31.reduce (flagValue division)) *
              M31.reduce remainderLimb.toNat) = 0 := by
  cases hd : destinationNonzero with
  | false =>
      rw [hd, if_neg (by simp)] at equation
      rw [equation]
      simp only [flagValue, M31.reduce_zero, M31.zero_mul]
      rw [M31.sub_zero]
      rfl
  | true =>
      rw [hd, if_pos rfl] at equation
      cases hv : division with
      | false =>
          rw [hv, if_neg (by simp)] at equation
          rw [equation]
          simp only [flagValue, M31.reduce_zero, M31.zero_mul, M31.zero_add, M31.sub_zero,
            M31.reduce_mul, Nat.one_mul, M31.sub_self]
      | true =>
          rw [hv, if_pos rfl] at equation
          rw [equation]
          simp only [flagValue, M31.sub_self, M31.zero_mul, M31.add_zero, M31.reduce_mul,
            Nat.one_mul]

private theorem rdNonzeroImage (row : DivRow) (holds : DivHolds row) :
    row.destinationNonzero = decide (row.rd.toNat ≠ 0) := by
  have index : (row.rd = zeroRegister) ↔ (row.rd.toNat = 0) := by
    constructor
    · intro equal
      rw [equal]
      rfl
    · intro equal
      apply BitVec.eq_of_toNat_eq
      rw [equal]
      rfl
  rw [holds.destinationFlag]
  simp only [ne_eq, index]

private theorem destinationSelectorVanishes (row : DivRow) (holds : DivHolds row) :
    M31.reduce row.rd.toNat *
        (M31.reduce 1 - M31.reduce (flagValue row.destinationNonzero)) = 0 := by
  cases flag : row.destinationNonzero with
  | false =>
      have image := rdNonzeroImage row holds
      rw [flag] at image
      have zero : row.rd.toNat = 0 := by simpa using image.symm
      rw [zero]
      simp only [flagValue, M31.reduce_zero, M31.zero_mul]
  | true => simp only [flagValue]; rw [M31.sub_self, M31.mul_zero]

private theorem nextPcImage (row : DivRow) (holds : DivHolds row) (fits : DivRowFits row) :
    row.claimedNextPc.toNat = row.pc.toNat + 4 := by
  have wrap := fits.programCounter
  simp only [holds.nextPcResult, RiscvRefinement.nextPc, BitVec.toNat_add,
    BitVec.toNat_ofNat, Nat.reducePow]
  omega

private theorem readOnlyVanishes (limbNext limbPrevious : Byte)
    (equal : limbNext = limbPrevious) :
    M31.reduce 1 * (M31.reduce limbNext.toNat - M31.reduce limbPrevious.toNat) = 0 := by
  rw [equal, M31.sub_self, M31.mul_zero]

private theorem reduceToNat_lt {value bound : Nat} (small : value < bound) :
    (M31.reduce value).toNat < bound := by
  simp only [M31.toNat, M31.val_reduce]
  exact Nat.lt_of_le_of_lt (Nat.mod_le _ _) small

/-! ## The bridge for the constraint roots

Unfold the encoded node table under the column assignment -- this *is* the
evaluation of the production AIR -- and discharge the 85 resulting `M31`
identities from `DivHolds`. -/

set_option maxRecDepth 100000 in
/-- Every constraint root of the encoded production `div` AIR evaluates to zero
under `divColumns row`, for every row the transcription accepts. -/
theorem divConstraintValues (row : DivRow) (holds : DivHolds row) (fits : DivRowFits row) :
    divProgramCompiled.constraintValues (divColumns row) = List.replicate 85 0 := by
  simp only [DivCircuit.constraintValues, DivCircuit.values, DivCircuit.value,
    DivCircuit.nodeValuesRev, divProgramCompiled, divProgram, evalLoop,
    Node.evalLocal, nth, List.map_cons, List.map_nil, divColumns, List.replicate,
    List.cons.injEq, and_true]
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  -- 0  active * (1 - active)
  · rw [activeOne row holds, M31.sub_self, M31.mul_zero]
  -- 1  booleanity of isDiv
  · exact boolVanishes row.isDiv
  -- 2  booleanity of isDivu
  · exact boolVanishes row.isDivu
  -- 3  booleanity of isRem
  · exact boolVanishes row.isRem
  -- 4  booleanity of isRemu
  · exact boolVanishes row.isRemu
  -- 5  booleanity of zeroDivisor
  · exact boolVanishes row.zeroDivisor
  -- 6  booleanity of rZero
  · exact boolVanishes row.rZero
  -- 7  booleanity of bSign
  · exact boolVanishes row.bSign
  -- 8  booleanity of cSign
  · exact boolVanishes row.cSign
  -- 9  booleanity of qSign
  · exact boolVanishes row.qSign
  -- 10  booleanity of signXor
  · exact boolVanishes row.signXor
  -- 11  booleanity of ltMarker0
  · exact boolVanishes row.ltMarker0
  -- 12  booleanity of ltMarker1
  · exact boolVanishes row.ltMarker1
  -- 13  booleanity of ltMarker2
  · exact boolVanishes row.ltMarker2
  -- 14  booleanity of ltMarker3
  · exact boolVanishes row.ltMarker3
  -- 15 booleanity of zero_divisor + r_zero
  · exact pairBoolVanishes row.zeroDivisor row.rZero holds.specialExclusive
  -- 16 booleanity of active - zero_divisor
  · rw [activeOne row holds]
    cases hzd : row.zeroDivisor <;> decide
  -- 17 booleanity of active - (zero_divisor + r_zero)
  · rw [activeOne row holds]
    cases hzd : row.zeroDivisor with
    | true => rw [holds.specialExclusive hzd]; decide
    | false => cases hrz : row.rZero <;> decide
  -- 18 zero_divisor * rs2_next_0
  · exact gatedLimbVanishes row.zeroDivisor _ holds.zeroDivisorLimb0
  -- 19 zero_divisor * rs2_next_1
  · exact gatedLimbVanishes row.zeroDivisor _ holds.zeroDivisorLimb1
  -- 20 zero_divisor * rs2_next_2
  · exact gatedLimbVanishes row.zeroDivisor _ holds.zeroDivisorLimb2
  -- 21 zero_divisor * rs2_next_3
  · exact gatedLimbVanishes row.zeroDivisor _ holds.zeroDivisorLimb3
  -- 22 zero_divisor * (q_0 - 255)
  · exact gatedConstVanishes row.zeroDivisor _ 255
      (fun h => by rw [holds.zeroDivisorQuotient0 h]; rfl)
  -- 23 zero_divisor * (q_1 - 255)
  · exact gatedConstVanishes row.zeroDivisor _ 255
      (fun h => by rw [holds.zeroDivisorQuotient1 h]; rfl)
  -- 24 zero_divisor * (q_2 - 255)
  · exact gatedConstVanishes row.zeroDivisor _ 255
      (fun h => by rw [holds.zeroDivisorQuotient2 h]; rfl)
  -- 25 zero_divisor * (q_3 - 255)
  · exact gatedConstVanishes row.zeroDivisor _ 255
      (fun h => by rw [holds.zeroDivisorQuotient3 h]; rfl)
  -- 26 c_sum_inv witnesses a nonzero divisor
  · rw [activeOne row holds]
    cases hzd : row.zeroDivisor with
    | true => simp only [flagValue]; rw [M31.sub_self, M31.zero_mul]
    | false =>
        rw [limbSumImage, limbSumInverse_spec _ (holds.divisorNonzero hzd), M31.sub_self,
          M31.mul_zero]
  -- 27 r_zero * r_0
  · exact gatedLimbVanishes row.rZero _ holds.remainderZeroLimb0
  -- 28 r_zero * r_1
  · exact gatedLimbVanishes row.rZero _ holds.remainderZeroLimb1
  -- 29 r_zero * r_2
  · exact gatedLimbVanishes row.rZero _ holds.remainderZeroLimb2
  -- 30 r_zero * r_3
  · exact gatedLimbVanishes row.rZero _ holds.remainderZeroLimb3
  -- 31 r_sum_inv witnesses a nonzero remainder
  · rw [activeOne row holds]
    cases hzd : row.zeroDivisor with
    | true =>
        rw [holds.specialExclusive hzd]
        simp only [flagValue]
        rw [show M31.reduce 1 - (M31.reduce 1 + M31.reduce 0) = 0 from by decide,
          M31.zero_mul]
    | false =>
        cases hrz : row.rZero with
        | true =>
            simp only [flagValue]
            rw [show M31.reduce 1 - (M31.reduce 0 + M31.reduce 1) = 0 from by decide,
              M31.zero_mul]
        | false =>
            rw [limbSumImage, limbSumInverse_spec _ (holds.remainderNonzero hzd hrz),
              M31.sub_self, M31.mul_zero]
  -- 32 (1 - is_signed) * b_sign
  · rw [signedSum row holds]
    exact unsignedSignVanishes row.isSigned row.bSign holds.unsignedDividendSign
  -- 33 (1 - is_signed) * c_sign
  · rw [signedSum row holds]
    exact unsignedSignVanishes row.isSigned row.cSign holds.unsignedDivisorSign
  -- 34 sign_xor = b_sign xor c_sign
  · rw [activeOne row holds]
    have xorDefinition := holds.signXorDefinition
    cases hb : row.bSign <;> cases hc : row.cSign <;>
      rw [xorDefinition, hb, hc] <;> decide
  -- 35 (1 - zero_divisor) * q_sum * (q_sign - sign_xor)
  · cases hzd : row.zeroDivisor with
    | true => simp only [flagValue]; rw [M31.sub_self, M31.zero_mul, M31.zero_mul]
    | false =>
        by_cases hq : row.quotient.value = 0
        · rw [limbSumVanishes row.quotient hq, M31.mul_zero, M31.zero_mul]
        · rw [holds.quotientSignMatches hzd hq, M31.sub_self, M31.mul_zero]
  -- 36 (1 - zero_divisor) * (q_sign - sign_xor) * q_sign
  · cases hzd : row.zeroDivisor with
    | true => simp only [flagValue]; rw [M31.sub_self, M31.zero_mul, M31.zero_mul]
    | false =>
        cases hq : row.qSign with
        | false => simp only [flagValue, M31.reduce_zero]; rw [M31.mul_zero]
        | true =>
            rw [holds.quotientSignImpliesXor hzd hq]
            simp only [flagValue]
            rw [M31.sub_self, M31.mul_zero, M31.zero_mul]
  -- 37 zero_divisor * (q_sign - is_signed)
  · rw [signedSum row holds]
    cases hzd : row.zeroDivisor with
    | false => simp only [flagValue, M31.reduce_zero]; rw [M31.zero_mul]
    | true => rw [holds.zeroDivisorQuotientSign hzd, M31.sub_self, M31.mul_zero]
  -- 38 (1 - sign_xor) * (r_abs_0 - r_0)
  · exact absSameVanishes row.signXor _ _
      (fun h => by rw [holds.absSameLimb0 h])
  -- 39 sign_xor * carry_0 * (carry_0 - 1)
  · cases hsx : row.signXor with
    | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
    | true =>
        obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
          holds.negationRecurrence hsx
        rw [carryImage 0 row.remainder.limb0.toNat row.remainderAbs.limb0.toNat n0
            (by omega)]
        cases n0 <;> decide
  -- 40 sign_xor * (1 - carry_0) * r_abs_0
  · cases hsx : row.signXor with
    | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
    | true =>
        obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
          holds.negationRecurrence hsx
        rw [carryImage 0 row.remainder.limb0.toNat row.remainderAbs.limb0.toNat n0
            (by omega)]
        cases hn : n0 with
        | false => rw [z0 hn]; decide
        | true =>
            simp only [Bool.toNat_true]
            rw [M31.sub_self, M31.mul_zero, M31.zero_mul]
  -- 41 sign_xor * ((r_abs_0 - 256) * r_inv_0 - 1)
  · rw [absLimbInverse_spec, M31.sub_self, M31.mul_zero]
  -- 42 (1 - sign_xor) * (r_abs_1 - r_1)
  · exact absSameVanishes row.signXor _ _
      (fun h => by rw [holds.absSameLimb1 h])
  -- 43 sign_xor * (carry_1 - carry_0) * (carry_1 - 1)
  · cases hsx : row.signXor with
    | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
    | true =>
        obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
          holds.negationRecurrence hsx
        rw [carryImage 0 row.remainder.limb0.toNat row.remainderAbs.limb0.toNat n0
            (by omega),
          carryImage n0.toNat row.remainder.limb1.toNat row.remainderAbs.limb1.toNat n1
            (by omega)]
        rcases m1 with step | step <;> rw [step] <;>
          cases n0 <;> decide
  -- 44 sign_xor * (1 - carry_1) * r_abs_1
  · cases hsx : row.signXor with
    | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
    | true =>
        obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
          holds.negationRecurrence hsx
        rw [carryImage 0 row.remainder.limb0.toNat row.remainderAbs.limb0.toNat n0
            (by omega),
          carryImage n0.toNat row.remainder.limb1.toNat row.remainderAbs.limb1.toNat n1
            (by omega)]
        cases hn : n1 with
        | false => rw [z1 hn]; decide
        | true =>
            simp only [Bool.toNat_true]
            rw [M31.sub_self, M31.mul_zero, M31.zero_mul]
  -- 45 sign_xor * ((r_abs_1 - 256) * r_inv_1 - 1)
  · rw [absLimbInverse_spec, M31.sub_self, M31.mul_zero]
  -- 46 (1 - sign_xor) * (r_abs_2 - r_2)
  · exact absSameVanishes row.signXor _ _
      (fun h => by rw [holds.absSameLimb2 h])
  -- 47 sign_xor * (carry_2 - carry_1) * (carry_2 - 1)
  · cases hsx : row.signXor with
    | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
    | true =>
        obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
          holds.negationRecurrence hsx
        rw [carryImage 0 row.remainder.limb0.toNat row.remainderAbs.limb0.toNat n0
            (by omega),
          carryImage n0.toNat row.remainder.limb1.toNat row.remainderAbs.limb1.toNat n1
            (by omega),
          carryImage n1.toNat row.remainder.limb2.toNat row.remainderAbs.limb2.toNat n2
            (by omega)]
        rcases m2 with step | step <;> rw [step] <;>
          cases n1 <;> decide
  -- 48 sign_xor * (1 - carry_2) * r_abs_2
  · cases hsx : row.signXor with
    | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
    | true =>
        obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
          holds.negationRecurrence hsx
        rw [carryImage 0 row.remainder.limb0.toNat row.remainderAbs.limb0.toNat n0
            (by omega),
          carryImage n0.toNat row.remainder.limb1.toNat row.remainderAbs.limb1.toNat n1
            (by omega),
          carryImage n1.toNat row.remainder.limb2.toNat row.remainderAbs.limb2.toNat n2
            (by omega)]
        cases hn : n2 with
        | false => rw [z2 hn]; decide
        | true =>
            simp only [Bool.toNat_true]
            rw [M31.sub_self, M31.mul_zero, M31.zero_mul]
  -- 49 sign_xor * ((r_abs_2 - 256) * r_inv_2 - 1)
  · rw [absLimbInverse_spec, M31.sub_self, M31.mul_zero]
  -- 50 (1 - sign_xor) * (r_abs_3 - r_3)
  · exact absSameVanishes row.signXor _ _
      (fun h => by rw [holds.absSameLimb3 h])
  -- 51 sign_xor * (carry_3 - carry_2) * (carry_3 - 1)
  · cases hsx : row.signXor with
    | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
    | true =>
        obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
          holds.negationRecurrence hsx
        rw [carryImage 0 row.remainder.limb0.toNat row.remainderAbs.limb0.toNat n0
            (by omega),
          carryImage n0.toNat row.remainder.limb1.toNat row.remainderAbs.limb1.toNat n1
            (by omega),
          carryImage n1.toNat row.remainder.limb2.toNat row.remainderAbs.limb2.toNat n2
            (by omega),
          carryImage n2.toNat row.remainder.limb3.toNat row.remainderAbs.limb3.toNat n3
            (by omega)]
        rcases m3 with step | step <;> rw [step] <;>
          cases n2 <;> decide
  -- 52 sign_xor * (1 - carry_3) * r_abs_3
  · cases hsx : row.signXor with
    | false => simp only [flagValue, M31.reduce_zero, M31.zero_mul]
    | true =>
        obtain ⟨n0, n1, n2, n3, e0, e1, e2, e3, z0, z1, z2, z3, m1, m2, m3⟩ :=
          holds.negationRecurrence hsx
        rw [carryImage 0 row.remainder.limb0.toNat row.remainderAbs.limb0.toNat n0
            (by omega),
          carryImage n0.toNat row.remainder.limb1.toNat row.remainderAbs.limb1.toNat n1
            (by omega),
          carryImage n1.toNat row.remainder.limb2.toNat row.remainderAbs.limb2.toNat n2
            (by omega),
          carryImage n2.toNat row.remainder.limb3.toNat row.remainderAbs.limb3.toNat n3
            (by omega)]
        cases hn : n3 with
        | false => rw [z3 hn]; decide
        | true =>
            simp only [Bool.toNat_true]
            rw [M31.sub_self, M31.mul_zero, M31.zero_mul]
  -- 53 sign_xor * ((r_abs_3 - 256) * r_inv_3 - 1)
  · rw [absLimbInverse_spec, M31.sub_self, M31.mul_zero]
  -- 54 scan prefix guard on limb 3
  · have total := holds.scanTotal
    simp only [flagValue_eq_toNat, M31.reduce_add]
    refine guardRootVanishes _ _ (by omega) ?_
    intro allClear
    have h1 : row.zeroDivisor = false := bool_of_toNat_zero (by omega)
    have h2 : row.rZero = false := bool_of_toNat_zero (by omega)
    have h3 : row.ltMarker3 = false := bool_of_toNat_zero (by omega)
    have raw : divCompareDiff row row.rs2Next.limb3 row.remainderAbs.limb3 = 0 :=
      holds.scanEqual3 h1 h2 h3
    rw [compareDiff_zero raw, M31.sub_self, M31.mul_zero]
  -- 55 lt_markers_3 * (lt_diff - diffs_3)
  · exact scanMarkerVanishes row row.ltMarker3 row.rs2Next.limb3 row.remainderAbs.limb3
      (fun h => holds.scanMarker3 h)
  -- 56 scan prefix guard on limb 2
  · have total := holds.scanTotal
    simp only [flagValue_eq_toNat, M31.reduce_add]
    refine guardRootVanishes _ _ (by omega) ?_
    intro allClear
    have h1 : row.zeroDivisor = false := bool_of_toNat_zero (by omega)
    have h2 : row.rZero = false := bool_of_toNat_zero (by omega)
    have h3 : row.ltMarker3 = false := bool_of_toNat_zero (by omega)
    have h4 : row.ltMarker2 = false := bool_of_toNat_zero (by omega)
    have raw : divCompareDiff row row.rs2Next.limb2 row.remainderAbs.limb2 = 0 :=
      holds.scanEqual2 h1 h2 h3 h4
    rw [compareDiff_zero raw, M31.sub_self, M31.mul_zero]
  -- 57 lt_markers_2 * (lt_diff - diffs_2)
  · exact scanMarkerVanishes row row.ltMarker2 row.rs2Next.limb2 row.remainderAbs.limb2
      (fun h => holds.scanMarker2 h)
  -- 58 scan prefix guard on limb 1
  · have total := holds.scanTotal
    simp only [flagValue_eq_toNat, M31.reduce_add]
    refine guardRootVanishes _ _ (by omega) ?_
    intro allClear
    have h1 : row.zeroDivisor = false := bool_of_toNat_zero (by omega)
    have h2 : row.rZero = false := bool_of_toNat_zero (by omega)
    have h3 : row.ltMarker3 = false := bool_of_toNat_zero (by omega)
    have h4 : row.ltMarker2 = false := bool_of_toNat_zero (by omega)
    have h5 : row.ltMarker1 = false := bool_of_toNat_zero (by omega)
    have raw : divCompareDiff row row.rs2Next.limb1 row.remainderAbs.limb1 = 0 :=
      holds.scanEqual1 h1 h2 h3 h4 h5
    rw [compareDiff_zero raw, M31.sub_self, M31.mul_zero]
  -- 59 lt_markers_1 * (lt_diff - diffs_1)
  · exact scanMarkerVanishes row row.ltMarker1 row.rs2Next.limb1 row.remainderAbs.limb1
      (fun h => holds.scanMarker1 h)
  -- 60 scan prefix guard on limb 0
  · have total := holds.scanTotal
    simp only [flagValue_eq_toNat, M31.reduce_add]
    refine guardRootVanishes _ _ (by omega) ?_
    intro allClear
    have h1 : row.zeroDivisor = false := bool_of_toNat_zero (by omega)
    have h2 : row.rZero = false := bool_of_toNat_zero (by omega)
    have h3 : row.ltMarker3 = false := bool_of_toNat_zero (by omega)
    have h4 : row.ltMarker2 = false := bool_of_toNat_zero (by omega)
    have h5 : row.ltMarker1 = false := bool_of_toNat_zero (by omega)
    have h6 : row.ltMarker0 = false := bool_of_toNat_zero (by omega)
    have raw : divCompareDiff row row.rs2Next.limb0 row.remainderAbs.limb0 = 0 :=
      holds.scanEqual0 h1 h2 h3 h4 h5 h6
    rw [compareDiff_zero raw, M31.sub_self, M31.mul_zero]
  -- 61 lt_markers_0 * (lt_diff - diffs_0)
  · exact scanMarkerVanishes row row.ltMarker0 row.rs2Next.limb0 row.remainderAbs.limb0
      (fun h => holds.scanMarker0 h)
  -- 62 active * (1 - scan total)
  · rw [activeOne row holds]
    simp only [flagValue_eq_toNat, M31.reduce_add, holds.scanTotal]
    rw [M31.sub_self, M31.mul_zero]
  -- 63 booleanity of destination_nonzero
  · exact boolVanishesFlipped row.destinationNonzero
  -- 64 rd_addr * (1 - destination_nonzero)
  · exact destinationSelectorVanishes row holds
  -- 65 rd_addr * destination_inverse - destination_nonzero
  · have bound : row.rd.toNat < 32 := by simpa using row.rd.isLt
    rw [registerInverse, M31.reduce_mul, rdNonzeroImage row holds]
    exact M31.reduce_sub_eq_zero _ _ (registerInverseTable_spec row.rd.toNat bound)
  -- 66 rd_next_0 = destination_nonzero * result_0
  · rw [divisionSum row holds]
    refine destinationResultVanishes row.destinationNonzero row.isDivision _ _ _ ?_
    have limb := holds.destinationLimb0
    simp only [divResultBytes] at limb
    rw [limb]
    cases row.destinationNonzero <;> cases row.isDivision <;> rfl
  -- 67 rd_next_1 = destination_nonzero * result_1
  · rw [divisionSum row holds]
    refine destinationResultVanishes row.destinationNonzero row.isDivision _ _ _ ?_
    have limb := holds.destinationLimb1
    simp only [divResultBytes] at limb
    rw [limb]
    cases row.destinationNonzero <;> cases row.isDivision <;> rfl
  -- 68 rd_next_2 = destination_nonzero * result_2
  · rw [divisionSum row holds]
    refine destinationResultVanishes row.destinationNonzero row.isDivision _ _ _ ?_
    have limb := holds.destinationLimb2
    simp only [divResultBytes] at limb
    rw [limb]
    cases row.destinationNonzero <;> cases row.isDivision <;> rfl
  -- 69 rd_next_3 = destination_nonzero * result_3
  · rw [divisionSum row holds]
    refine destinationResultVanishes row.destinationNonzero row.isDivision _ _ _ ?_
    have limb := holds.destinationLimb3
    simp only [divResultBytes] at limb
    rw [limb]
    cases row.destinationNonzero <;> cases row.isDivision <;> rfl
  -- 70 active * (rs1_next_0 - rs1_previous_0)
  · rw [activeOne row holds]
    exact readOnlyVanishes _ _ holds.sourceOneLimb0
  -- 71 active * (rs1_next_1 - rs1_previous_1)
  · rw [activeOne row holds]
    exact readOnlyVanishes _ _ holds.sourceOneLimb1
  -- 72 active * (rs1_next_2 - rs1_previous_2)
  · rw [activeOne row holds]
    exact readOnlyVanishes _ _ holds.sourceOneLimb2
  -- 73 active * (rs1_next_3 - rs1_previous_3)
  · rw [activeOne row holds]
    exact readOnlyVanishes _ _ holds.sourceOneLimb3
  -- 74 active * (rs2_next_0 - rs2_previous_0)
  · rw [activeOne row holds]
    exact readOnlyVanishes _ _ holds.sourceTwoLimb0
  -- 75 active * (rs2_next_1 - rs2_previous_1)
  · rw [activeOne row holds]
    exact readOnlyVanishes _ _ holds.sourceTwoLimb1
  -- 76 active * (rs2_next_2 - rs2_previous_2)
  · rw [activeOne row holds]
    exact readOnlyVanishes _ _ holds.sourceTwoLimb2
  -- 77 active * (rs2_next_3 - rs2_previous_3)
  · rw [activeOne row holds]
    exact readOnlyVanishes _ _ holds.sourceTwoLimb3
  -- 78 active - 1
  · rw [activeOne row holds]; exact M31.sub_self 1
  -- 79 bus_value_67 = the opcode identifier
  · rcases div_selector_cases row holds with
      ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩ | ⟨a, b, c, d⟩
    · rw [div_opcode_id_div row holds a, a, b, c, d]; decide
    · rw [div_opcode_id_divu row holds b, a, b, c, d]; decide
    · rw [div_opcode_id_rem row holds c, a, b, c, d]; decide
    · rw [div_opcode_id_remu row holds d, a, b, c, d]; decide
  -- 80 bus_value_68 = pc + 4
  · rw [nextPcImage row holds fits, M31.reduce_add]
    exact M31.sub_self _
  -- 81 bus_value_69 = clock + 1
  · rw [M31.reduce_add]
    exact M31.sub_self _
  -- 82 bus_value_70 = (clock - 1) * 4 + 1
  · rw [M31.reduce_sub _ _ holds.clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _
  -- 83 bus_value_71 = (clock - 1) * 4 + 2
  · rw [M31.reduce_sub _ _ holds.clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _
  -- 84 bus_value_72 = (clock - 1) * 4 + 3
  · rw [M31.reduce_sub _ _ holds.clockPositive, M31.reduce_mul, M31.reduce_add]
    exact M31.sub_self _



/-! ## The product chain

The eight `range_check_8_11` requests are where the division actually lives: the
`div` AIR has no constraint root for `divisor * quotient + remainder = dividend`
at all, it pins the eight-limb convolution by asking the preprocessed table to
certify that each `(byte, carry)` pair is (8, 11)-bit. The AIR spells the carry
as `(accumulated - dividendLimb) * 8388608`, and `8388608` is the inverse of
`256` in `M31`, so the content of the eight lemmas below is that the transcribed
`Nat` carry chain of `DivHolds.productRecurrence` really is that field
expression. -/

private theorem productCarryImage (accumulated dividendLimb carry : Nat)
    (equation : accumulated = dividendLimb + 256 * carry) :
    (M31.reduce accumulated - M31.reduce dividendLimb) * M31.reduce 8388608 =
      M31.reduce carry := by
  rw [M31.reduce_sub _ _ (by omega),
    show accumulated - dividendLimb = 256 * carry from by omega, M31.reduce_mul]
  exact M31.reduce_shift _

private theorem quotientHighImage (row : DivRow) :
    M31.reduce (flagValue row.qSign) * M31.reduce 255 = M31.reduce (divQuotientHigh row) := by
  rw [M31.reduce_mul, flagValue_eq_toNat, divQuotientHigh,
    show row.qSign.toNat * 255 = 255 * row.qSign.toNat from Nat.mul_comm _ _]

private theorem divisorHighImage (row : DivRow) :
    M31.reduce (flagValue row.cSign) * M31.reduce 255 = M31.reduce (divDivisorHigh row) := by
  rw [M31.reduce_mul, flagValue_eq_toNat, divDivisorHigh,
    show row.cSign.toNat * 255 = 255 * row.cSign.toNat from Nat.mul_comm _ _]

private theorem dividendHighImage (row : DivRow) :
    M31.reduce (flagValue row.bSign) * M31.reduce 255 = M31.reduce (divDividendHigh row) := by
  rw [M31.reduce_mul, flagValue_eq_toNat, divDividendHigh,
    show row.bSign.toNat * 255 = 255 * row.bSign.toNat from Nat.mul_comm _ _]

private theorem remainderHighImage (row : DivRow) :
    M31.reduce (flagValue row.bSign) * (M31.reduce 1 - M31.reduce (flagValue row.rZero)) *
      M31.reduce 255 = M31.reduce (divRemainderHigh row) := by
  simp only [divRemainderHigh]
  cases hb : row.bSign <;> cases hr : row.rZero <;> decide

private theorem productCarry0 (row : DivRow) (k0 : Nat)
    (equation : divConv0 row = row.rs1Next.limb0.toNat + 256 * k0) :
    ((((M31.reduce row.rs2Next.limb0.toNat * M31.reduce row.quotient.limb0.toNat) + M31.reduce
      row.remainder.limb0.toNat) - M31.reduce row.rs1Next.limb0.toNat) * M31.reduce 8388608) =
      M31.reduce k0 := by
  simp only [M31.reduce_mul, M31.reduce_add]
  refine productCarryImage _ _ _ ?_
  simp only [divConv0] at equation ⊢
  omega

private theorem productCarry1 (row : DivRow) (k0 k1 : Nat)
    (equation : k0 + divConv1 row = row.rs1Next.limb1.toNat + 256 * k1) :
    (((((M31.reduce k0 + (M31.reduce row.rs2Next.limb0.toNat * M31.reduce
      row.quotient.limb1.toNat)) + (M31.reduce row.rs2Next.limb1.toNat * M31.reduce
      row.quotient.limb0.toNat)) + M31.reduce row.remainder.limb1.toNat) - M31.reduce
      row.rs1Next.limb1.toNat) * M31.reduce 8388608) =
      M31.reduce k1 := by
  simp only [M31.reduce_mul, M31.reduce_add]
  refine productCarryImage _ _ _ ?_
  simp only [divConv1] at equation ⊢
  omega

private theorem productCarry2 (row : DivRow) (k1 k2 : Nat)
    (equation : k1 + divConv2 row = row.rs1Next.limb2.toNat + 256 * k2) :
    ((((((M31.reduce k1 + (M31.reduce row.rs2Next.limb0.toNat * M31.reduce
      row.quotient.limb2.toNat)) + (M31.reduce row.rs2Next.limb1.toNat * M31.reduce
      row.quotient.limb1.toNat)) + (M31.reduce row.rs2Next.limb2.toNat * M31.reduce
      row.quotient.limb0.toNat)) + M31.reduce row.remainder.limb2.toNat) - M31.reduce
      row.rs1Next.limb2.toNat) * M31.reduce 8388608) =
      M31.reduce k2 := by
  simp only [M31.reduce_mul, M31.reduce_add]
  refine productCarryImage _ _ _ ?_
  simp only [divConv2] at equation ⊢
  omega

private theorem productCarry3 (row : DivRow) (k2 k3 : Nat)
    (equation : k2 + divConv3 row = row.rs1Next.limb3.toNat + 256 * k3) :
    (((((((M31.reduce k2 + (M31.reduce row.rs2Next.limb0.toNat * M31.reduce
      row.quotient.limb3.toNat)) + (M31.reduce row.rs2Next.limb1.toNat * M31.reduce
      row.quotient.limb2.toNat)) + (M31.reduce row.rs2Next.limb2.toNat * M31.reduce
      row.quotient.limb1.toNat)) + (M31.reduce row.rs2Next.limb3.toNat * M31.reduce
      row.quotient.limb0.toNat)) + M31.reduce row.remainder.limb3.toNat) - M31.reduce
      row.rs1Next.limb3.toNat) * M31.reduce 8388608) =
      M31.reduce k3 := by
  simp only [M31.reduce_mul, M31.reduce_add]
  refine productCarryImage _ _ _ ?_
  simp only [divConv3] at equation ⊢
  omega

private theorem productCarry4 (row : DivRow) (k3 k4 : Nat)
    (equation : k3 + divConv4 row = divDividendHigh row + 256 * k4) :
    ((((((((M31.reduce k3 + (M31.reduce row.rs2Next.limb0.toNat * (M31.reduce (flagValue
      row.qSign) * M31.reduce 255))) + (M31.reduce row.rs2Next.limb1.toNat * M31.reduce
      row.quotient.limb3.toNat)) + (M31.reduce row.rs2Next.limb2.toNat * M31.reduce
      row.quotient.limb2.toNat)) + (M31.reduce row.rs2Next.limb3.toNat * M31.reduce
      row.quotient.limb1.toNat)) + ((M31.reduce (flagValue row.cSign) * M31.reduce 255) *
      M31.reduce row.quotient.limb0.toNat)) + ((M31.reduce (flagValue row.bSign) * (M31.reduce 1
      - M31.reduce (flagValue row.rZero))) * M31.reduce 255)) - (M31.reduce (flagValue
      row.bSign) * M31.reduce 255)) * M31.reduce 8388608) =
      M31.reduce k4 := by
  rw [quotientHighImage, divisorHighImage, remainderHighImage, dividendHighImage]
  simp only [M31.reduce_mul, M31.reduce_add]
  refine productCarryImage _ _ _ ?_
  simp only [divConv4, divQuotientHigh, divDivisorHigh, divRemainderHigh,
    divDividendHigh] at equation ⊢
  omega

private theorem productCarry5 (row : DivRow) (k4 k5 : Nat)
    (equation : k4 + divConv5 row = divDividendHigh row + 256 * k5) :
    (((((((M31.reduce k4 + ((M31.reduce row.rs2Next.limb0.toNat + M31.reduce
      row.rs2Next.limb1.toNat) * (M31.reduce (flagValue row.qSign) * M31.reduce 255))) +
      (M31.reduce row.rs2Next.limb2.toNat * M31.reduce row.quotient.limb3.toNat)) + (M31.reduce
      row.rs2Next.limb3.toNat * M31.reduce row.quotient.limb2.toNat)) + ((M31.reduce (flagValue
      row.cSign) * M31.reduce 255) * (M31.reduce row.quotient.limb0.toNat + M31.reduce
      row.quotient.limb1.toNat))) + ((M31.reduce (flagValue row.bSign) * (M31.reduce 1 -
      M31.reduce (flagValue row.rZero))) * M31.reduce 255)) - (M31.reduce (flagValue row.bSign)
      * M31.reduce 255)) * M31.reduce 8388608) =
      M31.reduce k5 := by
  rw [quotientHighImage, divisorHighImage, remainderHighImage, dividendHighImage]
  simp only [M31.reduce_mul, M31.reduce_add]
  refine productCarryImage _ _ _ ?_
  simp only [divConv5, divQuotientHigh, divDivisorHigh, divRemainderHigh,
    divDividendHigh] at equation ⊢
  try simp only [Nat.add_mul, Nat.mul_add] at equation
  try simp only [Nat.add_mul, Nat.mul_add]
  omega

private theorem productCarry6 (row : DivRow) (k5 k6 : Nat)
    (equation : k5 + divConv6 row = divDividendHigh row + 256 * k6) :
    ((((((M31.reduce k5 + (((((M31.reduce row.rs2Next.limb0.toNat + M31.reduce
      row.rs2Next.limb1.toNat) + M31.reduce row.rs2Next.limb2.toNat) + M31.reduce
      row.rs2Next.limb3.toNat) - M31.reduce row.rs2Next.limb3.toNat) * (M31.reduce (flagValue
      row.qSign) * M31.reduce 255))) + (M31.reduce row.rs2Next.limb3.toNat * M31.reduce
      row.quotient.limb3.toNat)) + ((M31.reduce (flagValue row.cSign) * M31.reduce 255) *
      ((((M31.reduce row.quotient.limb0.toNat + M31.reduce row.quotient.limb1.toNat) +
      M31.reduce row.quotient.limb2.toNat) + M31.reduce row.quotient.limb3.toNat) - M31.reduce
      row.quotient.limb3.toNat))) + ((M31.reduce (flagValue row.bSign) * (M31.reduce 1 -
      M31.reduce (flagValue row.rZero))) * M31.reduce 255)) - (M31.reduce (flagValue row.bSign)
      * M31.reduce 255)) * M31.reduce 8388608) =
      M31.reduce k6 := by
  rw [quotientHighImage, divisorHighImage, remainderHighImage, dividendHighImage]
  simp only [M31.reduce_mul, M31.reduce_add]
  rw [M31.reduce_sub _ _ (by omega), M31.reduce_sub _ _ (by omega)]
  simp only [M31.reduce_mul, M31.reduce_add]
  refine productCarryImage _ _ _ ?_
  simp only [divConv6, divQuotientHigh, divDivisorHigh, divRemainderHigh,
    divDividendHigh] at equation ⊢
  simp only [Nat.add_sub_cancel]
  try simp only [Nat.add_mul, Nat.mul_add] at equation
  try simp only [Nat.add_mul, Nat.mul_add]
  omega

private theorem productCarry7 (row : DivRow) (k6 k7 : Nat)
    (equation : k6 + divConv7 row = divDividendHigh row + 256 * k7) :
    (((((M31.reduce k6 + ((((M31.reduce row.rs2Next.limb0.toNat + M31.reduce
      row.rs2Next.limb1.toNat) + M31.reduce row.rs2Next.limb2.toNat) + M31.reduce
      row.rs2Next.limb3.toNat) * (M31.reduce (flagValue row.qSign) * M31.reduce 255))) +
      ((M31.reduce (flagValue row.cSign) * M31.reduce 255) * (((M31.reduce
      row.quotient.limb0.toNat + M31.reduce row.quotient.limb1.toNat) + M31.reduce
      row.quotient.limb2.toNat) + M31.reduce row.quotient.limb3.toNat))) + ((M31.reduce
      (flagValue row.bSign) * (M31.reduce 1 - M31.reduce (flagValue row.rZero))) * M31.reduce
      255)) - (M31.reduce (flagValue row.bSign) * M31.reduce 255)) * M31.reduce 8388608) =
      M31.reduce k7 := by
  rw [quotientHighImage, divisorHighImage, remainderHighImage, dividendHighImage]
  simp only [M31.reduce_mul, M31.reduce_add]
  refine productCarryImage _ _ _ ?_
  simp only [divConv7, divQuotientHigh, divDivisorHigh, divRemainderHigh,
    divDividendHigh] at equation ⊢
  try simp only [Nat.add_mul, Nat.mul_add] at equation
  try simp only [Nat.add_mul, Nat.mul_add]
  omega



private theorem gapImage (row : DivRow) (holds : DivHolds row)
    (ordinal previous : Nat) (order : previous < accessClock row.clock ordinal) :
    (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 + M31.reduce ordinal -
          M31.reduce previous - M31.reduce 1 =
      M31.reduce (accessClock row.clock ordinal - previous - 1) := by
  have positive := holds.clockPositive
  rw [M31.reduce_sub _ _ positive, M31.reduce_mul, M31.reduce_add]
  rw [show (row.clock - 1) * 4 + ordinal = accessClock row.clock ordinal from rfl]
  rw [M31.reduce_sub _ _ (by omega), M31.reduce_sub _ _ (by omega)]

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 200000 in
theorem divFixedRequestsHoldProbe (row : DivRow) (holds : DivHolds row) :
    divProgramCompiled.fixedRequestsHold (divColumns row) = true := by
  obtain ⟨k0, k1, k2, k3, k4, k5, k6, k7, b0, b1, b2, b3, b4, b5, b6, b7,
    e0, e1, e2, e3, e4, e5, e6, e7⟩ := holds.productRecurrence
  have sourceOne := holds.sourceOneClock
  have sourceTwo := holds.sourceTwoClock
  have destination := holds.destinationClock
  simp only [DivCircuit.fixedRequestsHold, DivCircuit.fixedRequestHolds,
    DivCircuit.lookupTuple, DivCircuit.lookupNumerator, DivCircuit.values,
    DivCircuit.value, DivCircuit.nodeValuesRev, divProgramCompiled, divProgram,
    evalLoop, Node.evalLocal, nth, List.map_cons, List.map_nil, List.all_cons,
    List.all_nil, divColumns, rangeCheck20Contains, rangeCheck811Contains,
    rangeCheck88Contains, rangeCheckM31Contains]
  rw [productCarry0 row k0 e0, productCarry1 row k0 k1 e1, productCarry2 row k1 k2 e2,
    productCarry3 row k2 k3 e3, productCarry4 row k3 k4 e4, productCarry5 row k4 k5 e5,
    productCarry6 row k5 k6 e6, productCarry7 row k6 k7 e7,
    gapImage row holds 1 row.rs1PreviousClock sourceOne.1,
    gapImage row holds 2 row.rs2PreviousClock sourceTwo.1,
    gapImage row holds 3 row.rdPreviousClock destination.1]

/-! ## The encoding is the export, and the evaluator is A's

`DivProgram.lean` carries the verbatim export and its localisation. The three
facts below turn the link between them, and the link to Team A's evaluator, into
theorems rather than `#guard`s: `EvaluatorSpec.localValue_eq_evalNodes` supplies
the generic half and the two `decide`s supply the family-specific half. -/

set_option maxRecDepth 1000000 in
theorem divProgramCompiled_eq_localise : divProgramCompiled = divProgram.localise := by
  decide

set_option maxRecDepth 1000000 in
theorem divProgram_wellFormed : divProgram.wellFormed = true := by decide

theorem DivCircuit.nodesWellFormed_of_wellFormed (circuit : DivCircuit)
    (valid : circuit.wellFormed = true) :
    nodesWellFormed circuit.columns.length 0 circuit.nodes = true := by
  simp only [DivCircuit.wellFormed, Bool.and_eq_true] at valid
  exact valid.1.1.2

theorem DivCircuit.nodeCount_of_wellFormed (circuit : DivCircuit)
    (valid : circuit.wellFormed = true) :
    circuit.nodeCount = circuit.nodes.length := by
  simp only [DivCircuit.wellFormed, Bool.and_eq_true, decide_eq_true_eq] at valid
  exact valid.1.1.1.2

/-- The `div` bridge reads the localised table; that read is Team A's node-order
read of A's memo table on the verbatim table, at every node index. -/
theorem DivCircuit.localise_value_eq_evalNodes (circuit : DivCircuit) (columns : List M31)
    (index : Nat) (valid : circuit.wellFormed = true)
    (covered : index < circuit.nodes.length) :
    (circuit.localise).value columns index =
      nth (evalNodes columns circuit.nodes) index := by
  have nodes := DivCircuit.nodesWellFormed_of_wellFormed circuit valid
  have count := DivCircuit.nodeCount_of_wellFormed circuit valid
  simp only [DivCircuit.value, DivCircuit.nodeValuesRev, DivCircuit.localise, count]
  exact localValue_eq_evalNodes columns circuit.columns.length circuit.nodes index
    nodes covered

theorem divProgramCompiled_value_eq_evalNodes (columns : List M31) (index : Nat)
    (covered : index < divProgram.nodes.length) :
    divProgramCompiled.value columns index =
      nth (evalNodes columns divProgram.nodes) index := by
  rw [divProgramCompiled_eq_localise]
  exact DivCircuit.localise_value_eq_evalNodes divProgram columns index
    divProgram_wellFormed covered

-- The encoded table and the hand transcription are pinned to the same export
-- bytes mechanically, not by comment.
#guard divProgramIrDigest == Air.Family.divIrDigest
#guard divProgram.columns.length == Air.Family.divIrColumns
#guard divProgram.constraints.length == Air.Family.divIrConstraints

/-! ## Non-vacuity, and a check on the column assignment itself

`divColumns` is hand-written, so it is exactly the kind of transcription this
work exists to remove. It is checked here against `divWitnessColumns`, which the
generator computed independently from `div.json` (and which the generated file
already checks satisfies every constraint, every table request and every lookup
tuple). If a column were mis-ordered or mis-populated -- including any of the
eleven synthesised ones -- this `#guard` fails. -/

/-- `7 / 2 = 3` remainder `1`, as a `DIVU` row. -/
def divWitnessRow : DivRow where
  pc := 100#32
  clock := 5
  rd := 7#5
  rdPreviousClock := 3
  rdPrevious := { limb0 := 0#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rdNext := { limb0 := 3#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs1 := 1#5
  rs1PreviousClock := 3
  rs1Previous := { limb0 := 7#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs1Next := { limb0 := 7#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs2 := 2#5
  rs2PreviousClock := 3
  rs2Previous := { limb0 := 2#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  rs2Next := { limb0 := 2#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  zeroDivisor := false
  rZero := false
  quotient := { limb0 := 3#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  remainder := { limb0 := 1#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  bSign := false
  cSign := false
  qSign := false
  signXor := false
  remainderAbs := { limb0 := 1#8, limb1 := 0#8, limb2 := 0#8, limb3 := 0#8 }
  ltMarker0 := true
  ltMarker1 := false
  ltMarker2 := false
  ltMarker3 := false
  ltDiff := 1
  isDiv := false
  isDivu := true
  isRem := false
  isRemu := false
  destinationNonzero := true
  claimedNextPc := 104#32

set_option maxRecDepth 40000 in
#guard divColumns divWitnessRow == divWitnessColumns

theorem divWitnessHolds : DivHolds divWitnessRow := by
  constructor <;> first
    | decide
    | exact ⟨0, 0, 0, 0, 0, 0, 0, 0, by decide⟩
    | exact ⟨by decide, by decide⟩
    | (intro absurdity; exact absurd absurdity (by decide))

theorem divWitnessFits : DivRowFits divWitnessRow := by
  constructor
  decide

-- The bridge is therefore not vacuous: this row satisfies every hypothesis.
set_option maxRecDepth 100000 in
theorem divWitnessConstraintValues :
    divProgramCompiled.constraintValues (divColumns divWitnessRow) =
      List.replicate 85 0 :=
  divConstraintValues divWitnessRow divWitnessHolds divWitnessFits

end RiscvRefinement.Air.Bridge
