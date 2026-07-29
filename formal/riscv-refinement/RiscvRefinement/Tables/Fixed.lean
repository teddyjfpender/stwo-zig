import RiscvRefinement.Field.M31

namespace RiscvRefinement.Air

open RiscvRefinement

/-- The six preprocessed tables whose meanings are used by opcode proofs. -/
inductive FixedTableId where
  | bitwise
  | rangeCheck20
  | rangeCheck811
  | rangeCheck884
  | rangeCheck88
  | rangeCheckM31
deriving DecidableEq, Repr

namespace FixedTableId

def all : Array FixedTableId :=
  #[.bitwise, .rangeCheck20, .rangeCheck811, .rangeCheck884, .rangeCheck88,
    .rangeCheckM31]

def wireName : FixedTableId → String
  | .bitwise => "bitwise"
  | .rangeCheck20 => "range_check_20"
  | .rangeCheck811 => "range_check_8_11"
  | .rangeCheck884 => "range_check_8_8_4"
  | .rangeCheck88 => "range_check_8_8"
  | .rangeCheckM31 => "range_check_m31"

def arity : FixedTableId → Nat
  | .bitwise => 4
  | .rangeCheck20 => 1
  | .rangeCheck811 => 2
  | .rangeCheck884 => 3
  | .rangeCheck88 => 2
  | .rangeCheckM31 => 2

def logSize : FixedTableId → Nat
  | .bitwise => 18
  | .rangeCheck20 => 20
  | .rangeCheck811 => 19
  | .rangeCheck884 => 20
  | .rangeCheck88 => 16
  | .rangeCheckM31 => 15

def ofWireName? : String → Option FixedTableId
  | "bitwise" => some .bitwise
  | "range_check_20" => some .rangeCheck20
  | "range_check_8_11" => some .rangeCheck811
  | "range_check_8_8_4" => some .rangeCheck884
  | "range_check_8_8" => some .rangeCheck88
  | "range_check_m31" => some .rangeCheckM31
  | _ => none

/--
The byte-wise operation selected by the production `bitwise` fixed table.

This is public because opcode refinement proofs must connect fixed-table
membership to the corresponding architectural bitwise operation.
-/
def bitwiseResult (lhs rhs operation : Nat) : Option Nat :=
  match operation with
  | 0 => some (Nat.land lhs rhs)
  | 1 => some (Nat.lor lhs rhs)
  | 2 => some (Nat.xor lhs rhs)
  | 3 => some 0
  | _ => none

/--
Executable membership in the exact unpermuted meaning of each production
fixed table.

The `range_check_m31` table is the production 15-bit limb table.  Its final
physical row duplicates `(0, 0)`, while `(255, 127)` is absent, so membership
is exactly `lo < 2^8`, `hi < 2^7`, and `lo + 2^8 * hi < 2^15 - 1`.
-/
def contains : FixedTableId → List M31 → Bool
  | .bitwise, [lhs, rhs, result, operation] =>
      decide (lhs.toNat < 256) &&
      decide (rhs.toNat < 256) &&
      decide (operation.toNat < 4) &&
      decide (bitwiseResult lhs.toNat rhs.toNat operation.toNat = some result.toNat)
  | .rangeCheck20, [value] =>
      decide (value.toNat < 2 ^ 20)
  | .rangeCheck811, [low, high] =>
      decide (low.toNat < 2 ^ 8) && decide (high.toNat < 2 ^ 11)
  | .rangeCheck884, [low, middle, high] =>
      decide (low.toNat < 2 ^ 8) &&
      decide (middle.toNat < 2 ^ 8) &&
      decide (high.toNat < 2 ^ 4)
  | .rangeCheck88, [low, high] =>
      decide (low.toNat < 2 ^ 8) && decide (high.toNat < 2 ^ 8)
  | .rangeCheckM31, [low, high] =>
      decide (low.toNat < 2 ^ 8) &&
      decide (high.toNat < 2 ^ 7) &&
      decide (low.toNat + 2 ^ 8 * high.toNat < 2 ^ 15 - 1)
  | _, _ => false

/-- Propositional table membership used by refinement theorem statements. -/
def Meaning (table : FixedTableId) (tuple : List M31) : Prop :=
  table.contains tuple = true

theorem contains_eq_true_iff (table : FixedTableId) (tuple : List M31) :
    table.contains tuple = true ↔ table.Meaning tuple := by
  rfl

/-- Operation `0` in the production bitwise table is byte-wise AND. -/
theorem bitwise_contains_and_iff (lhs rhs result : M31) :
    FixedTableId.bitwise.contains [lhs, rhs, result, (0 : M31)] = true ↔
      lhs.toNat < 256 ∧
      rhs.toNat < 256 ∧
      Nat.land lhs.toNat rhs.toNat = result.toNat := by
  simp [contains, bitwiseResult, Bool.and_eq_true, decide_eq_true_eq, and_assoc]

/-- Operation `1` in the production bitwise table is byte-wise OR. -/
theorem bitwise_contains_or_iff (lhs rhs result : M31) :
    FixedTableId.bitwise.contains [lhs, rhs, result, (1 : M31)] = true ↔
      lhs.toNat < 256 ∧
      rhs.toNat < 256 ∧
      Nat.lor lhs.toNat rhs.toNat = result.toNat := by
  simp [contains, bitwiseResult, Bool.and_eq_true, decide_eq_true_eq, and_assoc]

/-- Operation `2` in the production bitwise table is byte-wise XOR. -/
theorem bitwise_contains_xor_iff (lhs rhs result : M31) :
    FixedTableId.bitwise.contains [lhs, rhs, result, M31.reduce 2] = true ↔
      lhs.toNat < 256 ∧
      rhs.toNat < 256 ∧
      Nat.xor lhs.toNat rhs.toNat = result.toNat := by
  have operation_eq : (M31.reduce 2).toNat = 2 :=
    M31.reduce_val_of_lt 2 (by decide)
  simp [contains, bitwiseResult, Bool.and_eq_true, decide_eq_true_eq,
    operation_eq, and_assoc]

end FixedTableId

end RiscvRefinement.Air
