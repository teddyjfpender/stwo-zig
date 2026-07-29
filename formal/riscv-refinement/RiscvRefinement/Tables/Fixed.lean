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

private def bitwiseResult (lhs rhs operation : Nat) : Option Nat :=
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

end FixedTableId

end RiscvRefinement.Air
