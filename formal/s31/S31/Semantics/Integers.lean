import S31.Semantics.Words

namespace S31.Integers

def unsigned (limbs : List M31) : Nat := Words.decode 65536 (limbs.map (·.val))

def interpretation (spec : IntegerSpec) (n : Nat) : Int :=
  if spec.signed && n ≥ spec.limit / 2 then (n : Int) - spec.limit else n

def lower (spec : IntegerSpec) : Int := if spec.signed then -(spec.limit / 2 : Nat) else 0
def upper (spec : IntegerSpec) : Int :=
  if spec.signed then (spec.limit / 2 : Nat) - 1 else (spec.limit : Int) - 1

def encode (limbs : Nat) (value : Nat) : List M31 :=
  (Words.encode 65536 limbs value).map RiscvRefinement.M31.reduce

def evaluate (op : Op) (spec : IntegerSpec) (lhs rhs : List M31) : Result (List M31) := do
  let base := if spec.width == 8 then 256 else 65536
  require (lhs.all (fun x => x.val < base) && rhs.all (fun x => x.val < base)) .invalidValue
  if op == .int_view then return lhs
  let a := interpretation spec (unsigned lhs)
  let b := interpretation spec (unsigned rhs)
  if op == .int_le then return [RiscvRefinement.M31.reduce (if a ≤ b then 1 else 0)]
  let subtract := op == .int_sub_checked || op == .int_sub_wrapping
  let checked := op == .int_add_checked || op == .int_sub_checked
  let value := if subtract then a - b else a + b
  if checked then require (lower spec ≤ value && value ≤ upper spec) .overflow
  return encode spec.limbs (value % (spec.limit : Int)).toNat

def u256 (op : Op) (lhs rhs : List M31) : Result (List M31) := do
  let a := unsigned lhs
  let b := unsigned rhs
  if op == .u256_le then return [RiscvRefinement.M31.reduce (if a ≤ b then 1 else 0)]
  let subtract := op == .u256_sub || op == .u256_sub_checked
  if op == .u256_add_checked then require (a + b < 2^256) .overflow
  if op == .u256_sub_checked then require (b ≤ a) .overflow
  let value : Int := if subtract then (a : Int) - b else (a : Int) + b
  return encode 16 (value % (2^256 : Int)).toNat

end S31.Integers
