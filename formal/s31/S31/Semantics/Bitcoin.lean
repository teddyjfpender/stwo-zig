import S31.Semantics.Integers
import S31.Semantics.Constants

namespace S31.Bitcoin

def powLimit : Nat := 2^224 - 1

def target (compact : Nat) : Result Nat := do
  let exponent := compact / 2^24
  let mantissa := compact % 2^23
  let negative := compact / 2^23 % 2 == 1
  require (!negative && 1 ≤ exponent && exponent ≤ 32 && mantissa > 0) .invalidValue
  let result := if exponent ≤ 3 then mantissa / 2^(8 * (3 - exponent))
    else mantissa * 2^(8 * (exponent - 3))
  require (0 < result && result ≤ powLimit) .invalidValue
  return result

def headerTarget (limbs : List M31) : Result (List M31) := do
  let compact := Integers.unsigned ((limbs.drop 36).take 2)
  return Integers.encode 16 (← target compact)

def blockWork (limbs : List M31) : Result (List M31) := do
  let value := Integers.unsigned limbs
  require (0 < value && value < 2^256 - 1) .invalidValue
  return Integers.encode 16 (2^256 / (value + 1))

def genesis : List M31 := (List.range 16).map (fun i =>
  RiscvRefinement.M31.reduce (Words.readLE Constants.genesisBytes (2 * i) 2))

end S31.Bitcoin
