import S31.Semantics.Validation
import S31.Semantics.Field
import S31.Semantics.Poseidon2
import S31.Semantics.Blake2s
import S31.Semantics.Sha256
import S31.Semantics.Bitcoin

namespace S31

def applyStep (words : List M31) : Step → List M31
  | .square => words.map (fun x => x * x)
  | .add_const c => words.map (· + c)
  | .mul_const c => words.map (· * c)
  | .mix4 =>
    let sum := words.foldl (· + ·) 0
    words.map (· + sum)

def applyBody (body : List Step) (words : List M31) : List M31 := body.foldl applyStep words

def repeatBody (body : List Step) : Nat → List M31 → List M31
  | 0, words => words
  | n + 1, words => repeatBody body n (applyBody body words)

def valueOperand (env : Env) (name : Option String) : Value :=
  (name.bind (lookup env)).getD ⟨.m31, []⟩

def bitValue (b : Bool) : M31 := RiscvRefinement.M31.reduce (if b then 1 else 0)

def evaluateNode (env : Env) (n : Node) : Result Value := do
  let shape ← inferNode (env.map (fun (name, value) => (name, value.shape))) n
  let a := valueOperand env n.lhs
  let b := valueOperand env n.rhs
  let s := (valueOperand env n.selector).words.getD 0 0
  let c := RiscvRefinement.M31.reduce (n.constant.getD 0)
  let words ← match n.op with
  | .constant => pure (List.replicate shape.length c)
  | .cast_m31 | .int_view =>
    if n.op == .int_view then
      Integers.evaluate n.op (← need (n.constant.bind IntegerSpec.decode)) a.words []
    else pure a.words
  | .add => pure ((a.words.zip b.words).map (fun (x, y) => x + y))
  | .mul => pure ((a.words.zip b.words).map (fun (x, y) => x * y))
  | .inv => do
    require (a.words.all (fun x => x.val != 0)) .divisionByZero
    pure (a.words.map Field.inverse)
  | .is_zero => pure [bitValue ((a.words.getD 0 0).val == 0)]
  | .add_const => pure (a.words.map (· + c))
  | .mul_const => pure (a.words.map (· * c))
  | .sum_lanes => pure [a.words.foldl (· + ·) 0]
  | .array_get => pure [a.words.getD (n.index.getD 0) 0]
  | .array_concat => pure (a.words ++ b.words)
  | .array_slice => pure ((a.words.drop (n.index.getD 0)).take (n.length.getD 0))
  | .repeat => pure (repeatBody (n.body.getD []) (n.rounds.getD 0) a.words)
  | .select => do
    require (s.val ≤ 1) .invalidValue
    pure (if s.val == 0 then a.words else b.words)
  | .bool_not | .bool_and | .bool_or | .bool_xor | .bool_select => do
    let x := a.words.getD 0 0
    let y := b.words.getD 0 0
    require (x.val ≤ 1 && y.val ≤ 1 && s.val ≤ 1) .invalidValue
    let x := x.val == 1
    let y := y.val == 1
    pure [bitValue (match n.op with
      | .bool_not => !x | .bool_and => x && y | .bool_or => x || y
      | .bool_xor => x != y | _ => if s.val == 0 then x else y)]
  | .hash_blake2s => pure (Blake2s.hash a.words)
  | .hash_blake2s_leaf => pure (Blake2s.hash a.words Blake2s.leafPersonalization)
  | .hash_blake2s_pair => pure (Blake2s.hash (a.words ++ b.words) Blake2s.pairPersonalization)
  | .hash_poseidon2_leaf => pure (Poseidon2.leaf a.words)
  | .hash_poseidon2_pair => pure (Poseidon2.pair a.words b.words)
  | .hash_sha256d_header => pure (Sha256.header a.words)
  | .u256_add | .u256_add_checked | .u256_sub | .u256_sub_checked | .u256_le =>
    Integers.u256 n.op a.words b.words
  | .u32_lt => pure [bitValue (Integers.unsigned a.words < Integers.unsigned b.words)]
  | .int_add_checked | .int_add_wrapping | .int_sub_checked | .int_sub_wrapping | .int_le =>
    Integers.evaluate n.op (← need (n.constant.bind IntegerSpec.decode)) a.words b.words
  | .bitcoin_target_mainnet => Bitcoin.headerTarget a.words
  | .bitcoin_block_work => Bitcoin.blockWork a.words
  | .bitcoin_genesis_hash_mainnet => pure Bitcoin.genesis
  | .bitcoin_prev_hash => pure ((a.words.drop 2).take 16)
  | .bitcoin_header_time => pure ((a.words.drop 34).take 2)
  | .bitcoin_header_bits => pure ((a.words.drop 36).take 2)
  let out : Value := ⟨shape.kind, words⟩
  require (out.shape == shape && out.valid) .invalidValue
  return out

end S31
