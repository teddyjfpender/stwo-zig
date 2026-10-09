import S31.Semantics.Types

namespace S31

/-- Exact metadata masks: irrelevant fields are rejected, even if their values
would be ignored by the evaluator. All dimensions remain source constants. -/
def Node.fields (n : Node) (lhs rhs selector index constant length rounds body : Bool) : Bool :=
  n.lhs.isSome == lhs && n.rhs.isSome == rhs && n.selector.isSome == selector &&
    n.index.isSome == index && n.constant.isSome == constant && n.length.isSome == length &&
    n.rounds.isSome == rounds && n.body.isSome == body

def Node.metadataValid (n : Node) : Bool :=
  match n.op with
  | .constant => n.fields false false false false true true false false
  | .bitcoin_genesis_hash_mainnet => n.fields false false false false false false false false
  | .array_get => n.fields true false false true false false false false
  | .array_slice => n.fields true false false true false true false false
  | .select | .bool_select => n.fields true true true false false false false false
  | .repeat => n.fields true false false false false false true true
  | .add_const | .mul_const | .int_view => n.fields true false false false true false false false
  | .int_add_checked | .int_add_wrapping | .int_sub_checked | .int_sub_wrapping | .int_le =>
    n.fields true true false false true false false false
  | .add | .mul | .array_concat | .u256_add | .u256_add_checked | .u256_le |
      .u256_sub | .u256_sub_checked | .u32_lt | .bool_and | .bool_or | .bool_xor |
      .hash_blake2s_pair | .hash_poseidon2_pair =>
    n.fields true true false false false false false false
  | .cast_m31 | .inv | .is_zero | .bool_not | .sum_lanes | .hash_blake2s |
      .hash_blake2s_leaf | .hash_poseidon2_leaf | .hash_sha256d_header |
      .bitcoin_target_mainnet | .bitcoin_prev_hash | .bitcoin_header_bits |
      .bitcoin_header_time | .bitcoin_block_work =>
    n.fields true false false false false false false false

def shapeOperand (shapes : Shapes) : Option String → Result (Option Shape)
  | none => .ok none
  | some name => (need (lookup shapes name) .unknownOperand).map some

def expectShape (shape : Option Shape) (kind : Kind) (length : Option Nat := none) : Result Shape := do
  let shape ← need shape .invalidShape
  require (shape.kind == kind && (length.isNone || length == some shape.length)) .invalidShape
  return shape

def inferNode (shapes : Shapes) (node : Node) : Result Shape := do
  require node.metadataValid
  let lhs ← shapeOperand shapes node.lhs
  let rhs ← shapeOperand shapes node.rhs
  let selector ← shapeOperand shapes node.selector
  match node.op with
  | .constant =>
    let length ← need node.length
    require (node.constant.getD modulus < modulus && 0 < length && length ≤ 4096)
    return ⟨.m31, length⟩
  | .array_get =>
    let a ← need lhs .invalidShape
    require (node.index.getD a.length < a.length) .invalidShape
    return ⟨a.kind, 1⟩
  | .array_slice =>
    let a ← need lhs .invalidShape
    let offset ← need node.index
    let length ← need node.length
    require (0 < length && offset + length ≤ a.length) .invalidShape
    return ⟨a.kind, length⟩
  | .array_concat =>
    let a ← need lhs .invalidShape
    let b ← need rhs .invalidShape
    require (a.kind == b.kind && a.length + b.length ≤ 4096) .invalidShape
    return ⟨a.kind, a.length + b.length⟩
  | .cast_m31 =>
    let a ← expectShape lhs .u16
    return ⟨.m31, a.length⟩
  | .add | .mul =>
    let a ← expectShape lhs .m31
    let _ ← expectShape rhs .m31 a.length
    return a
  | .inv => expectShape lhs .m31
  | .is_zero | .bool_not => expectShape lhs .m31 (some 1)
  | .bool_and | .bool_or | .bool_xor =>
    let a ← expectShape lhs .m31 (some 1)
    let _ ← expectShape rhs .m31 (some 1)
    return a
  | .bool_select =>
    let a ← expectShape lhs .m31 (some 1)
    let _ ← expectShape rhs .m31 (some 1)
    let _ ← expectShape selector .m31 (some 1)
    return a
  | .select =>
    let a ← need lhs .invalidShape
    require (rhs == some a) .invalidShape
    let _ ← expectShape selector .m31 (some 1)
    return a
  | .add_const | .mul_const =>
    require (node.constant.getD modulus < modulus)
    expectShape lhs .m31
  | .sum_lanes =>
    let _ ← expectShape lhs .m31
    return ⟨.m31, 1⟩
  | .repeat =>
    let a ← expectShape lhs .m31
    let rounds ← need node.rounds
    let body ← need node.body
    require (0 < rounds && rounds ≤ 32768 && 0 < body.length && body.length ≤ 16)
    require (body.all (fun step => match step with | .mix4 => a.length == 4 | _ => true))
    return a
  | .hash_blake2s | .hash_blake2s_leaf | .hash_poseidon2_leaf =>
    let a ← expectShape lhs .m31
    require (a.length ≤ 16 && a.length % 4 == 0) .invalidShape
    return ⟨.m31, 8⟩
  | .hash_blake2s_pair | .hash_poseidon2_pair =>
    let _ ← expectShape lhs .m31 (some 8)
    let _ ← expectShape rhs .m31 (some 8)
    return ⟨.m31, 8⟩
  | .u256_add | .u256_add_checked | .u256_sub | .u256_sub_checked | .u256_le =>
    let _ ← expectShape lhs .u16 (some 16)
    let _ ← expectShape rhs .u16 (some 16)
    return if node.op == .u256_le then ⟨.m31, 1⟩ else ⟨.u16, 16⟩
  | .u32_lt =>
    let _ ← expectShape lhs .u16 (some 2)
    let _ ← expectShape rhs .u16 (some 2)
    return ⟨.m31, 1⟩
  | .int_view | .int_add_checked | .int_add_wrapping | .int_sub_checked |
      .int_sub_wrapping | .int_le =>
    let spec ← need (node.constant.bind IntegerSpec.decode)
    let a ← expectShape lhs .u16 spec.limbs
    if node.op != .int_view then
      let _ ← expectShape rhs .u16 spec.limbs
      pure ()
    return if node.op == .int_le then ⟨.m31, 1⟩ else a
  | .bitcoin_block_work => expectShape lhs .u16 (some 16)
  | .hash_sha256d_header | .bitcoin_target_mainnet | .bitcoin_prev_hash |
      .bitcoin_header_bits | .bitcoin_header_time =>
    let _ ← expectShape lhs .u16 (some 40)
    return ⟨.u16, if node.op == .bitcoin_header_bits || node.op == .bitcoin_header_time then 2 else 16⟩
  | .bitcoin_genesis_hash_mainnet => return ⟨.u16, 16⟩

def addInput (shapes : Shapes) (input : Input) : Result Shapes := do
  require (validName input.name && (lookup shapes input.name).isNone)
  require (0 < input.shape.length && input.shape.length ≤ 4096) .invalidShape
  return shapes ++ [(input.name, input.shape)]

def addNode (shapes : Shapes) (node : Node) : Result Shapes := do
  require (validName node.name && (lookup shapes node.name).isNone)
  return shapes ++ [(node.name, ← inferNode shapes node)]

def Program.validate (p : Program) : Result Shapes := do
  require (p.version == 1 && validName p.name)
  let shapes ← p.inputs.foldlM addInput []
  let shapes ← p.nodes.foldlM addNode shapes
  for (lhs, rhs) in p.assertions do
    let a ← need (lookup shapes lhs) .unknownOperand
    let b ← need (lookup shapes rhs) .unknownOperand
    require (a == b) .invalidShape
  let publicInputs := p.inputs.filter (fun i => i.visibility == .public)
  let mut words := (publicInputs.map (·.shape.length)).sum
  for name in p.outputs do
    let shape ← need (lookup shapes name) .unknownOperand
    words := words + shape.length
  require (0 < words && words ≤ 8) .invalidShape
  return shapes

end S31
