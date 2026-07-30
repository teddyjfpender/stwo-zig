def execute_ITYPE (imm : (BitVec 12)) (rs1 : regidx) (rd : regidx) (op : iop) : SailM Retired := do
  let immext : (BitVec 32) := (sign_extend (m := 32) imm)
  let result : (BitVec 32) ← do
    match op with
    | .ADDI => (pure ((← (rX_bits rs1)) + immext))
    | .SLTI => (pure (zero_extend (m := 32) (bool_to_bits (BitVec.slt (← (rX_bits rs1)) immext))))
    | .SLTIU => (pure (zero_extend (m := 32) (bool_to_bits (BitVec.ult (← (rX_bits rs1)) immext))))
    | .ANDI => (pure ((← (rX_bits rs1)) &&& immext))
    | .ORI => (pure ((← (rX_bits rs1)) ||| immext))
    | .XORI => (pure ((← (rX_bits rs1)) ^^^ immext))
  (wX_bits rd result)
  (pure RETIRE_SUCCESS)
