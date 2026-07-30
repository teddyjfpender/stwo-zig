def execute_UTYPE (imm : (BitVec 20)) (rd : regidx) (op : uop) : SailM Retired := do
  let off : (BitVec 32) := (sign_extend (m := 32) (imm +++ 0x000#12))
  let ret : (BitVec 32) ← do
    match op with
    | .LUI => (pure off)
    | .AUIPC => (pure ((← (get_arch_pc ())) + off))
  (wX_bits rd ret)
  (pure RETIRE_SUCCESS)
