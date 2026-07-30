def execute_RTYPE (rs2 : regidx) (rs1 : regidx) (rd : regidx) (op : rop) : SailM ExecutionResult := do
  (wX_bits rd
    (← do
      match op with
      | .ADD => (pure ((← (rX_bits rs1)) + (← (rX_bits rs2))))
      | .SLT =>
        (pure (zero_extend (m := 32)
            (bool_to_bit (zopz0zI_s (← (rX_bits rs1)) (← (rX_bits rs2))))))
      | .SLTU =>
        (pure (zero_extend (m := 32)
            (bool_to_bit (zopz0zI_u (← (rX_bits rs1)) (← (rX_bits rs2))))))
      | .AND => (pure ((← (rX_bits rs1)) &&& (← (rX_bits rs2))))
      | .OR => (pure ((← (rX_bits rs1)) ||| (← (rX_bits rs2))))
      | .XOR => (pure ((← (rX_bits rs1)) ^^^ (← (rX_bits rs2))))
      | .SLL =>
        (pure (shift_bits_left (← (rX_bits rs1))
            (Sail.BitVec.extractLsb (← (rX_bits rs2)) (log2_xlen -i 1) 0)))
      | .SRL =>
        (pure (shift_bits_right (← (rX_bits rs1))
            (Sail.BitVec.extractLsb (← (rX_bits rs2)) (log2_xlen -i 1) 0)))
      | .SUB => (pure ((← (rX_bits rs1)) - (← (rX_bits rs2))))
      | .SRA =>
        (pure (shift_bits_right_arith (← (rX_bits rs1))
            (Sail.BitVec.extractLsb (← (rX_bits rs2)) (log2_xlen -i 1) 0)))))
  (pure RETIRE_SUCCESS)
