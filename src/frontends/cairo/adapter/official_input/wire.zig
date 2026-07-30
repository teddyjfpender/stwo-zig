//! Exact JSON wire shape of official `stwo_cairo_adapter::ProverInput`.

pub const CasmState = struct {
    pc: u32,
    ap: u32,
    fp: u32,
};

pub const CasmStatesByOpcode = struct {
    generic_opcode: []const CasmState,
    add_ap_opcode: []const CasmState,
    add_opcode: []const CasmState,
    add_opcode_small: []const CasmState,
    assert_eq_opcode: []const CasmState,
    assert_eq_opcode_double_deref: []const CasmState,
    assert_eq_opcode_imm: []const CasmState,
    call_opcode_abs: []const CasmState,
    call_opcode_rel_imm: []const CasmState,
    jnz_opcode_non_taken: []const CasmState,
    jnz_opcode_taken: []const CasmState,
    jump_opcode_rel_imm: []const CasmState,
    jump_opcode_rel: []const CasmState,
    jump_opcode_double_deref: []const CasmState,
    jump_opcode_abs: []const CasmState,
    mul_opcode_small: []const CasmState,
    mul_opcode: []const CasmState,
    ret_opcode: []const CasmState,
    blake_compress_opcode: []const CasmState,
    qm_31_add_mul_opcode: []const CasmState,
};

pub const StateTransitions = struct {
    initial_state: CasmState,
    final_state: CasmState,
    casm_states_by_opcode: CasmStatesByOpcode,
};

pub const MemoryConfig = struct {
    small_max: u128,
    log_small_value_capacity: u32,
};

pub const Memory = struct {
    config: MemoryConfig,
    address_to_id: []const u32,
    f252_values: []const [8]u32,
    small_values: []const u128,
};

pub const MemorySegmentAddresses = struct {
    begin_addr: usize,
    stop_ptr: usize,
};

pub const BuiltinSegments = struct {
    add_mod_builtin: ?MemorySegmentAddresses,
    bitwise_builtin: ?MemorySegmentAddresses,
    output: ?MemorySegmentAddresses,
    mul_mod_builtin: ?MemorySegmentAddresses,
    pedersen_builtin: ?MemorySegmentAddresses,
    poseidon_builtin: ?MemorySegmentAddresses,
    range_check96_builtin: ?MemorySegmentAddresses,
    range_check_builtin: ?MemorySegmentAddresses,
    ec_op_builtin: ?MemorySegmentAddresses,
};

pub const PublicSegmentContext = struct {
    present: [11]bool,
};

pub const ProverInput = struct {
    state_transitions: StateTransitions,
    memory: Memory,
    pc_count: usize,
    public_memory_addresses: []const u32,
    builtin_segments: BuiltinSegments,
    public_segment_context: PublicSegmentContext,
};
