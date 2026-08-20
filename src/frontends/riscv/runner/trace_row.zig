//! One architecturally retired RISC-V instruction.
//!
//! This leaf module owns the row type so witness implementations can consume
//! execution rows without importing trace allocation, family dispatch, or any
//! witness module. `runner/trace.zig` re-exports the exact same nominal type.

const Opcode = @import("decode.zig").Opcode;

pub const TraceRow = struct {
    clk: u32,
    pc: u32,
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    rs2: u5,
    imm: i32,
    rs1_val: u32,
    rs2_val: u32,
    rs1_prev_clk: u32 = 0,
    rs2_prev_clk: u32 = 0,
    rd_prev_val: u32 = 0,
    rd_prev_clk: u32 = 0,
    rd_val: u32,
    mem_addr: u32,
    mem_val: u32,
    mem_prev_word: u32 = 0,
    mem_next_word: u32 = 0,
    mem_prev_clk: u32 = 0,
    is_load: bool,
    is_store: bool,
    branch_taken: bool,
    next_pc: u32,
    inst_word: u32 = 0,
};
