//! Architecture-facing records, separate from CPU, allocation and future AIR.
const isa = @import("decode.zig");
const Word = @import("word.zig").Word;
pub const MemoryEffect = struct {
    address: Word,
    width: u4,
    value: Word,
    before_word: Word,
    after_word: Word,
    write: bool,
};
pub const Retirement = struct {
    clock: u64,
    pc: Word,
    next_pc: Word,
    immediate: Word,
    instruction: u32,
    opcode: isa.Opcode,
    rs1: u5,
    rs2: u5,
    lhs: Word,
    rhs: Word,
    rd: u5,
    previous_rd: Word,
    result: Word,
    writes_rd: bool,
    branch_taken: bool,
    memory: ?MemoryEffect,
};
