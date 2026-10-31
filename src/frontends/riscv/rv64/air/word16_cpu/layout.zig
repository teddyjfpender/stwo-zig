//! Concrete register-only AND/OR/XOR CPU v1. This layout is separate from all
//! existing RV64 proof profiles. Every u64 word/PC has FOUR canonical u16 limbs;
//! no three-u16/48-bit truncation or full-u64 equality in M31 is permitted.
const core = @import("stwo_core");
pub const fixed = struct {
    pub const index = 0;
    pub const first = 1;
    pub const last = 2;
    pub const COUNT = 3;
};
pub const main = struct {
    pub const pc = 0;
    pub const next_pc = pc + 4;
    pub const opcode = next_pc + 4;
    pub const registers = opcode + 1;
    pub const zero = registers + 3;
    pub const active = zero + 3;
    pub const enabled = active + 1;
    pub const a = enabled + 3;
    pub const b = a + 4;
    pub const c = b + 4;
    pub const previous_rd = c + 4;
    pub const previous_clock = previous_rd + 4;
    pub const gap16 = previous_clock + 3;
    pub const gap8 = gap16 + 3;
    pub const COUNT = gap8 + 3;
};
pub const inter = struct {
    pub const register_inverses = 0;
    pub const register_sum = register_inverses + 12;
    pub const function_inverse = register_sum + 4;
    pub const function_sum = function_inverse + 4;
    pub const rom_inverse = function_sum + 4;
    pub const rom_sum = rom_inverse + 4;
    pub const range16_inverses = rom_sum + 4;
    pub const range16_sum = range16_inverses + 8;
    pub const range8_inverses = range16_sum + 4;
    pub const range8_sum = range8_inverses + 8;
    pub const COUNT = range8_sum + 4;
};
pub const ROM = 16; // valid1 + PC4 + NEXT4 + opcode1 + regIDs3 + zeroFlags3.
pub const REGISTER = 6; // register ID, value4, clock. No RAM/Byte20 duplicate.
pub const CONSTRAINTS = 61;
pub const MIN_LOG = 5;
pub const MAX_LOG = 22;
pub fn physical(row: usize, log_size: u32) usize {
    return core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, log_size), log_size);
}
pub fn previousMain(column: usize) bool {
    return (column >= main.next_pc and column < main.next_pc + 4) or column == main.active;
}
pub fn previousInteraction(column: usize) bool {
    return (column >= inter.register_sum and column < inter.register_sum + 4) or
        (column >= inter.function_sum and column < inter.function_sum + 4) or
        (column >= inter.rom_sum and column < inter.rom_sum + 4) or
        (column >= inter.range16_sum and column < inter.range16_sum + 4) or
        (column >= inter.range8_sum and column < inter.range8_sum + 4);
}
