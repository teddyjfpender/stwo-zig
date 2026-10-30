//! Concrete logical constraint layout; projection owns physical commitments.
//! No type factory or machine specialization.
pub const Word = enum(u8) {
    a,
    b,
    result,
    previous_rd,
    memory_before,
    memory_after,
    address,
    rhs,
    difference,
    product_low,
    product_high,
    high_sub_a,
    high_sub_b,
    abs_a,
    abs_b,
    quotient,
    remainder,
    remainder_gap,
    raw_result,
    out_abs,
    product_x,
    product_y,
};
pub const WORDS = 22;
pub const WORD_COLUMNS = 72; // 8 bytes + 64 Boolean bits
pub fn byte(word: Word, index: usize) usize {
    return @as(usize, @intFromEnum(word)) * WORD_COLUMNS + index;
}
pub fn bit(word: Word, index: usize) usize {
    return byte(word, 8 + index);
}
pub const Carry = enum(u8) { alu, compare, address, high_a, high_b, abs_a, abs_b, negate, div_sum_low, div_sum_high, remainder };
pub const CARRIES = 88;
pub const carry_start = WORDS * WORD_COLUMNS;
pub fn carry(kind: Carry, index: usize) usize {
    return carry_start + @as(usize, @intFromEnum(kind)) * 8 + index;
}
pub const product_carry_start = carry_start + CARRIES;
pub fn productCarry(index: usize) usize {
    return product_carry_start + index * 12;
}
pub const shift_start = product_carry_start + 16 * 12;
pub fn shift(stage: usize, index: usize) usize {
    return shift_start + stage * 64 + index;
}
pub const clock_start = shift_start + 384;
pub const CLOCK_BITS = 12;
pub fn previousClock(slot: usize) usize {
    return clock_start + slot * (2 + 2 * CLOCK_BITS);
}
pub fn gap(slot: usize) usize {
    return previousClock(slot) + 1 + CLOCK_BITS;
}
pub const offset_start = clock_start + 4 * (2 + 2 * CLOCK_BITS);
pub const readable = offset_start + 8;
pub const writable = readable + 1;
pub const divisor_zero = writable + 1;
pub const divisor_inverse = divisor_zero + 1;
pub const sign_a = divisor_inverse + 1;
pub const sign_b = sign_a + 1;
pub const negate = sign_b + 1;
pub const apply_negate = negate + 1;
pub const equal = apply_negate + 1;
pub const equal_inverse = equal + 1;
pub const taken = equal_inverse + 1;
pub const MAIN = taken + 1;

pub const fixed = struct {
    pub const active = 0;
    pub const first = 1;
    pub const last = 2;
    pub const opcode_start = 3;
    pub const OPCODES = 65;
    pub const rs1 = opcode_start + OPCODES;
    pub const rs2 = rs1 + 1;
    pub const rd = rs2 + 1;
    pub const slot_start = rd + 1;
    pub const tick_start = slot_start + 4;
    pub const immediate = tick_start + 4;
    pub const pc = immediate + 8;
    pub const next_pc = pc + 8;
    pub const increment = next_pc + 8;
    pub const target = increment + 8;
    pub const word_start = target + 8;
    pub const carry_start = word_start + WORDS;
    pub const COUNT = @This().carry_start + CARRIES;
};
pub const INTERACTION = 36; // eight inverse QM31s + one prefix QM31
pub const MAX_DEGREE: u8 = 4;
pub const EXPANSION: u32 = 2;

/// Derived public support, never witness-dependent configuration.
pub const Support = struct {
    words: [WORDS]bool = @splat(true),
    carries: [CARRIES]bool = @splat(true),
    slots: [4]bool = @splat(true),
    shifts: bool = true,
    product: bool = true,
};
