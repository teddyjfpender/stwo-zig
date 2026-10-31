//! Concrete full64 CPU shell. No selector-profile runtime switch.
const Old = @import("../word16_cpu/layout.zig");
pub const fixed = Old.fixed;
pub const main = struct {
    pub const pc = 0;
    pub const next_pc = 4;
    pub const operation = 8;
    pub const registers = 9;
    pub const zero = 12;
    pub const active = 15;
    pub const enabled = 16;
    pub const a = 19;
    pub const b = 23;
    pub const c = 27;
    pub const previous_rd = 31;
    pub const previous_clock = 35;
    pub const gap16 = 38;
    pub const gap8 = 41;
    pub const immediate = 44;
    pub const use_immediate = 48;
    pub const branch = 49;
    pub const use_pc = 50;
    pub const dynamic_next = 51;
    pub const function = 52;
    pub const COUNT = 53;
};
pub const rom = struct {
    pub const valid = 0;
    pub const pc = 1;
    pub const next_pc = 5;
    pub const operation = 9;
    pub const registers = 10;
    pub const zero = 13;
    pub const immediate = 16;
    pub const flags = 20;
    pub const link = 25;
    pub const taken = 29;
    pub const COUNT = 30;
    pub const FIRST = COUNT;
    pub const LAST = COUNT + 1;
    pub const FIXED = COUNT + 2;
};
pub const inter = struct {
    pub const registers = 0; // three strict products of affine before/after.
    pub const function = 12; // one quadratic FUNCTION denominator.
    pub const rom = 16; // one quadratic ROM denominator.
    pub const affine = 20; // OWNER + U16x3 + U8x3: three pairs, one single.
    pub const sum = 36;
    pub const COUNT = 40;
};
pub const MIN_LOG = 5;
pub const MAX_LOG = 22;
pub const physical = Old.physical;
pub fn previousMain(c: usize) bool {
    return (c >= main.next_pc and c < main.next_pc + 4) or c == main.active;
}
pub fn previousInter(c: usize) bool {
    return c >= inter.sum and c < inter.COUNT;
}
