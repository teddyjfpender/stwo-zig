//! Concrete full64 CPU shell. No selector-profile runtime switch.
const Old = @import("../word16_cpu/layout.zig");
pub const fixed = Old.fixed;
pub const main = struct {
    pub const pc = 0;
    pub const next_pc = 4;
    pub const operation = 8;
    pub const registers = 9;
    pub const active = 12;
    pub const enabled = 13;
    pub const a = 16;
    pub const b = 20;
    pub const c = 24;
    pub const previous_rd = 28;
    pub const gap16 = 32;
    pub const gap8 = 35;
    pub const immediate = 38;
    pub const use_immediate = 42;
    pub const branch = 43;
    pub const use_pc = 44;
    pub const dynamic_next = 45;
    pub const function = 46;
    pub const COUNT = 47;
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
/// Opt-in fused-tail encoding (Geometry.cpu_fused_tail). Slots 0..2 hold the
/// register FRACTIONS enabled*(a-b)/(a*b), slot 5 the OWNER+U16 pair fraction,
/// slots 3,4,6,7 the same strict inverses as `inter`. The last U8 single has
/// no column: it is enforced through the running-sum residual.
pub const fused = struct {
    pub const registers = 0;
    pub const function = 12;
    pub const rom = 16;
    pub const affine = 20; // OWNER+U16, U16+U16, U8+U8; the U8 single is fused.
    pub const WITNESSES = 8;
    pub const sum = 32;
    pub const COUNT = 36;
};
pub fn interCount(is_fused: bool) usize {
    return if (is_fused) fused.COUNT else inter.COUNT;
}
pub const MIN_LOG = 5;
pub const MAX_LOG = 22;
pub const physical = Old.physical;
pub fn previousMain(c: usize) bool {
    return (c >= main.next_pc and c < main.next_pc + 4) or c == main.active;
}
pub fn previousInter(c: usize) bool {
    return c >= inter.sum and c < inter.COUNT;
}
pub fn previousInterFor(is_fused: bool, c: usize) bool {
    return if (is_fused) c >= fused.sum and c < fused.COUNT else previousInter(c);
}
