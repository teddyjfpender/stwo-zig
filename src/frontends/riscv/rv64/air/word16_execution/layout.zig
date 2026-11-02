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
/// Opt-in byte-pair encoding (Geometry.cpu_u8_pairs, on top of the fused
/// tail). Every committed slot is a FRACTION witness of degree one: REG x3,
/// FUNCTION, ROM, OWNER+U16, U16+U16. The two U8 pair lookups have no column:
/// they are enforced through the running-sum residual.
pub const pairs = struct {
    pub const registers = 0;
    pub const function = 12;
    pub const rom = 16;
    pub const affine = 20; // OWNER+U16, U16+U16; both byte pairs are fused.
    pub const WITNESSES = 7;
    pub const sum = 28;
    pub const COUNT = 32;
};
pub fn interCount(is_fused: bool) usize {
    return if (is_fused) fused.COUNT else inter.COUNT;
}
pub fn interCountFor(is_fused: bool, is_pairs: bool) usize {
    return if (is_pairs) pairs.COUNT else interCount(is_fused);
}
pub const MIN_LOG = 5;
/// Structural cap. Logs above CLOCK24_MAX_LOG select the wide-clock encoding.
pub const MAX_LOG = 23;
/// Largest CPU log whose register clock `4*row+slot+1` and OWNER/RAM tick
/// `4*row+4` stay below 2^24 (gap16 + 65536*gap8 with gap8 a U8).
pub const CLOCK24_MAX_LOG = 22;
/// Wide-clock CPU encoding (log 23 only; fused tail, no byte pairs):
/// - REG gaps reach 2^25, so each gap8 limb (< 2^9) is range-checked by the
///   U16 query `WIDE_GAP_SCALE*gap8` instead of the U8 query `gap8`;
/// - the OWNER/RAM tick is `row+1` (stride 1) instead of `4*row+4`, so every
///   RAM-side tick stays a 24-bit value and no RAM/service AIR changes.
pub fn wideClock(log_size: u32) bool {
    return log_size > CLOCK24_MAX_LOG;
}
pub const WIDE_GAP_SCALE = 128;
/// OWNER/RAM tick of CPU row `index`: `stride*(index+1)`.
pub fn ramStride(log_size: u32) u32 {
    return if (wideClock(log_size)) 1 else 4;
}
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
pub fn previousInterMode(is_fused: bool, is_pairs: bool, c: usize) bool {
    return if (is_pairs) c >= pairs.sum and c < pairs.COUNT else previousInterFor(is_fused, c);
}
