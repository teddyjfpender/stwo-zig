//! Twenty-five independently authenticated RAM14 updates per CPU ECALL.
const R = @import("../../../memory/closed_ram/layout.zig");
pub const FIXED = 6;
pub const POINTER = 28;
pub const CALL_ID = 32;
pub const BEFORE_BYTES = 33;
pub const AFTER_BYTES = 41;
pub const ADDRESS_CARRY = 49;
pub const ALIGN_BITS = 53;
pub const MAIN = 66;
pub const RAM = 0;
pub const OWNER = 8;
pub const IO = 16;
pub const RANGE16 = 24;
pub const U16 = R.T_U16 ++ [_]usize{ 28, 29, 30, 31 };
pub const U8 = R.T_U8 ++ [_]usize{ 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48 };
pub const RANGE8 = RANGE16 + R.pairColumns(U16.len);
pub const INTERACTION = RANGE8 + R.pairColumns(U8.len);
pub const CONSTRAINTS = 167;
pub const Kind = enum { bridge };
pub fn widths(_: Kind) [3]usize {
    return .{ FIXED, MAIN, INTERACTION };
}
pub fn constraints(_: Kind) usize {
    return CONSTRAINTS;
}
pub fn previousMainFor(_: Kind, c: usize) bool {
    return c == 0 or c == 9 or c == 12 or c == 13 or (c >= POINTER and c <= CALL_ID);
}
pub fn previousInterFor(_: Kind, c: usize) bool {
    return (c >= 4 and c < 8) or (c >= 12 and c < 16) or (c >= 20 and c < 24) or (c >= RANGE8 - 4 and c < RANGE8) or c >= INTERACTION - 4;
}
