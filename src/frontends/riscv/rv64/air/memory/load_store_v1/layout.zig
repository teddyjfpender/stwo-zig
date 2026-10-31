//! Experimental full base+immediate LS ownership, not a production CPU profile.
const R = @import("../closed_ram/layout.zig");
pub const MAIN = 79;
pub const INTERACTION = 116;
pub const a = 28;
pub const immediate = 32;
pub const b = 36;
pub const c = 40;
pub const effective = 44;
pub const opcode = 48;
pub const flags = 49;
pub const offsets = 60;
pub const quotient = 68;
pub const selected_limb = 69;
pub const selected_byte = 70;
pub const selected_sign = 71;
pub const limb_sign = 72;
pub const b_low = 73;
pub const b_high = 74;
pub const address_carries = 75;
pub const RAM = 0;
pub const OWNER = 8;
pub const RANGE16 = 16;
pub const U16 = R.T_U16 ++ [_]usize{ 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 68 };
pub const RANGE8 = RANGE16 + R.pairColumns(U16.len);
pub const U8 = R.T_U8 ++ [_]usize{ b_low, b_high };
pub const SELECTION = RANGE8 + R.pairColumns(U8.len);
pub const TABLE_LOG = 16;
pub const OWNER_LOG = 6;
pub const OWNER_MAIN = 22;
pub fn previousMain(column: usize) bool {
    return column == 0;
}
pub fn previousInter(column: usize) bool {
    return (column >= 4 and column < 8) or (column >= 12 and column < 16) or
        (column >= RANGE8 - 4 and column < RANGE8) or
        (column >= SELECTION - 4 and column < SELECTION) or column >= INTERACTION - 4;
}
comptime {
    if (U16.len != 35 or U8.len != 5 or SELECTION + 8 != INTERACTION) @compileError("LS query/interaction ledger mismatch");
}

pub const Kind = enum { ls, owner, selection };
pub fn widths(kind: Kind) [3]usize {
    return switch (kind) {
        .ls => .{ 3, MAIN, INTERACTION },
        .owner => .{ 66, OWNER_MAIN, 8 },
        .selection => .{ 6, 2, 8 },
    };
}
pub fn constraints(kind: Kind) usize {
    return switch (kind) {
        .ls => 280,
        .owner => 26,
        .selection => 3,
    };
}

pub fn previousMainFor(kind: Kind, c_: usize) bool {
    return kind == .ls and previousMain(c_);
}
pub fn previousInterFor(kind: Kind, c_: usize) bool {
    return if (kind == .ls) previousInter(c_) else c_ >= 4;
}
