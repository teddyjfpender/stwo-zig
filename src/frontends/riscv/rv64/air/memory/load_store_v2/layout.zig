//! Shared checked LS arithmetic, separate RAM and merged local lookup debt.
const V1 = @import("../load_store_v1/layout.zig");
const R = @import("../closed_ram/layout.zig");
pub const Kind = enum { ls, initial, terminal, range16, range8, selection };
pub const MAIN = V1.MAIN;
pub const LOCAL_INVERSES = 8;
pub const LOCAL_PREFIX = 92;
pub const INTERACTION = 96;
pub const BOUND_INTERACTION = 20;
pub const BOUND_U16 = [_]usize{ 14, 15, 16, 17 };
pub const U16 = V1.U16;
pub const U8 = V1.U8;
pub fn widths(kind: Kind) [3]usize {
    return switch (kind) {
        .ls => .{ 3, MAIN, INTERACTION },
        .selection => V1.widths(.selection),
        .initial, .terminal => .{ 3, R.BOUND_MAIN, BOUND_INTERACTION },
        .range16 => R.widths(.range16),
        .range8 => R.widths(.range8),
    };
}
pub fn constraints(kind: Kind) usize {
    return switch (kind) {
        .ls => 273,
        .initial, .terminal => 47,
        .selection => 3,
        .range16, .range8 => 3,
    };
}
pub fn previousMainFor(kind: Kind, c: usize) bool {
    return switch (kind) {
        .ls => V1.previousMainFor(.ls, c),
        .initial, .terminal => c == 0 or (c >= 1 and c < 5),
        else => false,
    };
}
pub fn previousInterFor(kind: Kind, c: usize) bool {
    return switch (kind) {
        .ls => (c >= 4 and c < 8) or c >= LOCAL_PREFIX,
        .initial, .terminal => (c >= 4 and c < 8) or c >= 16,
        else => c >= 4,
    };
}
