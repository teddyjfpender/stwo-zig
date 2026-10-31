//! All native widths remain those of the checked LS/RAM authorities.
const V1 = @import("../load_store_v1/layout.zig");
const R = @import("../closed_ram/layout.zig");
pub const Kind = enum { ls, initial, terminal, range16, range8, selection };
pub const MAIN = V1.MAIN;
pub const INTERACTION = V1.INTERACTION;
pub const U16 = V1.U16;
pub const U8 = V1.U8;
pub fn widths(kind: Kind) [3]usize {
    return switch (kind) {
        .ls => V1.widths(.ls),
        .selection => V1.widths(.selection),
        .initial, .terminal => .{ 3, R.BOUND_MAIN, R.BOUND_INTER },
        .range16 => R.widths(.range16),
        .range8 => R.widths(.range8),
    };
}
pub fn constraints(kind: Kind) usize {
    return switch (kind) {
        .ls => 281,
        .initial, .terminal => 54,
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
        .ls => V1.previousInterFor(.ls, c),
        .initial, .terminal => R.previousInter(.initial, c),
        else => c >= 4,
    };
}
