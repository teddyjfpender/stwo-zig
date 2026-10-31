//! One packet coordinate (four RAM words) per independently sized bridge row.
pub const FIXED = 8;
pub const ACTIVE = 0;
pub const WRITE = 1;
pub const POINTER = 2;
pub const ADDRESS = 6;
pub const TICK = 10;
pub const EPOCH = 11;
pub const LOW = 12;
pub const HIGH = 13;
pub const CALL_ID = 14;
pub const BEFORE = 15;
pub const AFTER = 47;
pub const PREV_EPOCH = 79;
pub const PREV_LOW = 83;
pub const PREV_HIGH = 87;
pub const GAP_EPOCH = 91;
pub const GAP_LOW = 95;
pub const GAP_HIGH = 99;
pub const SAME = 103;
pub const BORROW = 107;
pub const READABLE = 111;
pub const WRITABLE = 115;
pub const CARRY = 119;
pub const ALIGN = 123;
pub const MAIN = 134;
pub const RAM = 0;
pub const OWNER = 20;
pub const WIRE = 28;
pub const RANGE16 = 36;
pub const U16 = [_]usize{ 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 79, 80, 81, 82, 83, 84, 85, 86, 91, 92, 93, 94, 95, 96, 97, 98 };
pub const U8 = blk: {
    var out: [73]usize = undefined;
    out[0] = HIGH;
    var at: usize = 1;
    for ([_]usize{ PREV_HIGH, GAP_HIGH }) |start| for (0..4) |c| {
        out[at] = start + c;
        at += 1;
    };
    for (BEFORE..AFTER + 32) |c| {
        out[at] = c;
        at += 1;
    }
    break :blk out;
};
pub const RANGE8 = RANGE16 + 4 * ((U16.len + 1) / 2 + 1);
pub const INTERACTION = RANGE8 + 4 * ((U8.len + 1) / 2 + 1);
// Counted by the shared scalar/packed emitter; locked by dense residual gates.
pub const CONSTRAINTS = 439;
pub const Kind = enum { bridge };
pub fn widths(_: Kind) [3]usize {
    return .{ FIXED, MAIN, INTERACTION };
}
pub fn constraints(_: Kind) usize {
    return CONSTRAINTS;
}
pub fn previousMainFor(_: Kind, c: usize) bool {
    return c == ACTIVE or (c >= POINTER and c < ADDRESS) or (c >= TICK and c <= CALL_ID);
}
pub fn previousInterFor(_: Kind, c: usize) bool {
    return (c >= 16 and c < 20) or (c >= OWNER + 4 and c < OWNER + 8) or (c >= WIRE + 4 and c < WIRE + 8) or (c >= RANGE8 - 4 and c < RANGE8) or c >= INTERACTION - 4;
}
