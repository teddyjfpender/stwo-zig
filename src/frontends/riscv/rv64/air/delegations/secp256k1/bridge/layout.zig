//! One32-byte coordinate per row; four RAM lanes share existing arithmetic-byte authority.
pub const COMPLETE_GROUP = 0;
pub const COORD = 1;
pub const CALL_INDEX = 2;
pub const FIRST = 3;
pub const GROUP_FIRST = 4;
pub const IS_OUTPUT = 5;
pub const OUTPUT_WIRE = 6;
pub const FIXED = 7;
pub const POINTER = 0;
pub const TICK = 8;
pub const TICK_BYTES = 9;
pub const ADDRESS = 12;
pub const CARRY = 20;
pub const ALIGNED = 27;
pub const BEFORE = 30;
pub const AFTER = 62;
pub const PREVIOUS = 94;
pub const PREVIOUS_BYTES = 98;
pub const GAP = 110;
pub const WRITABLE = 122;
pub const ACTIVE = 126;
pub const CALL_ID = 127;
pub const MAIN = 128;
pub const PREVIOUS_MAIN = 9;
pub const RANGE_COUNT = 42;
pub const EVENTS = RANGE_COUNT + 11;
pub const BATCHES = (EVENTS + 2) / 3;
pub const INTERACTION = 4 * BATCHES;
pub const DIRECT = 212;
pub const CONSTRAINTS = DIRECT + BATCHES;
pub const RANGE_COLUMNS: [RANGE_COUNT]usize = blk: {
    var columns: [RANGE_COUNT]usize = undefined;
    var at: usize = 0;
    for (1..8) |i| {
        columns[at] = POINTER + i;
        at += 1;
    }
    for ([_]struct { start: usize, len: usize }{ .{ .start = TICK_BYTES, .len = 3 }, .{ .start = ADDRESS, .len = 8 }, .{ .start = PREVIOUS_BYTES, .len = 12 }, .{ .start = GAP, .len = 12 } }) |span| for (0..span.len) |i| {
        columns[at] = span.start + i;
        at += 1;
    };
    break :blk columns;
};
