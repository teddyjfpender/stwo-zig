//! Twenty-five narrow rows per dynamic service, independent of CPU geometry.
pub const COMPLETE_GROUP = 0;
pub const LANE = 1;
pub const CALL_INDEX = 2;
pub const FIRST = 3;
pub const GROUP_FIRST = 4;
pub const FIXED = 5;
pub const POINTER = 0;
pub const TICK = 8;
pub const TICK_BYTES = 9;
pub const ADDRESS = 12;
pub const CARRY = 20;
pub const ALIGNED = 27;
pub const BEFORE = 32;
pub const AFTER = 40;
pub const PREVIOUS = 48;
pub const PREVIOUS_BYTES = 49;
pub const GAP = 52;
pub const ACTIVE = 55;
pub const CALL_ID = 56;
pub const MAIN = 57;
pub const HEADER = 9;
pub const RANGE_COUNT = 40;
pub const EVENTS = RANGE_COUNT + 5;
pub const BATCHES = EVENTS / 3;
pub const INTERACTION = 4 * BATCHES;
pub const DIRECT = 88 + HEADER;
pub const CONSTRAINTS = DIRECT + BATCHES;
pub const PREVIOUS_MAIN = 9;
pub const RANGE_COLUMNS: [RANGE_COUNT]usize = blk: {
    var columns: [RANGE_COUNT]usize = undefined;
    var at: usize = 0;
    for (1..8) |i| {
        columns[at] = POINTER + i;
        at += 1;
    }
    for ([_]struct { start: usize, len: usize }{ .{ .start = TICK_BYTES, .len = 3 }, .{ .start = ADDRESS, .len = 8 }, .{ .start = BEFORE, .len = 8 }, .{ .start = AFTER, .len = 8 }, .{ .start = PREVIOUS_BYTES, .len = 3 }, .{ .start = GAP, .len = 3 } }) |span| for (0..span.len) |i| {
        columns[at] = span.start + i;
        at += 1;
    };
    break :blk columns;
};
