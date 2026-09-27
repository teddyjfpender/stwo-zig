//! Stable integer sorting in exactly Event.lessThan order. Values do not enter
//! the ordering key; callers still reject repeated (space,address,clock).
const std = @import("std");
const Event = @import("memory_event.zig").Event;

pub fn sort(events: []Event, scratch: []Event) !void {
    if (scratch.len < events.len) return error.MemorySortScratchTooSmall;
    if (events.len <= 1) return;
    var input = events;
    var output = scratch[0..events.len];
    // Least-significant first: clock u64, address u32, then the space bit.
    for (0..13) |part| {
        var counts: [256]usize = @splat(0);
        for (input) |event| counts[digit(event, part)] += 1;
        var offset: usize = 0;
        for (&counts) |*count| {
            const size = count.*;
            count.* = offset;
            offset += size;
        }
        for (input) |event| {
            const bucket = digit(event, part);
            output[counts[bucket]] = event;
            counts[bucket] += 1;
        }
        std.mem.swap([]Event, &input, &output);
    }
    // Thirteen passes leave the result in scratch; publish to the caller's
    // original allocation, preserving its ownership and immutable disk API.
    @memcpy(events, input);
}
fn digit(event: Event, part: usize) u8 {
    if (part < 8) return @truncate(event.clock >> @intCast(part * 8));
    if (part < 12) return @truncate(event.address >> @intCast((part - 8) * 8));
    return event.space;
}

test "memory radix sort preserves exact unsigned space address and u64 clock order" {
    const a = std.testing.allocator;
    const count = 8193;
    const events = try a.alloc(Event, count);
    defer a.free(events);
    const scratch = try a.alloc(Event, count);
    defer a.free(scratch);
    var random = std.Random.DefaultPrng.init(0x72616d);
    for (events, 0..) |*event, index| event.* = .{ .space = @intCast(index & 1), .address = random.random().int(u32) & ~@as(u32, 3), .clock = random.random().int(u64), .value = @intCast(index) };
    events[0] = .{ .space = 0, .address = 0, .clock = std.math.maxInt(u64), .value = 1 };
    events[1] = .{ .space = 0, .address = 31, .clock = 0, .value = 2 };
    events[2] = .{ .space = 1, .address = std.math.maxInt(u32), .clock = std.math.maxInt(u64), .value = 3 };
    const expected = try a.dupe(Event, events);
    defer a.free(expected);
    std.sort.pdq(Event, expected, {}, Event.lessThan);
    try sort(events, scratch);
    try std.testing.expectEqualSlices(Event, expected, events);
    try std.testing.expectError(error.MemorySortScratchTooSmall, sort(events, scratch[0 .. count - 1]));
    var repeated = [_]Event{ .{ .space = 1, .address = 4, .clock = 5, .value = 17 }, .{ .space = 1, .address = 4, .clock = 5, .value = 19 } };
    var repeated_scratch: [2]Event = undefined;
    try sort(&repeated, &repeated_scratch);
    try std.testing.expectEqual(@as(u32, 17), repeated[0].value);
    try std.testing.expectEqual(@as(u32, 19), repeated[1].value);
}
