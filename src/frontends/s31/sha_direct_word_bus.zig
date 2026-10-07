//! Candidate word-bus roster for the table-free SHA256d AIR.
//!
//! This is an exact host-side multiset audit. It is not an AIR or a proof:
//! each producer/consumer event must be committed, constrained, key-bound,
//! and closed with one challenge-derived LogUp in the eventual joint proof.
const std = @import("std");
const core = @import("stwo_core");
const sha = @import("s31_sha_provider").compression;
const plan_mod = @import("sha_chip_plan.zig");
const caller = @import("sha_caller_stream_equations.zig");
const schedule = @import("sha_schedule_direct_equations.zig");
const feed = @import("sha_feed_direct_equations.zig");
const M31 = core.fields.m31.M31;

pub const relation_id: u32 = 0x5333_3103;
pub const schedule_base: u32 = 1024;
pub const terminal_base: u32 = 2048;
pub const boundary_word_count: usize = 32;
pub const events_per_call: usize = 32 + 80 + 80 + 24;

pub const Event = struct {
    call_id: u32,
    address: u32,
    lo: u16,
    hi: u16,
    weight: i8,

    pub fn key(self: Event) Key {
        return .{ .call_id = self.call_id, .address = self.address, .lo = self.lo, .hi = self.hi };
    }
};
pub const Key = struct { call_id: u32, address: u32, lo: u16, hi: u16 };

fn event(call_id: u32, address: u32, word: u32, weight: i8) Event {
    return .{ .call_id = call_id, .address = address, .lo = @truncate(word), .hi = @truncate(word >> 16), .weight = weight };
}

fn blockWords(block: [64]u8) [16]u32 {
    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, block[4 * i ..][0..4], .big);
    return words;
}

fn outputWord(row: feed.Row(M31)) u32 {
    var result: u32 = 0;
    for (row.output_bits, 0..) |bit, i| result |= bit.toU32() << @intCast(i);
    return result;
}

/// The caller emits each state input with multiplicity two: the round AIR
/// consumes it once and feed-forward consumes it once. A block input is
/// consumed once by schedule. Outputs are consumed by the caller, then
/// produced by feed-forward. Internal schedule and terminal addresses cannot
/// collide with boundary addresses or with one another.
pub fn build(allocator: std.mem.Allocator, headers: []const [80]u8, first_call_id: u32) ![]Event {
    const count = std.math.mul(usize, headers.len, 3) catch return error.TooManyShaCalls;
    if (headers.len == 0 or first_call_id == 0 or count > core.fields.m31.Modulus - first_call_id)
        return error.InvalidShaCallId;
    var events: std.ArrayList(Event) = .empty;
    errdefer events.deinit(allocator);
    try events.ensureTotalCapacity(allocator, headers.len * 3 * events_per_call);

    for (headers, 0..) |header, header_index| {
        const plan = plan_mod.prepare(header);
        const caller_rows = caller.witness(header);
        const base_id = first_call_id + @as(u32, @intCast(header_index * 3));
        for (caller_rows, 0..) |row, row_index| {
            for (caller.wordEvents(M31, row, row_index, base_id)) |maybe_word| if (maybe_word) |word| {
                try events.append(allocator, .{
                    .call_id = word.call_id,
                    .address = word.word_id,
                    .lo = @intCast(word.lo.toU32()),
                    .hi = @intCast(word.hi.toU32()),
                    .weight = if (word.word_id < 8) 2 else if (word.direction == .emit_input) 1 else -1,
                });
            };
        }
        for (plan.calls, 0..) |call, call_index| {
            const id = base_id + @as(u32, @intCast(call_index));
            const words = schedule.referenceWords(blockWords(call.block));
            const rounds = sha.witness(call.state, call.block);
            if (!std.meta.eql(words, rounds.schedule)) return error.ShaScheduleMismatch;
            const feed_rows = feed.witness(call.state, rounds.states[64]);
            for (feed_rows, call.output) |row, expected| if (outputWord(row) != expected) return error.ShaFeedMismatch;

            // Schedule consumes the sixteen caller block words and emits all
            // 64 W words. The round AIR consumes the same 64 W addresses.
            for (0..16) |i| try events.append(allocator, event(id, @as(u32, @intCast(8 + i)), words[i], -1));
            for (words, 0..) |word, i| try events.append(allocator, event(id, schedule_base + @as(u32, @intCast(i)), word, 1));

            for (call.state, 0..) |word, i| try events.append(allocator, event(id, @intCast(i), word, -1));
            for (words, 0..) |word, i| try events.append(allocator, event(id, schedule_base + @as(u32, @intCast(i)), word, -1));
            for (rounds.states[64], 0..) |word, i| try events.append(allocator, event(id, terminal_base + @as(u32, @intCast(i)), word, 1));

            for (call.state, 0..) |word, i| try events.append(allocator, event(id, @intCast(i), word, -1));
            for (rounds.states[64], 0..) |word, i| try events.append(allocator, event(id, terminal_base + @as(u32, @intCast(i)), word, -1));
            for (feed_rows, 0..) |row, i| try events.append(allocator, event(id, @as(u32, @intCast(24 + i)), outputWord(row), 1));
        }
    }
    if (events.items.len != count * events_per_call) return error.InvalidShaWordRoster;
    return events.toOwnedSlice(allocator);
}

pub fn balanced(allocator: std.mem.Allocator, events: []const Event) !bool {
    var counts = std.AutoHashMap(Key, i32).init(allocator);
    defer counts.deinit();
    for (events) |item| {
        const slot = try counts.getOrPut(item.key());
        if (!slot.found_existing) slot.value_ptr.* = 0;
        slot.value_ptr.* += item.weight;
    }
    var values = counts.valueIterator();
    while (values.next()) |value| if (value.* != 0) return false;
    return true;
}

test "one and two private headers have exactly closed candidate direct-SHA word rosters" {
    const allocator = std.testing.allocator;
    var headers: [2][80]u8 = undefined;
    for (&headers[0], 0..) |*byte, i| byte.* = @truncate(i * 31 + 3);
    for (&headers[1], 0..) |*byte, i| byte.* = @truncate(i * 73 + 11);
    for ([_]usize{ 1, 2 }) |n_headers| {
        const events = try build(allocator, headers[0..n_headers], 1);
        defer allocator.free(events);
        try std.testing.expectEqual(n_headers * 3 * events_per_call, events.len);
        try std.testing.expect(try balanced(allocator, events));
        const altered = try allocator.dupe(Event, events);
        defer allocator.free(altered);
        altered[0].lo ^= 1;
        try std.testing.expect(!(try balanced(allocator, altered)));
        altered[0] = events[0];
        altered[0].call_id += 1;
        try std.testing.expect(!(try balanced(allocator, altered)));
        altered[0] = events[0];
        altered[0].weight = events[0].weight + 1;
        try std.testing.expect(!(try balanced(allocator, altered)));
    }
    try std.testing.expectError(error.InvalidShaCallId, build(allocator, &headers, 0));
}
