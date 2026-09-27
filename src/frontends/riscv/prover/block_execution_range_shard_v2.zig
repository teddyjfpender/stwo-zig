//! Separate byte-table roster for execution sidecar requests. Each proved
//! access makes exactly fourteen 8x8 requests. We use the existing table
//! proof's conservative 35/event shard bound so its current PCS API can be
//! shared without counter wrap or a second table AIR implementation.
const std = @import("std");
const core = @import("stwo_core");
const memory_shard = @import("block_memory_range_shard_v2.zig");
const range = @import("block_execution_byte_range_v2.zig");

pub const Shard = memory_shard.Shard;
pub const MAX_EVENTS_PER_SHARD: u64 = memory_shard.MAX_EVENTS_PER_SHARD;
pub const REQUESTS_PER_EVENT: u64 = range.REQUEST_COUNT;
pub const TAG: u32 = 0x42324552; // B2ER

pub const Plan = struct {
    shards: []Shard,
    event_counts: []u64,
    total_events: u64,
    digest: [32]u8,
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        a.free(self.shards); a.free(self.event_counts); self.* = undefined;
    }
};

/// `counts` are the exact AIR-constrained active counts for ordered execution
/// instances. The prover plans before challenge draw; the receiver recomputes
/// this plan after fresh sidecar verification and checks its sealed digest.
pub fn plan(a: std.mem.Allocator, counts: []const u64) !Plan {
    if (counts.len == 0 or counts.len > std.math.maxInt(u32)) return error.InvalidExecutionRangeRoster;
    var shards: std.ArrayList(Shard) = .empty;
    errdefer shards.deinit(a);
    var first_instance: usize = 0;
    var first_event: u64 = 0;
    var events: u64 = 0;
    for (counts, 0..) |count, index| {
        if (count > MAX_EVENTS_PER_SHARD) return error.ExecutionRangeInstanceExceedsShard;
        if (events != 0 and count > MAX_EVENTS_PER_SHARD - events) {
            try appendShard(a, &shards, first_instance, index, first_event, events);
            first_instance = index;
            first_event = try std.math.add(u64, first_event, events);
            events = 0;
        }
        events = try std.math.add(u64, events, count);
    }
    if (events != 0) try appendShard(a, &shards, first_instance, counts.len, first_event, events);
    const total = try std.math.add(u64, first_event, events);
    const owned_shards = try shards.toOwnedSlice(a);
    errdefer a.free(owned_shards);
    const owned_counts = try a.dupe(u64, counts);
    return .{ .shards = owned_shards, .event_counts = owned_counts, .total_events = total,
        .digest = digestRoster(owned_shards, owned_counts, total) };
}

fn appendShard(a: std.mem.Allocator, shards: *std.ArrayList(Shard), first: usize, end: usize, first_event: u64, events: u64) !void {
    if (end <= first or events == 0) return error.InvalidExecutionRangeRoster;
    const shard = Shard{
        .index = @intCast(shards.items.len), .first_instance = @intCast(first), .instance_count = @intCast(end - first),
        .first_event = first_event, .event_count = events,
        .max_requests = try std.math.mul(u64, events, memory_shard.REQUESTS_PER_EVENT),
    };
    try shard.validate();
    try shards.append(a, shard);
}

pub fn admit(value: *const Plan, counts: []const u64) !void {
    if (counts.len != value.event_counts.len or !std.mem.eql(u64, counts, value.event_counts))
        return error.InvalidExecutionRangeRoster;
    if (value.shards.len == 0) {
        if (counts.len == 0 or value.total_events != 0 or
            !std.meta.eql(value.digest, digestRoster(value.shards, counts, 0)))
            return error.InvalidExecutionRangeRoster;
        for (counts) |count| if (count != 0) return error.InvalidExecutionRangeRoster;
        return;
    }
    var next_instance: usize = 0;
    var next_event: u64 = 0;
    for (value.shards, 0..) |shard, index| {
        try shard.validate();
        if (shard.index != index or shard.first_instance != next_instance or shard.first_event != next_event or
            @as(usize, shard.first_instance) + shard.instance_count > counts.len) return error.InvalidExecutionRangeRoster;
        var events: u64 = 0;
        for (counts[shard.first_instance..][0..shard.instance_count]) |count| events = try std.math.add(u64, events, count);
        if (events != shard.event_count) return error.InvalidExecutionRangeRoster;
        next_instance += shard.instance_count;
        next_event = try std.math.add(u64, next_event, events);
    }
    if (next_instance != counts.len or next_event != value.total_events or
        !std.meta.eql(value.digest, digestRoster(value.shards, counts, value.total_events))) return error.InvalidExecutionRangeRoster;
}

pub fn digestRoster(shards: []const Shard, counts: []const u64, total: u64) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-execution/range-shards/v2\x00");
    var word: [8]u8 = undefined;
    std.mem.writeInt(u32, word[0..4], TAG, .little); hash.update(word[0..4]);
    std.mem.writeInt(u32, word[0..4], @intCast(shards.len), .little); hash.update(word[0..4]);
    std.mem.writeInt(u32, word[0..4], @intCast(counts.len), .little); hash.update(word[0..4]);
    std.mem.writeInt(u64, &word, total, .little); hash.update(&word);
    for (counts) |count| { std.mem.writeInt(u64, &word, count, .little); hash.update(&word); }
    for (shards) |shard| {
        for ([_]u32{ shard.index, shard.first_instance, shard.instance_count }) |part| {
            std.mem.writeInt(u32, word[0..4], part, .little); hash.update(word[0..4]);
        }
        for ([_]u64{ shard.first_event, shard.event_count, shard.max_requests }) |part| {
            std.mem.writeInt(u64, &word, part, .little); hash.update(&word);
        }
    }
    return hash.finalResult();
}

/// Family-nine pseudo-root seals the exact execution request census alongside
/// the separate family-eight table fixed/main roots before bus challenges.
pub fn planEntry(value: *const Plan) @import("block_memory_source_seal_v2.zig").FirstRoundEntry {
    return .{ .family = .execution_range_plan, .index = 0, .roots = .{ value.digest, @splat(0) } };
}

test "execution range shards bind exact active census and avoid M31 wrap" {
    const a = std.testing.allocator;
    const counts = [_]u64{ 20_000_000, 20_000_000, 20_000_000, 20_000_000 };
    var value = try plan(a, &counts);
    defer value.deinit(a);
    try admit(&value, &counts);
    try std.testing.expectEqual(@as(usize, 2), value.shards.len);
    try std.testing.expectEqual(@as(u64, 14 * 80_000_000), REQUESTS_PER_EVENT * value.total_events);
    for (value.shards) |shard| try std.testing.expect(shard.max_requests < core.fields.m31.Modulus);
    var changed = counts;
    changed[2] += 1;
    try std.testing.expectError(error.InvalidExecutionRangeRoster, admit(&value, &changed));
}

test "block-v4 empty execution range plan binds every zero-count instance" {
    const a = std.testing.allocator;
    const counts = [_]u64{ 0, 0 };
    var value = try plan(a, &counts);
    defer value.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), value.shards.len);
    try std.testing.expectEqual(@as(u64, 0), value.total_events);
    try admit(&value, &counts);
    var changed = counts;
    changed[1] = 1;
    try std.testing.expectError(error.InvalidExecutionRangeRoster, admit(&value, &changed));
    var bad = value;
    bad.digest[0] ^= 1;
    try std.testing.expectError(error.InvalidExecutionRangeRoster, admit(&bad, &counts));
}
