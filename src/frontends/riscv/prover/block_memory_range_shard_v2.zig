//! Exact, overflow-safe roster for shared block-v2 byte-table proofs.
//! A shard's total possible requests is strictly below the M31 modulus, so
//! every valid Boolean-gated 8x8 table multiplicity also has an exact M31
//! representation. The public partition is fixed before relation challenges.
const std = @import("std");
const core = @import("stwo_core");
const memory = @import("../air/block/memory_component.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");

pub const Digest = [32]u8;
pub const REQUESTS_PER_EVENT: u64 = range.EVENT_COUNT;
pub const MAX_EXACT_REQUESTS: u64 = core.fields.m31.Modulus - 1;
pub const MAX_EVENTS_PER_SHARD: u64 = MAX_EXACT_REQUESTS / REQUESTS_PER_EVENT;
pub const TAG: u32 = 0x42325253; // B2RS

pub const Shard = struct {
    index: u32,
    first_instance: u32,
    instance_count: u32,
    first_event: u64,
    event_count: u64,
    max_requests: u64,

    pub fn validate(self: Shard) !void {
        if (self.instance_count == 0 or self.event_count == 0 or
            self.max_requests != try std.math.mul(u64, self.event_count, REQUESTS_PER_EVENT) or
            self.max_requests > MAX_EXACT_REQUESTS) return error.InvalidRangeShard;
    }
};

pub const Plan = struct {
    shards: []Shard,
    total_events: u64,
    total_instances: u32,
    digest: Digest,

    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        a.free(self.shards);
        self.* = undefined;
    }
};

/// Greedy contiguous partition minimizes table-proof count subject to an
/// exact integer request bound. No power-of-two proof-count rounding occurs.
pub fn plan(a: std.mem.Allocator, claims: []const memory.Claim, total_events: u64) !Plan {
    try memory.admitSequence(claims, total_events);
    if (claims.len > std.math.maxInt(u32)) return error.InvalidRangeShardRoster;
    var shards = std.ArrayList(Shard).empty;
    errdefer shards.deinit(a);
    var first_instance: usize = 0;
    var first_event: u64 = 0;
    var events: u64 = 0;
    for (claims, 0..) |claim, index| {
        if (claim.rows > MAX_EVENTS_PER_SHARD) return error.RangeInstanceExceedsShard;
        if (events != 0 and events + claim.rows > MAX_EVENTS_PER_SHARD) {
            try appendShard(a, &shards, first_instance, index, first_event, events);
            first_instance = index;
            first_event += events;
            events = 0;
        }
        events += claim.rows;
    }
    try appendShard(a, &shards, first_instance, claims.len, first_event, events);
    const owned = try shards.toOwnedSlice(a);
    return .{ .shards = owned, .total_events = total_events, .total_instances = @intCast(claims.len), .digest = digestRoster(owned, total_events, @intCast(claims.len)) };
}

fn appendShard(a: std.mem.Allocator, shards: *std.ArrayList(Shard), first: usize, end: usize, first_event: u64, events: u64) !void {
    if (end <= first or events == 0) return error.InvalidRangeShardRoster;
    const shard = Shard{
        .index = @intCast(shards.items.len), .first_instance = @intCast(first),
        .instance_count = @intCast(end - first), .first_event = first_event,
        .event_count = events, .max_requests = try std.math.mul(u64, events, REQUESTS_PER_EVENT),
    };
    try shard.validate();
    try shards.append(a, shard);
}

pub fn admit(plan_value: *const Plan, claims: []const memory.Claim) !void {
    if (claims.len != plan_value.total_instances or plan_value.shards.len == 0) return error.InvalidRangeShardRoster;
    try memory.admitSequence(claims, plan_value.total_events);
    var next_instance: u32 = 0;
    var next_event: u64 = 0;
    for (plan_value.shards, 0..) |shard, index| {
        try shard.validate();
        if (shard.index != index or shard.first_instance != next_instance or shard.first_event != next_event or
            @as(usize, shard.first_instance) + shard.instance_count > claims.len) return error.InvalidRangeShardRoster;
        var actual_events: u64 = 0;
        for (claims[shard.first_instance..][0..shard.instance_count]) |claim| actual_events += claim.rows;
        if (actual_events != shard.event_count) return error.InvalidRangeShardRoster;
        next_instance += shard.instance_count;
        next_event += shard.event_count;
    }
    if (next_instance != claims.len or next_event != plan_value.total_events or
        !std.meta.eql(plan_value.digest, digestRoster(plan_value.shards, plan_value.total_events, plan_value.total_instances)))
        return error.InvalidRangeShardRoster;
}

pub fn digestRoster(shards: []const Shard, total_events: u64, total_instances: u32) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-memory/range-shards/v2\x00");
    var word: [8]u8 = undefined;
    std.mem.writeInt(u32, word[0..4], TAG, .little); hash.update(word[0..4]);
    std.mem.writeInt(u32, word[0..4], @intCast(shards.len), .little); hash.update(word[0..4]);
    std.mem.writeInt(u32, word[0..4], total_instances, .little); hash.update(word[0..4]);
    std.mem.writeInt(u64, &word, total_events, .little); hash.update(&word);
    for (shards) |shard| {
        for ([_]u32{ shard.index, shard.first_instance, shard.instance_count }) |value| {
            std.mem.writeInt(u32, word[0..4], value, .little); hash.update(word[0..4]);
        }
        for ([_]u64{ shard.first_event, shard.event_count, shard.max_requests }) |value| {
            std.mem.writeInt(u64, &word, value, .little); hash.update(&word);
        }
    }
    return hash.finalResult();
}

test "block-v2 range shard planner prevents M31 hot-counter wrap" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as(u64, 61_356_675), MAX_EVENTS_PER_SHARD);
    const transition = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = 0, .clock = 1, .before = 0, .after = 0 };
    var claims: [340]memory.Claim = undefined;
    const total: u64 = (1 << 20) * 339 + 836_650;
    try std.testing.expectEqual(@as(u64, 356_303_914), total);
    var cursor: u64 = 0;
    for (&claims, 0..) |*claim, index| {
        const rows: u32 = if (index == 339) 836_650 else 1 << 20;
        claim.* = try memory.Claim.fromSummary(.{ .first_row = cursor, .rows = rows, .first = transition, .last = transition }, total, 20, if (cursor == 0) null else transition);
        cursor += rows;
    }
    var result = try plan(a, &claims, total);
    defer result.deinit(a);
    try admit(&result, &claims);
    try std.testing.expectEqual(@as(usize, 6), result.shards.len);
    try std.testing.expectEqual(@as(u32, 58), result.shards[0].instance_count);
    for (result.shards) |shard| try std.testing.expect(shard.max_requests < core.fields.m31.Modulus);
    var forged = result;
    forged.shards = try a.dupe(Shard, result.shards);
    defer a.free(forged.shards);
    forged.shards[0].event_count += 1;
    try std.testing.expectError(error.InvalidRangeShard, admit(&forged, &claims));
}
