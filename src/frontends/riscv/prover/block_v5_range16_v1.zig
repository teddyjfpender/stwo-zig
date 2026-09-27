//! Independently planned field-safe range16 shards for packed memory AIRs.
//! Counts are exact before challenges and checked by both requester and table.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const memory = @import("../air/block/memory_component.zig");
const word = @import("../air/block/word_memory_v5.zig");
pub const TABLE_LOG = 16;
pub const TABLE_SIZE = 1 << TABLE_LOG;
pub const MAX_REQUESTS: u64 = core.fields.m31.Modulus - 1;
pub const Counter = struct {
    a: std.mem.Allocator,
    values: []u32,
    total: u64 = 0,
    pub fn init(a: std.mem.Allocator) !Counter {
        const values = try a.alloc(u32, TABLE_SIZE);
        @memset(values, 0);
        return .{ .a = a, .values = values };
    }
    pub fn deinit(self: *Counter) void {
        self.a.free(self.values);
        self.* = undefined;
    }
    pub fn add(self: *Counter, value: u32) !void {
        if (value >= TABLE_SIZE) return error.InvalidV5Range16Value;
        if (self.total >= MAX_REQUESTS or self.values[value] >= MAX_REQUESTS) return error.V5Range16CountOverflow;
        self.values[value] += 1;
        self.total += 1;
    }
    pub fn digest(self: *const Counter) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/block-v5/range16-counter/v1\x00");
        var bytes: [4]u8 = undefined;
        for (self.values) |count| {
            std.mem.writeInt(u32, &bytes, count, .little);
            hash.update(&bytes);
        }
        return hash.finalResult();
    }
    pub fn merge(self: *Counter, other: *const Counter) !void {
        if (self.total + other.total > MAX_REQUESTS or self.values.len != TABLE_SIZE or other.values.len != TABLE_SIZE) return error.V5Range16CountOverflow;
        for (self.values, other.values) |*count, addend| count.* = try std.math.add(u32, count.*, addend);
        self.total += other.total;
    }
};
pub const Shard = struct { index: u32, first_instance: u32, instance_count: u32, request_count: u64 };
pub const Plan = struct {
    shards: []Shard,
    counts: []u64,
    total_events: u64,
    digest: [32]u8,
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        a.free(self.shards);
        a.free(self.counts);
        self.* = undefined;
    }
};
/// An explicitly empty requester family has no range provider. Legacy
/// `plan` still requires a nonempty admitted memory sequence.
pub fn emptyPlan(a: std.mem.Allocator) !Plan {
    const shards = try a.alloc(Shard, 0);
    errdefer a.free(shards);
    const counts = try a.alloc(u64, 0);
    return .{ .shards = shards, .counts = counts, .total_events = 0, .digest = digestRoster(shards, counts, 0) };
}
pub fn plan(a: std.mem.Allocator, claims: []const memory.Claim, counts: []const u64, total: u64) !Plan {
    try memory.admitSequence(claims, total);
    if (counts.len != claims.len or counts.len > std.math.maxInt(u32)) return error.InvalidV5Range16Plan;
    var shards: std.ArrayList(Shard) = .empty;
    errdefer shards.deinit(a);
    var first: usize = 0;
    var requests: u64 = 0;
    for (claims, counts, 0..) |claim, count, index| {
        try word.validatePublicClaim(claim);
        const bounds = word.rangeCountBounds(claim);
        if (count < bounds.minimum or count > bounds.maximum or count > MAX_REQUESTS) return error.InvalidV5Range16Plan;
        if (requests != 0 and requests + count > MAX_REQUESTS) {
            try append(a, &shards, first, index, requests);
            first = index;
            requests = 0;
        }
        requests += count;
    }
    try append(a, &shards, first, counts.len, requests);
    const owned_counts = try a.dupe(u64, counts);
    errdefer a.free(owned_counts);
    const owned_shards = try shards.toOwnedSlice(a);
    return .{ .shards = owned_shards, .counts = owned_counts, .total_events = total, .digest = digestRoster(owned_shards, owned_counts, total) };
}
pub fn admit(a: std.mem.Allocator, value: *const Plan, claims: []const memory.Claim) !void {
    if (claims.len == 0) {
        if (value.total_events != 0 or value.counts.len != 0 or value.shards.len != 0 or !std.meta.eql(value.digest, digestRoster(&.{}, &.{}, 0))) return error.InvalidV5Range16Plan;
        return;
    }
    var expected = try plan(a, claims, value.counts, value.total_events);
    defer expected.deinit(a);
    if (!std.meta.eql(expected.digest, value.digest) or expected.shards.len != value.shards.len) return error.InvalidV5Range16Plan;
    for (expected.shards, value.shards) |left, right| if (!std.meta.eql(left, right)) return error.InvalidV5Range16Plan;
}
test "block-v5 range17 planner rejects obsolete duplicate predecessor census" {
    const event = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = 0xffff_fffc, .clock = std.math.maxInt(u64), .before = 0xffff_ffff, .after = 0xffff_ffff };
    const claims = [_]memory.Claim{.{ .first_row = 0, .total_rows = 103, .rows = 103, .log_size = 8, .first = event, .last = event, .preceding = null }};
    var planned = try plan(std.testing.allocator, &claims, &.{1336}, 103);
    defer planned.deinit(std.testing.allocator);
    try admit(std.testing.allocator, &planned, &claims);
    try std.testing.expectError(error.InvalidV5Range16Plan, plan(std.testing.allocator, &claims, &.{2152}, 103));
    try std.testing.expectError(error.InvalidV5Range16Plan, plan(std.testing.allocator, &claims, &.{1335}, 103));
    var missing_predecessor = claims;
    missing_predecessor[0].first_row = 1;
    missing_predecessor[0].total_rows = 104;
    try std.testing.expectError(error.InvalidMemoryComponentClaim, plan(std.testing.allocator, &missing_predecessor, &.{1339}, 104));
}
fn append(a: std.mem.Allocator, shards: *std.ArrayList(Shard), first: usize, last: usize, count: u64) !void {
    if (last <= first or count == 0 or count > MAX_REQUESTS) return error.InvalidV5Range16Plan;
    try shards.append(a, .{ .index = @intCast(shards.items.len), .first_instance = @intCast(first), .instance_count = @intCast(last - first), .request_count = count });
}
fn digestRoster(shards: []const Shard, counts: []const u64, total: u64) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/range16-plan/v4\x00");
    hash.update(&@import("block_v5_word_memory_protocol_v1.zig").abiId());
    var bytes: [8]u8 = undefined;
    for ([_]u64{ total, counts.len, shards.len }) |value| {
        std.mem.writeInt(u64, &bytes, value, .little);
        hash.update(&bytes);
    }
    for (counts) |count| {
        std.mem.writeInt(u64, &bytes, count, .little);
        hash.update(&bytes);
    }
    for (shards) |shard| for ([_]u64{ shard.index, shard.first_instance, shard.instance_count, shard.request_count }) |value| {
        std.mem.writeInt(u64, &bytes, value, .little);
        hash.update(&bytes);
    };
    return hash.finalResult();
}
pub fn valueColumn(a: std.mem.Allocator) ![]M {
    const values = try a.alloc(M, TABLE_SIZE);
    for (0..TABLE_SIZE) |logical| values[@import("../air/block/memory_component_trace.zig").committedRow(logical, TABLE_LOG)] = M.fromCanonical(@intCast(logical));
    return values;
}
pub fn multiplicityColumn(a: std.mem.Allocator, counter: *const Counter, expected: u64) ![]M {
    if (counter.total != expected or expected > MAX_REQUESTS) return error.InvalidV5Range16Counter;
    const values = try a.alloc(M, TABLE_SIZE);
    for (counter.values, 0..) |count, logical| values[@import("../air/block/memory_component_trace.zig").committedRow(logical, TABLE_LOG)] = M.fromCanonical(count);
    return values;
}
