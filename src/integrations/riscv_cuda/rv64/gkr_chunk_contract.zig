//! Admission contract for a bounded-device GKR implementation. Numerical chunk
//! callbacks and a joined host store are not implemented here. This cost must
//! never authorize the current retained-tree or partial-frontier enqueue.
const std = @import("std");
const G = @import("gkr.zig");
const A = @import("abi.zig");
pub const Range = struct {
    first: u32,
    count: u32,
    pub fn validate(self: Range, total: u32, chunk_facts: u32) !void {
        if (self.count == 0 or self.count > chunk_facts or self.first > total or self.count > total - self.first) return error.InvalidGkrChunkRange;
    }
};
pub const Cost = struct {
    device_workspace_bytes: u64,
    pinned_ring_bytes: u64,
    host_store_bytes: u64,
    product_combinations: u64,
    /// Upper bound for product-store and sumcheck traffic, excluding MAIN,
    /// parameters, state, records and source materialization.
    host_device_transfer_bytes_upper_bound: u64,
    chunk_facts: u32,
    pipeline_slots: u32,
    numerical_implementation_available: bool = false,
};
/// Four source stripes, two folded output stripes, one Eq stripe, and two
/// block reductions. Each fraction is two eight-coordinate M31 values. A
/// pipeline slot owns all its slabs until its stream event has joined.
pub fn cost(variables: []const u32, chunk_facts: u32, pipeline_slots: u32) !Cost {
    if (variables.len == 0 or variables.len > G.max_instances or chunk_facts < 128 or chunk_facts > 1 << G.max_variables or !std.math.isPowerOfTwo(chunk_facts) or pipeline_slots == 0 or pipeline_slots > 2) return error.InvalidGkrChunkGeometry;
    var facts: u64 = 0;
    var combinations: u64 = 0;
    for (variables) |height| {
        if (height == 0 or height > G.max_variables) return error.InvalidGkrChunkGeometry;
        const n = @as(u64, 1) << @intCast(height);
        facts = try std.math.add(u64, facts, n);
        combinations = try std.math.add(u64, combinations, n - 1);
    }
    const groups = (@as(u64, chunk_facts) + 127) / 128;
    const slab = try std.math.mul(u64, 416, chunk_facts);
    const reductions = try std.math.mul(u64, 256, groups);
    const state = 4 * (A.gkr_state_words + A.batch_state_words);
    // Small roots, terminal masks and all layer records remain GPU-owned.
    const metadata = 4 * (16 * @as(u64, variables.len) + 32 * @as(u64, variables.len) * G.max_variables + A.round_record_words * G.max_variables * (G.max_variables - 1) / 2);
    return .{
        .device_workspace_bytes = try std.math.add(u64, state + metadata, try std.math.mul(u64, pipeline_slots, slab + reductions)),
        .pinned_ring_bytes = try std.math.mul(u64, pipeline_slots, try std.math.mul(u64, 384, chunk_facts)),
        .host_store_bytes = try std.math.mul(u64, combinations, 64),
        .product_combinations = combinations,
        .host_device_transfer_bytes_upper_bound = try std.math.mul(u64, facts, 512),
        .chunk_facts = chunk_facts,
        .pipeline_slots = pipeline_slots,
    };
}

/// Store coordinates name the immutable product layer or the current folded
/// layer. Range order is global, never chunk-local. A generation changes only
/// after all readers/writers join; close-round is the transcript barrier.
pub const Address = struct { oracle: u32, product_level: u32, fold_round: u32, generation: u64, range: Range };
pub const Event = struct { token: u64 };
pub const ChunkStore = struct {
    context: *anyopaque,
    read_frontier_chunk: *const fn (*anyopaque, Address, *anyopaque, u32) anyerror!Event,
    write_frontier_chunk: *const fn (*anyopaque, Address, *const anyopaque, u32) anyerror!Event,
    join: *const fn (*anyopaque, Event) anyerror!void,
};

// These describe required numerical work, not callable kernel bindings. The
// implementation must pin exact global indices/point bits and retain the
// ordinary batch round's challenge/order/domain and polynomial representation.
pub const ProductChunk = struct { sources: [4]Address, source_stripes: u32, levels: u32, output: Address };
pub const FoldRoundChunk = struct { left: Address, right: Address, output: Address, challenge_word: u64 };
pub const SumRoundChunk = struct { stripes: [4]Address, equality_global_first: u32, round: u32 };

test "bounded GKR cost is device chunk bounded while host store is explicitly N dependent" {
    const a = try cost(&.{20}, 1 << 18, 2);
    const b = try cost(&.{28}, 1 << 18, 2);
    try std.testing.expectEqual(a.device_workspace_bytes, b.device_workspace_bytes);
    try std.testing.expectEqual(a.pinned_ring_bytes, b.pinned_ring_bytes);
    try std.testing.expect(b.host_store_bytes > a.host_store_bytes);
    try std.testing.expect(!a.numerical_implementation_available);
    try std.testing.expectError(error.InvalidGkrChunkGeometry, cost(&.{20}, 127, 2));
    try std.testing.expectError(error.InvalidGkrChunkGeometry, cost(&.{20}, 256, 3));
    try std.testing.expectError(error.InvalidGkrChunkRange, (Range{ .first = 1020, .count = 8 }).validate(1024, 128));
    try (Range{ .first = 896, .count = 128 }).validate(1024, 128);
    const real = try cost(&.{ 23, 22, 23, 21, 27, 26, 24, 24 }, 1 << 18, 2);
    std.debug.print("\nGKR_CHUNK_CONTRACT {f}\n", .{std.json.fmt(real, .{})});
}
