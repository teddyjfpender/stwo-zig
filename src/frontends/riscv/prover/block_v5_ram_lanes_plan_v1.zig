//! Independently reconstructed event/range roster. Legacy event claims are
//! used only by the unchanged field-safe range planner, never PCS geometry.
const std = @import("std");
const core = @import("stwo_core");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Proof = @import("block_v5_ram_lanes_proof_v1.zig");
const Range = @import("block_v5_range16_v1.zig");
const Memory = @import("../air/block/memory_component.zig");
pub const Limits = struct {
    max_instances: u32 = 4096,
    max_shards: u32 = 4096,
    max_metadata_bytes: usize = 32 << 20,
    pub fn require(self: Limits, instances: usize, shards: usize) !void {
        // Conservative concurrent stage + independent-plan reconstruction:
        // owned pins/claims, temporary exact/legacy claims, counts, roots.
        const bytes = try std.math.add(usize, try std.math.mul(usize, instances, @sizeOf(Proof.Pin) + 2 * @sizeOf(Protocol.Claim) + @sizeOf(Memory.Claim) + 3 * @sizeOf(u64)), try std.math.mul(usize, shards, 2 * @sizeOf(Range.Shard) + 64));
        if (instances > self.max_instances or shards > self.max_shards or bytes > self.max_metadata_bytes) return error.V5RamLanesResourceLimit;
    }
};
pub fn rangePlan(a: std.mem.Allocator, pins: []const Proof.Pin, total: u64, limits: Limits) !Range.Plan {
    try limits.require(pins.len, 0);
    if (pins.len == 0) {
        if (total != 0) return error.InvalidV5RamLanesCensus;
        return Range.emptyPlan(a);
    }
    // Bound the independently derived provider roster before the temporary
    // claim vectors or Range.plan's growing shard vector are allocated.
    var shards: usize = 1;
    var requests: u64 = 0;
    for (pins, 0..) |pin, index| {
        try pin.validate();
        if (pin.index != index) return error.InvalidV5RamLanesCensus;
        if (requests != 0 and requests + pin.request_count > Range.MAX_REQUESTS) {
            shards += 1;
            requests = 0;
        }
        requests += pin.request_count;
    }
    try limits.require(pins.len, shards);
    const claims = try a.alloc(Protocol.Claim, pins.len);
    defer a.free(claims);
    const legacy = try a.alloc(Memory.Claim, pins.len);
    defer a.free(legacy);
    const counts = try a.alloc(u64, pins.len);
    defer a.free(counts);
    for (pins, claims, legacy, counts, 0..) |pin, *claim, *event_claim, *count, index| {
        try pin.validate();
        if (pin.index != index) return error.InvalidV5RamLanesCensus;
        claim.* = pin.claim;
        event_claim.* = pin.claim.legacy();
        count.* = pin.request_count;
    }
    try Protocol.admitSequence(claims, total);
    var plan = try Range.plan(a, legacy, counts, total);
    errdefer plan.deinit(a);
    try limits.require(pins.len, plan.shards.len);
    return plan;
}
pub fn digest(a: std.mem.Allocator, pins: []const Proof.Pin, total: u64, roots: []const [2][32]u8, limits: Limits) ![32]u8 {
    var plan = try rangePlan(a, pins, total, limits);
    defer plan.deinit(a);
    if (roots.len != plan.shards.len) return error.InvalidV5RamLanesRangeRoster;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, 0x504c414e });
    channel.mixRoot(Protocol.abiId());
    channel.mixU64(total);
    channel.mixU64(pins.len);
    channel.mixU64(roots.len);
    channel.mixRoot(plan.digest);
    for (pins) |pin| channel.mixRoot(try pin.identity());
    for (roots) |pair| for (pair) |root| {
        if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedV5RamLanesPin;
        channel.mixRoot(root);
    };
    return channel.digestBytes();
}
pub fn admit(a: std.mem.Allocator, plan: *const Range.Plan, pins: []const Proof.Pin, total: u64, limits: Limits) !void {
    var expected = try rangePlan(a, pins, total, limits);
    defer expected.deinit(a);
    if (plan.total_events != total or !std.meta.eql(expected.digest, plan.digest) or
        !std.mem.eql(u64, expected.counts, plan.counts) or expected.shards.len != plan.shards.len)
        return error.InvalidV5RamLanesRangeRoster;
    for (expected.shards, plan.shards) |left, right| if (!std.meta.eql(left, right)) return error.InvalidV5RamLanesRangeRoster;
}
