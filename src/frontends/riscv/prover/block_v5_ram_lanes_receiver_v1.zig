//! Fresh all-instance lane/range/source closure. Compatible global Scoped
//! is returned only after this typed lane proof path completes internally.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Proof = @import("block_v5_ram_lanes_proof_v1.zig");
const Plan = @import("block_v5_ram_lanes_plan_v1.zig");
const Table = @import("block_v5_range16_proof_v1.zig");
const Join = @import("block_v5_ram_lanes_join_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Sources = @import("block_v5_word_memory_sources_v1.zig");
const Endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
pub const Scoped = @import("block_v5_word_memory_receiver_v1.zig").Scoped;
pub const Pins = struct {
    seal: Seal.Pins,
    expected_seal_digest: [32]u8,
    first_round: []const Seal.Entry,
    pins: []const Proof.Pin,
    range_roots: []const [2][32]u8,
    expected_total_events: u64,
    source: Endpoint.Pins,
    /// Independent receiver policy; never selected by received metadata.
    limits: Limits = .{},
};
pub const Limits = struct { proof: Proof.Limits = .{}, plan: Plan.Limits = .{} };
pub const Loader = struct {
    context: *anyopaque,
    take_memory: *const fn (*anyopaque, u32) anyerror!Proof.Proof,
    take_range: *const fn (*anyopaque, u32) anyerror!Table.Proof,
};
pub fn admit(a: std.mem.Allocator, pins: Pins, sealed: Seal.Sealed, limits: Limits) !void {
    if (!std.meta.eql(pins.limits, limits)) return error.UntrustedV5RamLanesReceiverLimits;
    try pins.seal.validateComplete();
    try sealed.require(pins.seal, pins.first_round);
    if (pins.seal.register_custody_mode != 1 or sealed.register_custody_mode != 1 or
        !std.meta.eql(pins.expected_seal_digest, sealed.digest) or pins.pins.len != sealed.memory_instance_count or
        pins.range_roots.len != pins.seal.counts[@intFromEnum(Seal.Family.memory_range) - 1]) return error.UntrustedV5RamLanesReceiver;
    const digest = try Plan.digest(a, pins.pins, pins.expected_total_events, pins.range_roots, limits.plan);
    if (!std.meta.eql(digest, pins.seal.memory_plan_digest) or !std.meta.eql(digest, pins.source.memory_plan_digest))
        return error.UntrustedV5RamLanesPlan;
    for (pins.pins) |pin| {
        try limits.proof.require(pin.claim);
        try Proof.admit(pin, sealed, pins.seal, pins.first_round);
    }
    var plan = try Plan.rangePlan(a, pins.pins, pins.expected_total_events, limits.plan);
    defer plan.deinit(a);
    var at: usize = 0;
    for (pins.first_round) |entry| if (entry.family == .memory_range) {
        if (at >= plan.shards.len or entry.index != at or !std.meta.eql(entry.roots, pins.range_roots[at]) or
            !std.meta.eql(entry.instance_id, Table.instanceId(plan.digest, @intCast(at)))) return error.UntrustedV5RamLanesRangeRoster;
        at += 1;
    };
    if (at != plan.shards.len) return error.UntrustedV5RamLanesRangeRoster;
}
pub fn verify(comptime Backend: type, a: std.mem.Allocator, pins: Pins, public_input: []const u8, files: Endpoint.Sources, loader: Loader, sealed: Seal.Sealed, limits: Limits) !Scoped {
    try admit(a, pins, sealed, limits);
    var plan = try Plan.rangePlan(a, pins.pins, pins.expected_total_events, limits.plan);
    defer plan.deinit(a);
    const public = try Sources.check(a, pins.source, public_input, files, pins.seal, pins.first_round, sealed);
    if (public.initial.register_touches != 0) return error.MixedV5RegisterCustody;
    if (pins.pins.len == 0) {
        // No loader is consumed and no memory STARK or scalar is invented.
        // The enclosing execution/register join must freshly prove RW absence.
        if (pins.expected_total_events != 0 or public.initial.first_touch_count != 0 or public.endpoints.count != 0 or
            !public.initial_sum.isZero() or !public.endpoint_sum.isZero() or
            !std.meta.eql(public.endpoints.final_root, pins.source.initial.initial_rw_root)) return error.UntrustedV5EmptyRwSources;
    }
    var transition = Q.zero();
    var link = Q.zero();
    var initial = Q.zero();
    var final = Q.zero();
    var endpoint_count: u64 = 0;
    var range_count: u64 = 0;
    const range_sums = try a.alloc(Q, pins.pins.len);
    defer a.free(range_sums);
    for (pins.pins, 0..) |pin, index| {
        const received = try loader.take_memory(loader.context, @intCast(index));
        const fresh = try Proof.ForBackend(Backend).verifyOwned(a, received, pin, sealed, pins.seal, pins.first_round, limits.proof);
        const buses = Join.buses(fresh.sums);
        transition = transition.add(buses.transition_sum);
        link = link.add(buses.link_sum);
        initial = initial.add(buses.initial_sum);
        final = final.add(buses.endpoint_sum);
        endpoint_count = try std.math.add(u64, endpoint_count, buses.endpoint_count);
        range_count = try std.math.add(u64, range_count, buses.range_count);
        range_sums[index] = buses.rangeSum();
        if (fresh.registerEndpointCount() != 0 or !fresh.registerEndpointSum().isZero()) return error.MixedV5RegisterCustody;
    }
    for (plan.shards, pins.range_roots) |shard, roots| {
        const received = try loader.take_range(loader.context, shard.index);
        const fresh = try Table.ForBackend(Backend).verifyOwned(a, received, shard, plan.digest, roots, sealed, pins.seal, pins.first_round);
        var sum = fresh.claim.sum;
        for (range_sums[shard.first_instance..][0..shard.instance_count]) |requests| sum = sum.add(requests);
        if (!sum.isZero()) return error.UnclosedV5Range16Relation;
    }
    if (!link.isZero()) return error.UnclosedV5RamLanesPredecessorRelation;
    if (!initial.add(public.initial_sum).isZero() or public.initial.first_touch_count > pins.expected_total_events)
        return error.UnclosedV5RamLanesInitialRelation;
    if (!final.sub(public.endpoint_sum).isZero() or endpoint_count != public.endpoints.count)
        return error.UnclosedV5RamLanesFinalRelation;
    return .{ .transition_sum = transition, .register_endpoints_verified = false, .register_endpoint_count = 0, .event_count = pins.expected_total_events, .first_touch_count = public.initial.first_touch_count, .endpoint_count = endpoint_count, .range_count = range_count, .memory_instances = @intCast(pins.pins.len), .range_shards = @intCast(plan.shards.len), .initial_rw_root = pins.source.initial.initial_rw_root, .final_rw_root = public.endpoints.final_root, .sealed_digest = sealed.digest, .memory_plan_digest = pins.seal.memory_plan_digest };
}
