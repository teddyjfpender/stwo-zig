//! Fresh packed36 memory, range16, initial and final RW closure under B5SS.
//! Returns an open transition claim, not native/public-register/complete-block
//! authority. Every proof is loaded, freshly verified and released in order.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const memory = @import("../air/block/memory_component.zig");
const proof = @import("block_v5_word_memory_proof_v1.zig");
const table = @import("block_v5_range16_proof_v1.zig");
const range = @import("block_v5_range16_v1.zig");
const sources = @import("block_v5_word_memory_sources_v1.zig");
const registers = @import("block_v5_register_endpoints_v1.zig");
const endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const Digest = [32]u8;
pub const Pins = struct {
    seal: seal.Pins,
    expected_seal_digest: Digest,
    first_round: []const seal.Entry,
    claims: []const memory.Claim,
    request_counts: []const u64,
    memory_roots: []const [2]Digest,
    range_roots: []const [2]Digest,
    expected_total_events: u64,
    source: endpoint.Pins,
    register_endpoints: ?registers.Pins = null,
};
pub const Loader = struct {
    context: *anyopaque,
    take_memory: *const fn (*anyopaque, u32) anyerror!proof.Proof,
    take_range: *const fn (*anyopaque, u32) anyerror!table.Proof,
};
pub const Scoped = struct {
    packed_memory_range_initial_final_rw_verified: void = {},
    transition_sum: Q,
    register_endpoints_verified: bool,
    register_endpoint_count: u64,
    event_count: u64,
    first_touch_count: u64,
    endpoint_count: u64,
    range_count: u64,
    memory_instances: u32,
    range_shards: u32,
    initial_rw_root: Digest,
    final_rw_root: Digest,
    sealed_digest: Digest,
    memory_plan_digest: Digest,
};
pub fn verify(comptime Backend: type, a: std.mem.Allocator, pins: Pins, public_input: []const u8, files: endpoint.Sources, loader: Loader, sealed: seal.Sealed) !Scoped {
    if (pins.claims.len == 0) return verifyEmpty(a, pins, public_input, files, sealed);
    if (pins.claims.len != pins.memory_roots.len or pins.claims.len != pins.request_counts.len or !std.meta.eql(pins.expected_seal_digest, sealed.digest)) return error.UntrustedV5WordPins;
    var plan = try range.plan(a, pins.claims, pins.request_counts, pins.expected_total_events);
    defer plan.deinit(a);
    const digest = try planDigest(a, pins.claims, pins.memory_roots, pins.range_roots, &plan);
    if (!std.meta.eql(digest, pins.seal.memory_plan_digest) or !std.meta.eql(digest, pins.source.memory_plan_digest) or
        pins.seal.counts[@intFromEnum(seal.Family.memory) - 1] != pins.claims.len or pins.seal.counts[@intFromEnum(seal.Family.memory_range) - 1] != pins.range_roots.len) return error.UntrustedV5WordPlan;
    try sealed.require(pins.seal, pins.first_round);
    try admitRoots(pins, &plan);
    const public = try sources.check(a, pins.source, public_input, files, pins.seal, pins.first_round, sealed);
    if (sealed.register_custody_mode == 1) {
        if (pins.register_endpoints != null or public.initial.register_touches != 0) return error.MixedV5RegisterCustody;
        // The sorted AIR constrains monotone space-major ordering. Pinning
        // both ends to RW excludes register rows throughout every instance.
        for (pins.claims) |claim| if (claim.first.space != 1 or claim.last.space != 1 or
            (claim.preceding != null and claim.preceding.?.space != 1)) return error.MixedV5RegisterCustody;
    }
    const register_claims = if (pins.register_endpoints) |reg_pins| try registers.check(a, reg_pins, pins.source.initial, files.initial.first_touches, sealed, pins.seal, pins.first_round) else null;
    if (sealed.register_custody_mode == 0 and register_claims == null and !std.meta.eql(pins.seal.register_endpoint_plan_digest, @as(Digest, @splat(0)))) return error.MissingV5RegisterEndpointPins;
    var total_registers = Q.zero();
    var register_count: u64 = 0;
    var total_transition = Q.zero();
    var total_link = Q.zero();
    var total_initial = Q.zero();
    var total_endpoints = Q.zero();
    var endpoint_count: u64 = 0;
    var range_count: u64 = 0;
    const range_sums = try a.alloc(Q, pins.claims.len);
    defer a.free(range_sums);
    for (pins.claims, pins.memory_roots, 0..) |claim, roots, index| {
        const received = try loader.take_memory(loader.context, @intCast(index));
        const fresh = try proof.ForBackend(Backend).verifyOwned(a, received, claim, sealed, pins.seal, pins.first_round, @intCast(index), roots);
        if (fresh.sums.range_count != pins.request_counts[index]) return error.UntrustedV5WordRequestCensus;
        total_registers = total_registers.add(fresh.sums.register_endpoint_sum);
        register_count = try std.math.add(u64, register_count, fresh.sums.register_endpoint_count);
        total_transition = total_transition.add(fresh.sums.transition_sum);
        total_link = total_link.add(fresh.sums.link_sum);
        total_initial = total_initial.add(fresh.sums.initial_sum);
        total_endpoints = total_endpoints.add(fresh.sums.endpoint_sum);
        endpoint_count = try std.math.add(u64, endpoint_count, fresh.sums.endpoint_count);
        range_count = try std.math.add(u64, range_count, fresh.sums.range_count);
        range_sums[index] = Q.zero();
        for (fresh.sums.range_sums) |value| range_sums[index] = range_sums[index].add(value);
    }
    for (plan.shards, pins.range_roots) |shard, roots| {
        const received = try loader.take_range(loader.context, shard.index);
        const fresh = try table.ForBackend(Backend).verifyOwned(a, received, shard, plan.digest, roots, sealed, pins.seal, pins.first_round);
        var sum = fresh.claim.sum;
        for (range_sums[shard.first_instance..][0..shard.instance_count]) |requests| sum = sum.add(requests);
        if (!sum.isZero()) return error.UnclosedV5Range16Relation;
    }
    if (!total_link.isZero()) return error.UnclosedV5WordPredecessorRelation;
    if (!total_initial.add(public.initial_sum).isZero() or public.initial.first_touch_count > pins.expected_total_events) return error.UnclosedV5WordInitialRelation;
    if (!total_endpoints.sub(public.endpoint_sum).isZero() or endpoint_count != public.endpoints.count) return error.UnclosedV5WordFinalRwRelation;
    if (register_claims) |fresh_public| {
        if (!total_registers.sub(fresh_public.sum).isZero() or register_count != fresh_public.count) return error.UnclosedV5RegisterEndpointRelation;
    }
    if (sealed.register_custody_mode == 1 and (register_count != 0 or !total_registers.isZero())) return error.MixedV5RegisterCustody;
    return .{ .register_endpoints_verified = register_claims != null, .register_endpoint_count = register_count, .transition_sum = total_transition, .event_count = pins.expected_total_events, .first_touch_count = public.initial.first_touch_count, .endpoint_count = endpoint_count, .range_count = range_count, .memory_instances = @intCast(pins.claims.len), .range_shards = @intCast(plan.shards.len), .initial_rw_root = pins.source.initial.initial_rw_root, .final_rw_root = public.endpoints.final_root, .sealed_digest = sealed.digest, .memory_plan_digest = digest };
}
/// A zero requester census creates no memory/range proof authority. The
/// enclosing MemoryJoin additionally proves absence of every RW slot from
/// its fresh native/caller hooks; TableJoin closes all register windows.
fn verifyEmpty(a: std.mem.Allocator, pins: Pins, public_input: []const u8, files: endpoint.Sources, sealed: seal.Sealed) !Scoped {
    const digest = @import("block_v5_empty_rw_memory_v1.zig").planDigest();
    if (sealed.register_custody_mode != 1 or pins.claims.len != 0 or pins.memory_roots.len != 0 or
        pins.request_counts.len != 0 or pins.range_roots.len != 0 or pins.expected_total_events != 0 or
        pins.register_endpoints != null or sealed.memory_instance_count != 0 or
        pins.seal.counts[@intFromEnum(seal.Family.memory_range) - 1] != 0 or
        !std.meta.eql(pins.expected_seal_digest, sealed.digest) or !std.meta.eql(pins.seal.memory_plan_digest, digest) or
        !std.meta.eql(pins.source.memory_plan_digest, digest) or pins.source.initial.first_touches.records != 0 or
        pins.source.endpoints.records != 0) return error.UntrustedV5EmptyRwPlan;
    try sealed.require(pins.seal, pins.first_round);
    const fresh = try sources.check(a, pins.source, public_input, files, pins.seal, pins.first_round, sealed);
    if (fresh.initial.first_touch_count != 0 or fresh.initial.register_touches != 0 or fresh.endpoints.count != 0 or
        !fresh.initial_sum.isZero() or !fresh.endpoint_sum.isZero() or
        !std.meta.eql(fresh.endpoints.final_root, pins.source.initial.initial_rw_root)) return error.UntrustedV5EmptyRwSources;
    return .{ .transition_sum = Q.zero(), .register_endpoints_verified = false, .register_endpoint_count = 0,
        .event_count = 0, .first_touch_count = 0, .endpoint_count = 0, .range_count = 0,
        .memory_instances = 0, .range_shards = 0, .initial_rw_root = pins.source.initial.initial_rw_root,
        .final_rw_root = fresh.endpoints.final_root, .sealed_digest = sealed.digest, .memory_plan_digest = digest };
}
pub fn planDigest(a: std.mem.Allocator, claims: []const memory.Claim, roots: []const [2]Digest, range_roots: []const [2]Digest, plan: *const range.Plan) !Digest {
    if (claims.len != roots.len or plan.shards.len != range_roots.len) return error.InvalidV5WordPlan;
    try range.admit(a, plan, claims);
    if (claims.len == 0) {
        if (roots.len != 0 or range_roots.len != 0) return error.InvalidV5WordPlan;
        return @import("block_v5_empty_rw_memory_v1.zig").planDigest();
    }
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/packed36-memory-plan/v1\x00");
    hash.update(&@import("block_v5_word_memory_protocol_v1.zig").abiId());
    put(&hash, plan.total_events);
    put(&hash, claims.len);
    put(&hash, range_roots.len);
    hash.update(&plan.digest);
    for (claims, roots, 0..) |claim, first, index| {
        // memoryInstanceId canonically encodes log/row census, both complete
        // boundary tuples and the optional full predecessor; no raw structs.
        hash.update(&proof.instanceId(claim, @intCast(index)));
        hash.update(&first[0]);
        hash.update(&first[1]);
    }
    for (range_roots) |first| {
        hash.update(&first[0]);
        hash.update(&first[1]);
    }
    return hash.finalResult();
}
fn admitRoots(pins: Pins, plan: *const range.Plan) !void {
    var memory_at: usize = 0;
    var range_at: usize = 0;
    for (pins.first_round) |entry| switch (entry.family) {
        .memory => {
            if (memory_at >= pins.claims.len or entry.index != memory_at or !std.meta.eql(entry.roots, pins.memory_roots[memory_at]) or !std.meta.eql(entry.instance_id, proof.instanceId(pins.claims[memory_at], @intCast(memory_at)))) return error.UntrustedV5WordRoots;
            memory_at += 1;
        },
        .memory_range => {
            if (range_at >= plan.shards.len or entry.index != range_at or !std.meta.eql(entry.roots, pins.range_roots[range_at]) or !std.meta.eql(entry.instance_id, table.instanceId(plan.digest, @intCast(range_at)))) return error.UntrustedV5WordRangeRoots;
            range_at += 1;
        },
        else => {},
    };
    if (memory_at != pins.claims.len or range_at != plan.shards.len) return error.UntrustedV5WordCensus;
}
fn put(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}
