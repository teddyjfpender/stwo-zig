//! Block-wide v5 sorted-memory receiver. Independently sized instance claims,
//! exact range shards, and public initial sources share one v5 transcript.
//! Execution/ROM closure and recursive block authority remain separate.
const std = @import("std");
const core = @import("stwo_core");
const memory = @import("../air/block/memory_component.zig");
const transition = @import("../air/block/memory_transition.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");
const instance = @import("block_memory_shared_instance_proof_v2.zig");
const old_memory = @import("block_memory_proof_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const sources = @import("block_v5_initial_sources_v1.zig");
const source_receiver = @import("block_v5_initial_source_receiver_v1.zig");
const v5 = @import("block_v5_source_seal_v1.zig");
const adapter_mod = @import("block_v5_initial_memory_receiver_v1.zig");
const Digest = [32]u8;
const Q = core.fields.qm31.QM31;

pub const Pins = struct {
    source: sources.Pins,
    seal: v5.Pins,
    expected_seal_digest: Digest,
    first_round: []const v5.Entry,
    claims: []const memory.Claim,
    memory_roots: []const [2]Digest,
    range_roots: []const [2]Digest,
    expected_total_events: u64,
};

/// The loader transfers each proof to the receiver on demand. A file-backed
/// implementation can decode and release one STARK at a time; proof-carried
/// claims remain unauthoritative until each fresh PCS/FRI check succeeds.
pub const ProofLoader = struct {
    context: *anyopaque,
    take_memory: *const fn (context: *anyopaque, index: u32) anyerror!instance.Proof,
    take_table: *const fn (context: *anyopaque, index: u32) anyerror!table.Proof,
};

pub const ScopedMemory = struct {
    sorted_memory_initial_range_verified: void = {},
    event_count: u64,
    /// Open block transition claim from freshly verified sorted proofs.
    transition_sum: Q,
    memory_instances: u32,
    range_shards: u32,
    first_touch_count: u64,
    register_touches: u64,
    input_touches: u64,
    rw_touches: u64,
    initial_rw_root: Digest,
    seal_digest: Digest,
    memory_plan_digest: Digest,
};

pub fn verify(comptime Backend: type, a: std.mem.Allocator, pins: Pins, public_input: []const u8, files: sources.Files, loader: ProofLoader, sealed: v5.Sealed) !ScopedMemory {
    return verifyMode(Backend, false, a, pins, public_input, files, loader, sealed);
}
pub fn verifyCompact(comptime Backend: type, a: std.mem.Allocator, pins: Pins, public_input: []const u8, files: sources.Files, loader: ProofLoader, sealed: v5.Sealed) !ScopedMemory {
    return verifyMode(Backend, true, a, pins, public_input, files, loader, sealed);
}
fn verifyMode(comptime Backend: type, comptime compact: bool, a: std.mem.Allocator, pins: Pins, public_input: []const u8, files: sources.Files, loader: ProofLoader, sealed: v5.Sealed) !ScopedMemory {
    const Api = if (compact) instance.ForCompactBackend(Backend) else instance.ForBackend(Backend);
    if (pins.claims.len == 0 or pins.claims.len != pins.memory_roots.len or
        pins.claims.len > std.math.maxInt(u32) or
        !std.meta.eql(sealed.digest, pins.expected_seal_digest))
        return error.UntrustedV5MemoryBatchPins;
    var plan = try shard_mod.plan(a, pins.claims, pins.expected_total_events);
    defer plan.deinit(a);
    if (plan.shards.len != pins.range_roots.len or plan.shards.len > std.math.maxInt(u32) or
        @as(usize, pins.seal.counts[@intFromEnum(v5.Family.memory) - 1]) != pins.claims.len or
        @as(usize, pins.seal.counts[@intFromEnum(v5.Family.memory_range) - 1]) != plan.shards.len)
        return error.InvalidV5MemoryBatchCensus;
    const plan_digest = if (compact) try @import("block_v5_memory_compact_v1.zig").planDigest(pins.claims, pins.memory_roots, pins.range_roots, &plan) else try memoryPlanDigest(pins.claims, pins.memory_roots, pins.range_roots, &plan);
    if (!std.meta.eql(plan_digest, pins.seal.memory_plan_digest))
        return error.UntrustedV5MemoryPlan;
    try sealed.require(pins.seal, pins.first_round);
    try admitRoots(compact, pins, &plan);
    const source_claim = try source_receiver.check(a, pins.source, public_input, files, pins.seal, pins.first_round, sealed);
    if (source_claim.first_touch_count > pins.expected_total_events)
        return error.InvalidV5FirstTouchCensus;
    const adapter = adapter_mod.MemorySeal{
        .source = sealed,
        .memory_instance_count = @intCast(pins.claims.len),
        .range_shard_digest = plan.digest,
    };
    const receipts = try a.alloc(old_memory.VerifiedMemoryReceipt, pins.claims.len);
    defer a.free(receipts);
    const requests = try a.alloc(range.Claims, pins.claims.len);
    defer a.free(requests);
    var sorted_initial = Q.zero();
    var sorted_transition = Q.zero();
    for (pins.claims, pins.memory_roots, 0..) |claim, roots, index| {
        const proof = try loader.take_memory(loader.context, @intCast(index));
        const verified = try Api.verifyOwned(a, proof, claim, adapter, @intCast(index), roots, pins.seal.config);
        receipts[index] = verified.memory;
        requests[index] = verified.range_claims;
        sorted_initial = sorted_initial.add(verified.memory.relation.initial_sum);
        sorted_transition = sorted_transition.add(verified.memory.relation.transition_sum);
    }
    try old_memory.admitMemoryReceipts(a, adapter, receipts, pins.expected_total_events);
    const table_receipts = try a.alloc(table.VerifiedTableReceipt, plan.shards.len);
    defer a.free(table_receipts);
    for (plan.shards, pins.range_roots, 0..) |shard, roots, index| {
        const proof = try loader.take_table(loader.context, @intCast(index));
        table_receipts[index] = try table.ForBackend(Backend).verifyOwned(a, proof, shard, adapter, roots, pins.seal.config);
    }
    try table.closed(&plan, adapter, table_receipts, requests);
    if (!sorted_initial.add(source_claim.initial_sum).eql(Q.zero()))
        return error.UnclosedV5InitialRelation;
    return .{
        .event_count = pins.expected_total_events,
        .transition_sum = sorted_transition,
        .memory_instances = @intCast(pins.claims.len),
        .range_shards = @intCast(plan.shards.len),
        .first_touch_count = source_claim.first_touch_count,
        .register_touches = source_claim.register_touches,
        .input_touches = source_claim.input_touches,
        .rw_touches = source_claim.rw_touches,
        .initial_rw_root = pins.source.initial_rw_root,
        .seal_digest = sealed.digest,
        .memory_plan_digest = plan_digest,
    };
}

fn admitRoots(comptime compact: bool, pins: Pins, plan: *const shard_mod.Plan) !void {
    var memory_at: usize = 0;
    var table_at: usize = 0;
    for (pins.first_round) |entry| switch (entry.family) {
        .memory => {
            if (memory_at >= pins.claims.len or @as(usize, entry.index) != memory_at or
                !std.meta.eql(entry.roots, pins.memory_roots[memory_at]) or
                !std.meta.eql(entry.instance_id, if (compact) @import("block_v5_memory_compact_v1.zig").instanceId(pins.claims[memory_at], @intCast(memory_at)) else memoryInstanceId(pins.claims[memory_at], @intCast(memory_at))))
                return error.UntrustedV5MemoryFirstRound;
            memory_at += 1;
        },
        .memory_range => {
            if (table_at >= plan.shards.len or @as(usize, entry.index) != table_at or
                !std.meta.eql(entry.roots, pins.range_roots[table_at]) or
                !std.meta.eql(entry.instance_id, rangeShardId(plan.digest, @intCast(table_at))))
                return error.UntrustedV5MemoryRangeFirstRound;
            table_at += 1;
        },
        else => {},
    };
    if (memory_at != pins.claims.len or table_at != plan.shards.len)
        return error.InvalidV5MemoryBatchCensus;
}

/// Canonical prechallenge digest of every independently sized claim, first
/// root pair, and the exact field-safe shared table shard plan/root pair.
pub fn memoryPlanDigest(claims: []const memory.Claim, memory_roots: []const [2]Digest, range_roots: []const [2]Digest, plan: *const shard_mod.Plan) !Digest {
    if (claims.len == 0 or claims.len != memory_roots.len or range_roots.len != plan.shards.len or
        claims.len > std.math.maxInt(u32) or range_roots.len > std.math.maxInt(u32))
        return error.InvalidV5MemoryPlanCensus;
    try shard_mod.admit(plan, claims);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/memory-plan/v1\x00");
    putWide(&hash, plan.total_events);
    putWord(&hash, @intCast(claims.len));
    putWord(&hash, @intCast(range_roots.len));
    hash.update(&plan.digest);
    for (claims, memory_roots) |claim, roots| {
        putClaim(&hash, claim);
        hash.update(&roots[0]);
        hash.update(&roots[1]);
    }
    for (range_roots) |roots| {
        hash.update(&roots[0]);
        hash.update(&roots[1]);
    }
    return hash.finalResult();
}

pub fn memoryInstanceId(claim: memory.Claim, index: u32) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/memory-instance/v1\x00");
    putWord(&hash, index);
    putClaim(&hash, claim);
    return hash.finalResult();
}
pub fn rangeShardId(plan_digest: Digest, index: u32) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/memory-range-shard/v1\x00");
    hash.update(&plan_digest);
    putWord(&hash, index);
    return hash.finalResult();
}
fn putClaim(hash: *std.crypto.hash.sha2.Sha256, claim: memory.Claim) void {
    putWide(hash, claim.first_row);
    putWide(hash, claim.total_rows);
    putWord(hash, claim.rows);
    putWord(hash, claim.log_size);
    putTransition(hash, claim.first);
    putTransition(hash, claim.last);
    putWord(hash, @intFromBool(claim.preceding != null));
    if (claim.preceding) |prior| putTransition(hash, prior);
}
fn putTransition(hash: *std.crypto.hash.sha2.Sha256, value: transition.Transition) void {
    putWord(hash, value.space);
    putWord(hash, value.address);
    putWide(hash, value.clock);
    putWord(hash, value.before);
    putWord(hash, value.after);
}
fn putWord(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}
fn putWide(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}
