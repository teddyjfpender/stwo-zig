//! Versioned packed27 sorted proof. Returned claims stay open until all range,
//! predecessor, initial-source, endpoint and execution buses close freshly.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const memory = @import("../air/block/memory_component.zig");
const trace_mod = @import("../air/block/word_memory_trace_v5.zig");
const fixed_mod = @import("../air/block/word_memory_fixed_v5.zig");
const air = @import("../air/block/word_memory_v5.zig");
const inter = @import("block_v5_word_memory_interaction_v1.zig");
const range = @import("block_v5_range16_v1.zig");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const component = @import("block_v5_word_memory_component_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const pcs = @import("block_v5_word_pcs_v1.zig");
const canonical = @import("../recursion/air/universal_provider_relations.zig");
const Q = core.fields.qm31.QM31;
pub const Proof = struct {
    stark: suite.Proof,
    claim: inter.Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const OpenReceipt = struct { claim: memory.Claim, sums: inter.Claim, roots: [2][32]u8, sealed_digest: [32]u8 };
pub fn collectCounter(trace: *const trace_mod.Trace, counter: *range.Counter) !u64 {
    if (!trace.sealed) return error.InvalidV5WordPhase;
    const start = counter.total;
    for (0..trace.claim.rows) |logical| for (air.rangePoints(trace.fixedAt(logical), trace.rowAt(logical))) |point| {
        if (point.weight.isZero()) continue;
        if (!point.weight.eql(Q.one())) return error.InvalidV5WordMultiplicity;
        const limbs = point.value.toM31Array();
        for (limbs[1..]) |limb| if (!limb.isZero()) return error.InvalidV5WordValue;
        try counter.add(limbs[0].toU32());
    };
    return counter.total - start;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = pcs.For(Backend, component.Spec);
        pub const FirstRound = struct {
            pcs_first: Api.First,
            counter_digest: [32]u8,
            request_count: u64,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                self.pcs_first.deinit(a);
                self.* = undefined;
            }
            pub fn roots(self: *const FirstRound) [2][32]u8 {
                return self.pcs_first.roots;
            }
        };
        pub fn commitFirstRound(a: std.mem.Allocator, trace: *const trace_mod.Trace, shard: *range.Counter, index: u32, config: core.pcs.PcsConfig, retain: bool) !FirstRound {
            var local = try range.Counter.init(a);
            defer local.deinit();
            const count = try collectCounter(trace, &local);
            try shard.merge(&local);
            var fixed: [component.Spec.FIXED_COUNT]pcs.Column = undefined;
            var main: [air.Layout.len]pcs.Column = undefined;
            for (&fixed, 0..) |*column, i| column.* = .{ .log_size = trace.claim.log_size, .values = trace.fixedColumn(i) };
            for (&main, 0..) |*column, i| column.* = .{ .log_size = trace.claim.log_size, .values = trace.mainColumn(i) };
            return .{ .pcs_first = try Api.commit(a, &fixed, &main, firstChannel(trace.claim, index), config, retain), .counter_digest = local.digest(), .request_count = count };
        }
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, trace: *const trace_mod.Trace, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, index: u32) !Proof {
            try admit(sealed, pins, entries, trace.claim, index, first.roots());
            const challenges = try protocol.Challenges.draw(a, sealed);
            var table = try inter.RangeInverses.init(a, challenges.range16);
            defer table.deinit();
            return provePrepared(a, first, trace, sealed, pins, entries, index, &table);
        }
        pub fn provePrepared(a: std.mem.Allocator, first: *FirstRound, trace: *const trace_mod.Trace, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, index: u32, table: *const inter.RangeInverses) !Proof {
            try admit(sealed, pins, entries, trace.claim, index, first.roots());
            var local = try range.Counter.init(a);
            defer local.deinit();
            const challenges = try protocol.Challenges.draw(a, sealed);
            var generated = try inter.generatePrepared(a, trace, &challenges, &local, table);
            defer generated.deinit(a);
            if (generated.claim.range_count != first.request_count or !std.meta.eql(local.digest(), first.counter_digest)) return error.V5WordCounterReplayMismatch;
            var columns: [inter.COLUMN_COUNT]pcs.Column = undefined;
            for (&columns, generated.columns) |*column, values| column.* = .{ .log_size = trace.claim.log_size, .values = values };
            const spec = component.Spec{ .claim = trace.claim, .interaction_claim = generated.claim, .challenges = &challenges, .endpoint_constants = try inter.publicEndpoints(trace.claim, &challenges) };
            return .{ .stark = try Api.prove(a, &first.pcs_first, spec, trace.claim.log_size, &columns, try proofChannel(a, sealed, trace.claim, index, generated.claim)), .claim = generated.claim };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, claim: memory.Claim, sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, index: u32, roots: [2][32]u8) !OpenReceipt {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            try admit(sealed, pins, entries, claim, index, roots);
            try validateClaim(proof.claim, claim);
            const challenges = try protocol.Challenges.draw(a, sealed);
            var trusted = try fixed_mod.Trace.init(a, claim);
            defer trusted.deinit();
            var fixed: [component.Spec.FIXED_COUNT]pcs.Column = undefined;
            for (&fixed, 0..) |*column, i| column.* = .{ .log_size = claim.log_size, .values = trusted.column(i) };
            const spec = component.Spec{ .claim = claim, .interaction_claim = proof.claim, .challenges = &challenges, .endpoint_constants = try inter.publicEndpoints(claim, &challenges) };
            const result = OpenReceipt{ .claim = claim, .sums = proof.claim, .roots = roots, .sealed_digest = sealed.digest };
            const transcript = try proofChannel(a, sealed, claim, index, proof.claim);
            owns = false;
            try Api.verifyOwned(a, proof.stark, spec, claim.log_size, &fixed, roots, pins.config, firstChannel(claim, index), transcript);
            return result;
        }
    };
}
fn admit(sealed: seal.Sealed, pins: seal.Pins, entries: []const seal.Entry, claim: memory.Claim, index: u32, roots: [2][32]u8) !void {
    try air.validatePublicClaim(claim);
    try sealed.require(pins, entries);
    for (entries) |entry| if (entry.family == .memory and entry.index == index) {
        if (!std.meta.eql(entry.roots, roots) or !std.meta.eql(entry.instance_id, instanceId(claim, index))) return error.UntrustedV5WordMemory;
        return;
    };
    return error.MissingV5WordMemory;
}
pub fn instanceId(claim: memory.Claim, index: u32) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/word-memory-instance/v4\x00");
    hash.update(&protocol.abiId());
    hash.update(&@import("block_v5_memory_batch_receiver_v1.zig").memoryInstanceId(claim, index));
    return hash.finalResult();
}
fn validateClaim(value: inter.Claim, claim: memory.Claim) !void {
    for ([_]Q{ value.transition_sum, value.link_sum, value.initial_sum, value.endpoint_sum, value.register_endpoint_sum } ++ value.range_sums) |sum| if (!canonical.secureIsCanonical(&sum)) return error.InvalidV5WordClaim;
    const bounds = air.rangeCountBounds(claim);
    if (value.register_endpoint_count > 32 or value.endpoint_count > @as(u64, claim.rows) + 1 or value.endpoint_count > claim.total_rows or value.range_count < bounds.minimum or value.range_count > bounds.maximum or value.range_count >= core.fields.m31.Modulus) return error.InvalidV5WordClaim;
}
fn firstChannel(claim: memory.Claim, index: u32) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ protocol.TAG, protocol.VERSION, air.Layout.len });
    @import("block_memory_proof_v2.zig").mixStatement(&channel, claim, index);
    return channel;
}
fn proofChannel(a: std.mem.Allocator, sealed: seal.Sealed, claim: memory.Claim, index: u32, value: inter.Claim) !suite.Channel {
    var channel = sealed.sharedChannel();
    _ = try protocol.Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ protocol.TAG, protocol.VERSION, air.Layout.len });
    @import("block_memory_proof_v2.zig").mixStatement(&channel, claim, index);
    for ([_]Q{ value.transition_sum, value.link_sum, value.initial_sum, value.endpoint_sum, value.register_endpoint_sum } ++ value.range_sums) |sum| for (sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    channel.mixU64(value.endpoint_count);
    channel.mixU64(value.register_endpoint_count);
    channel.mixU64(value.range_count);
    return channel;
}
