//! Replayable packed27 memory producer: roots-only first round, then
//! exact root/counter replay and one owned proof at a time under one B5SS.
const std = @import("std");
const core = @import("stwo_core");
const memory = @import("../air/block/memory_component.zig");
const trace = @import("../air/block/word_memory_trace_v5.zig");
const instance = @import("block_v5_word_memory_proof_v1.zig");
const table = @import("block_v5_range16_proof_v1.zig");
const range = @import("block_v5_range16_v1.zig");
const batch = @import("block_v5_word_memory_receiver_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const Boundary = @import("block_v5_proof_boundary_v1.zig").Boundary;
pub const Source = struct { context: *anyopaque, load: *const fn (*anyopaque, u32) anyerror!trace.Trace };
pub const Sink = struct {
    context: *anyopaque,
    /// Success transfers ownership; error leaves proof owned by producer.
    memory: *const fn (*anyopaque, u32, *instance.Proof) anyerror!void,
    range: *const fn (*anyopaque, u32, *table.Proof) anyerror!void,
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Api = instance.ForBackend(Backend);
        const Table = table.ForBackend(Backend);
        claims: []memory.Claim,
        counts: []u64,
        counter_digests: [][32]u8,
        memory_roots: [][2][32]u8,
        range_roots: [][2][32]u8,
        counters: []range.Counter,
        plan: range.Plan,
        plan_digest: [32]u8,
        config: core.pcs.PcsConfig,
        pub fn deinit(self: *Self, a: std.mem.Allocator) void {
            for (self.counters) |*counter| counter.deinit();
            a.free(self.counters);
            a.free(self.claims);
            a.free(self.counts);
            a.free(self.counter_digests);
            a.free(self.memory_roots);
            a.free(self.range_roots);
            self.plan.deinit(a);
            self.* = undefined;
        }
        pub fn collect(a: std.mem.Allocator, source: Source, claims: []const memory.Claim, total: u64, config: core.pcs.PcsConfig) !Self {
            try memory.admitSequence(claims, total);
            const owned = try a.dupe(memory.Claim, claims);
            errdefer a.free(owned);
            const counts = try a.alloc(u64, claims.len);
            errdefer a.free(counts);
            const digests = try a.alloc([32]u8, claims.len);
            errdefer a.free(digests);
            const roots = try a.alloc([2][32]u8, claims.len);
            errdefer a.free(roots);
            var counters: std.ArrayList(range.Counter) = .empty;
            errdefer {
                for (counters.items) |*counter| counter.deinit();
                counters.deinit(a);
            }
            for (claims, 0..) |claim, index| {
                var source_trace = try source.load(source.context, @intCast(index));
                defer source_trace.deinit();
                if (!std.meta.eql(source_trace.claim, claim)) return error.V5WordTraceReplayMismatch;
                var local = try range.Counter.init(a);
                defer local.deinit();
                var first = try Api.commitFirstRound(a, &source_trace, &local, @intCast(index), config, false);
                defer first.deinit(a);
                roots[index] = first.roots();
                counts[index] = first.request_count;
                digests[index] = first.counter_digest;
                if (counters.items.len == 0 or counters.items[counters.items.len - 1].total + local.total > range.MAX_REQUESTS) {
                    var fresh = try range.Counter.init(a);
                    errdefer fresh.deinit();
                    try counters.append(a, fresh);
                }
                try counters.items[counters.items.len - 1].merge(&local);
            }
            var plan = try range.plan(a, claims, counts, total);
            errdefer plan.deinit(a);
            if (plan.shards.len != counters.items.len) return error.InvalidV5WordShardCensus;
            const range_roots = try a.alloc([2][32]u8, plan.shards.len);
            errdefer a.free(range_roots);
            for (plan.shards, counters.items, range_roots) |shard, *counter, *root| {
                var first = try Table.commitFirstRound(a, counter, shard, plan.digest, config, false);
                defer first.deinit(a);
                root.* = first.roots();
            }
            const digest = try batch.planDigest(a, claims, roots, range_roots, &plan);
            return .{ .claims = owned, .counts = counts, .counter_digests = digests, .memory_roots = roots, .range_roots = range_roots, .counters = try counters.toOwnedSlice(a), .plan = plan, .plan_digest = digest, .config = config };
        }
        /// Actual empty family: the replay adapter checks the sorted stream
        /// is empty before calling this constructor. No PCS is fabricated.
        pub fn collectEmpty(a: std.mem.Allocator, config: core.pcs.PcsConfig) !Self {
            try @import("blake3_execution_protocol.zig").validateConfig(config);
            const claims = try a.alloc(memory.Claim, 0);
            errdefer a.free(claims);
            const counts = try a.alloc(u64, 0);
            errdefer a.free(counts);
            const digests = try a.alloc([32]u8, 0);
            errdefer a.free(digests);
            const roots = try a.alloc([2][32]u8, 0);
            errdefer a.free(roots);
            const range_roots = try a.alloc([2][32]u8, 0);
            errdefer a.free(range_roots);
            const counters = try a.alloc(range.Counter, 0);
            errdefer a.free(counters);
            const plan = try range.emptyPlan(a);
            return .{ .claims = claims, .counts = counts, .counter_digests = digests, .memory_roots = roots, .range_roots = range_roots, .counters = counters, .plan = plan, .plan_digest = @import("block_v5_empty_rw_memory_v1.zig").planDigest(), .config = config };
        }
        pub fn memoryEntry(self: *const Self, index: usize) seal.Entry {
            return .{ .family = .memory, .index = @intCast(index), .instance_id = instance.instanceId(self.claims[index], @intCast(index)), .roots = self.memory_roots[index] };
        }
        pub fn rangeEntry(self: *const Self, index: usize) seal.Entry {
            return .{ .family = .memory_range, .index = @intCast(index), .instance_id = table.instanceId(self.plan.digest, @intCast(index)), .roots = self.range_roots[index] };
        }
        pub fn prove(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, pins: seal.Pins, entries: []const seal.Entry, expected_digest: [32]u8, sealed: seal.Sealed) !void {
            return self.proveWithBoundary(a, source, sink, pins, entries, expected_digest, sealed, null);
        }
        pub fn proveWithBoundary(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, pins: seal.Pins, entries: []const seal.Entry, expected_digest: [32]u8, sealed: seal.Sealed, boundary: ?Boundary) !void {
            try Boundary.require(boundary);
            if (!std.meta.eql(sealed.digest, expected_digest) or !std.meta.eql(pins.memory_plan_digest, self.plan_digest) or !std.meta.eql(pins.config, self.config)) return error.UntrustedV5WordProducerSeal;
            try sealed.require(pins, entries);
            if (self.claims.len == 0) {
                if (sealed.register_custody_mode != 1 or self.counts.len != 0 or self.counters.len != 0 or
                    self.memory_roots.len != 0 or self.range_roots.len != 0 or self.plan.total_events != 0 or
                    self.plan.shards.len != 0 or sealed.memory_instance_count != 0 or
                    pins.counts[@intFromEnum(seal.Family.memory_range) - 1] != 0 or
                    !std.meta.eql(self.plan_digest, @import("block_v5_empty_rw_memory_v1.zig").planDigest())) return error.UntrustedV5EmptyRwPlan;
                return;
            }
            const challenges = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, sealed);
            var range_inverses = try @import("block_v5_word_memory_interaction_v1.zig").RangeInverses.init(a, challenges.range16);
            defer range_inverses.deinit();
            for (self.claims, 0..) |claim, index| {
                try Boundary.require(boundary);
                var source_trace = try source.load(source.context, @intCast(index));
                defer source_trace.deinit();
                if (!std.meta.eql(source_trace.claim, claim)) return error.V5WordTraceReplayMismatch;
                var local = try range.Counter.init(a);
                defer local.deinit();
                var first = try Api.commitFirstRound(a, &source_trace, &local, @intCast(index), self.config, true);
                defer first.deinit(a);
                if (!std.meta.eql(first.roots(), self.memory_roots[index]) or !std.meta.eql(first.counter_digest, self.counter_digests[index]) or first.request_count != self.counts[index]) return error.V5WordCommitmentReplayMismatch;
                try Boundary.require(boundary);
                var proof = try Api.provePrepared(a, &first, &source_trace, sealed, pins, entries, @intCast(index), &range_inverses);
                errdefer proof.deinit(a);
                try sink.memory(sink.context, @intCast(index), &proof);
            }
            for (self.plan.shards, self.counters, 0..) |shard, *counter, index| {
                try Boundary.require(boundary);
                var first = try Table.commitFirstRound(a, counter, shard, self.plan.digest, self.config, true);
                defer first.deinit(a);
                if (!std.meta.eql(first.roots(), self.range_roots[index])) return error.V5WordRangeCommitmentReplayMismatch;
                try Boundary.require(boundary);
                var proof = try Table.provePrepared(a, &first, counter, shard, self.plan.digest, sealed, pins, entries, &range_inverses);
                errdefer proof.deinit(a);
                try sink.range(sink.context, shard.index, &proof);
            }
        }
    };
}
