//! Replayable v5 memory-only producer. It retains exact first-round roots and
//! small range counters, never sorted-memory traces or PCS schemes across the
//! prechallenge seal. Proofs are yielded one at a time to caller-owned storage.
const std = @import("std");
const core = @import("stwo_core");
const memory = @import("../air/block/memory_component.zig");
const trace_mod = @import("../air/block/memory_component_trace.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const instance = @import("block_memory_shared_instance_proof_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const batch = @import("block_v5_memory_batch_receiver_v1.zig");
const adapter_mod = @import("block_v5_initial_memory_receiver_v1.zig");
const v5 = @import("block_v5_source_seal_v1.zig");
const Digest = [32]u8;

pub const TraceSource = TraceSourceFor(false);
pub const CompactTraceSource = TraceSourceFor(true);
fn TraceSourceFor(comptime compact: bool) type {
    return struct {
        context: *anyopaque,
        /// Returns an owned sealed trace for exactly `index`; caller calls deinit.
        load: *const fn (context: *anyopaque, index: u32) anyerror!(if (compact) trace_mod.CompactTrace else trace_mod.Trace),
    };
}

pub const ProofSink = struct {
    context: *anyopaque,
    /// On success the sink takes ownership of the proof. On failure it must
    /// leave the passed proof owned by this producer for cleanup.
    memory: *const fn (context: *anyopaque, index: u32, proof: *instance.Proof) anyerror!void,
    table: *const fn (context: *anyopaque, index: u32, proof: *table.Proof) anyerror!void,
};

pub fn ForBackend(comptime Backend: type) type {
    return ForBackendMode(Backend, false);
}
pub fn ForCompactBackend(comptime Backend: type) type {
    return ForBackendMode(Backend, true);
}
fn ForBackendMode(comptime Backend: type, comptime compact: bool) type {
    return struct {
        const Self = @This();
        const Source = if (compact) CompactTraceSource else TraceSource;
        const Api = if (compact) instance.ForCompactBackend(Backend) else instance.ForBackend(Backend);
        claims: []memory.Claim,
        plan: shard_mod.Plan,
        memory_roots: [][2]Digest,
        table_roots: [][2]Digest,
        counters: []counter_mod.Counter,
        plan_digest: Digest,
        total_events: u64,
        config: core.pcs.PcsConfig,

        pub fn deinit(self: *Self, a: std.mem.Allocator) void {
            for (self.counters) |*counter| counter.deinit(a);
            a.free(self.counters);
            a.free(self.table_roots);
            a.free(self.memory_roots);
            self.plan.deinit(a);
            a.free(self.claims);
            self.* = undefined;
        }

        pub fn collect(a: std.mem.Allocator, source: Source, claims: []const memory.Claim, total_events: u64, config: core.pcs.PcsConfig) !Self {
            var plan = try shard_mod.plan(a, claims, total_events);
            errdefer plan.deinit(a);
            const owned_claims = try a.dupe(memory.Claim, claims);
            errdefer a.free(owned_claims);
            const memory_roots = try a.alloc([2]Digest, claims.len);
            errdefer a.free(memory_roots);
            const table_roots = try a.alloc([2]Digest, plan.shards.len);
            errdefer a.free(table_roots);
            const counters = try a.alloc(counter_mod.Counter, plan.shards.len);
            var initialized: usize = 0;
            errdefer {
                for (counters[0..initialized]) |*counter| counter.deinit(a);
                a.free(counters);
            }
            for (counters) |*counter| {
                counter.* = try counter_mod.Counter.init(a, .range_check_8_8);
                initialized += 1;
            }
            var shard_at: usize = 0;
            for (claims, 0..) |claim, index| {
                while (index >= @as(usize, plan.shards[shard_at].first_instance) + plan.shards[shard_at].instance_count)
                    shard_at += 1;
                var trace = try source.load(source.context, @intCast(index));
                defer trace.deinit();
                if (!trace.sealed or !std.meta.eql(trace.claim, claim))
                    return error.V5MemoryTraceReplayMismatch;
                const first = try Api.commitFirstRoundRootsOnly(a, &trace, &counters[shard_at], @intCast(index), config);
                memory_roots[index] = first.roots;
            }
            for (plan.shards, 0..) |shard, index| {
                var first = try table.ForBackend(Backend).commitFirstRound(a, &counters[index], shard, config);
                table_roots[index] = first.roots;
                first.deinit(a);
            }
            const digest = if (compact) try @import("block_v5_memory_compact_v1.zig").planDigest(owned_claims, memory_roots, table_roots, &plan) else try batch.memoryPlanDigest(owned_claims, memory_roots, table_roots, &plan);
            return .{
                .claims = owned_claims,
                .plan = plan,
                .memory_roots = memory_roots,
                .table_roots = table_roots,
                .counters = counters,
                .plan_digest = digest,
                .total_events = total_events,
                .config = config,
            };
        }

        pub fn memoryEntry(self: *const Self, index: usize) v5.Entry {
            return .{
                .family = .memory,
                .index = @intCast(index),
                .instance_id = if (compact) @import("block_v5_memory_compact_v1.zig").instanceId(self.claims[index], @intCast(index)) else batch.memoryInstanceId(self.claims[index], @intCast(index)),
                .roots = self.memory_roots[index],
            };
        }
        pub fn tableEntry(self: *const Self, index: usize) v5.Entry {
            return .{
                .family = .memory_range,
                .index = @intCast(index),
                .instance_id = batch.rangeShardId(self.plan.digest, @intCast(index)),
                .roots = self.table_roots[index],
            };
        }

        /// Pass 2 reopens every sorted trace, checks the exact first roots,
        /// proves under the independently reconstructed v5 seal, then yields
        /// each proof to the sink. No proof may select its own plan or seal.
        pub fn prove(self: *const Self, a: std.mem.Allocator, source: Source, sink: ProofSink, seal_pins: v5.Pins, entries: []const v5.Entry, expected_seal_digest: Digest, sealed: v5.Sealed) !void {
            if (!std.meta.eql(sealed.digest, expected_seal_digest) or
                !std.meta.eql(seal_pins.memory_plan_digest, self.plan_digest) or
                !std.meta.eql(seal_pins.config, self.config) or
                @as(usize, seal_pins.counts[@intFromEnum(v5.Family.memory) - 1]) != self.claims.len or
                @as(usize, seal_pins.counts[@intFromEnum(v5.Family.memory_range) - 1]) != self.plan.shards.len)
                return error.UntrustedV5MemoryProducerSeal;
            try sealed.require(seal_pins, entries);
            for (0..self.claims.len) |index| {
                const expected = self.memoryEntry(index);
                if (!hasEntry(entries, expected)) return error.UntrustedV5MemoryProducerRoot;
            }
            for (self.plan.shards, 0..) |_, index| {
                if (!hasEntry(entries, self.tableEntry(index)))
                    return error.UntrustedV5MemoryProducerRoot;
            }
            const adapter = adapter_mod.MemorySeal{
                .source = sealed,
                .memory_instance_count = @intCast(self.claims.len),
                .range_shard_digest = self.plan.digest,
            };
            for (self.claims, 0..) |claim, index| {
                var trace = try source.load(source.context, @intCast(index));
                defer trace.deinit();
                if (!trace.sealed or !std.meta.eql(trace.claim, claim))
                    return error.V5MemoryTraceReplayMismatch;
                var first = try Api.replayFirstRound(a, &trace, @intCast(index), self.memory_roots[index], self.config);
                defer first.deinit(a);
                var proof = try Api.prove(a, &first, &trace, adapter, @intCast(index), self.memory_roots[index]);
                errdefer proof.deinit(a);
                try sink.memory(sink.context, @intCast(index), &proof);
            }
            for (self.plan.shards, 0..) |shard, index| {
                var first = try table.ForBackend(Backend).replayFirstRound(a, &self.counters[index], shard, self.table_roots[index], self.config);
                defer first.deinit(a);
                var proof = try table.ForBackend(Backend).prove(a, &first, &self.counters[index], shard, adapter, self.table_roots[index]);
                errdefer proof.deinit(a);
                try sink.table(sink.context, @intCast(index), &proof);
            }
        }
    };
}

fn hasEntry(entries: []const v5.Entry, expected: v5.Entry) bool {
    for (entries) |entry| {
        if (entry.family == expected.family and entry.index == expected.index)
            return std.meta.eql(entry, expected);
    }
    return false;
}
