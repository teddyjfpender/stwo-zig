//! Bounded roots-only collection and two-root warm proving, using the same
//! immutable sorted trace source and one owned memory proof at a time.
const std = @import("std");
const core = @import("stwo_core");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Proof = @import("block_v5_ram_lanes_proof_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig").Trace;
const Range = @import("block_v5_range16_v1.zig");
const Table = @import("block_v5_range16_proof_v1.zig");
const Plan = @import("block_v5_ram_lanes_plan_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Boundary = @import("block_v5_proof_boundary_v1.zig").Boundary;
pub const Limits = struct {
    proof: Proof.Limits = .{},
    plan: Plan.Limits = .{},
    max_counter_bytes: usize = 64 << 20,
    max_resident_bytes: usize = 24 << 30,
};
pub const Source = struct {
    context: *anyopaque,
    /// Owned sealed trace, actual row_log. Only this one trace is live until
    /// its roots are collected or its warm proof has consumed the PCS.
    load: *const fn (*anyopaque, u32) anyerror!Trace,
    /// Sorted-record ingress for explicitly requested resident backends.
    load_resident: ?*const fn (*anyopaque, u32) anyerror!@import("block_v5_ram_lanes_resident_source_v1.zig").Lease = null,
    report_resident: ?*const fn (*anyopaque, @import("block_v5_ram_lanes_resident_source_v1.zig").Summary) anyerror!void = null,
};
pub const Sink = struct {
    context: *anyopaque,
    /// Success takes proof ownership; error leaves it with the producer.
    memory: *const fn (*anyopaque, u32, *Proof.Proof) anyerror!void,
    range: *const fn (*anyopaque, u32, *Table.Proof) anyerror!void,
};
var empty_context: u8 = 0;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Api = Proof.ForBackend(Backend);
        const Provider = Table.ForBackend(Backend);
        claims: []Protocol.Claim,
        pins: []Proof.Pin,
        plan: Range.Plan,
        range_roots: [][2][32]u8,
        counters: []Range.Counter,
        plan_digest: [32]u8,
        config: core.pcs.PcsConfig,
        limits: Limits,
        pub fn deinit(self: *Self, a: std.mem.Allocator) void {
            a.free(self.claims);
            a.free(self.pins);
            a.free(self.range_roots);
            for (self.counters) |*counter| counter.deinit();
            a.free(self.counters);
            self.plan.deinit(a);
            self.* = undefined;
        }
        pub fn collectEmpty(a: std.mem.Allocator, config: core.pcs.PcsConfig, limits: Limits) !Self {
            // Caller must first validate EOF and zero independent RW census.
            // No source callback/PCS/STARK is used for this typed absence.
            return collect(a, .{ .context = &empty_context, .load = emptyLoad }, &.{}, 0, config, limits);
        }
        fn emptyLoad(_: *anyopaque, _: u32) anyerror!Trace {
            return error.UnexpectedV5EmptyRamLoad;
        }
        pub fn collect(a: std.mem.Allocator, source: Source, claims: []const Protocol.Claim, total: u64, config: core.pcs.PcsConfig, limits: Limits) !Self {
            try @import("blake3_execution_protocol.zig").validateConfig(config);
            try limits.plan.require(claims.len, 0);
            if (claims.len == 0) {
                if (total != 0) return error.InvalidV5RamLanesCensus;
            } else try Protocol.admitSequence(claims, total);
            const resident = comptime @hasDecl(Backend, "RamLaneResident");
            if (comptime resident) {
                if (claims.len != 0 and source.load_resident == null) return error.MissingSecureRamResidentSource;
                for (claims) |claim| try Backend.RamLaneResident.requireRowLog(claim.row_log);
            }
            var session: if (resident) ?Backend.RamLaneResident.Session else void = if (comptime resident) (if (claims.len == 0) null else try Backend.RamLaneResident.Session.initFirstRound(a, .{ .max_resident_bytes = limits.max_resident_bytes })) else {};
            _ = &session;
            defer if (comptime resident) {
                if (session) |*value| value.deinit();
            };
            const owned_claims = try a.dupe(Protocol.Claim, claims);
            errdefer a.free(owned_claims);
            const pins = try a.alloc(Proof.Pin, claims.len);
            errdefer a.free(pins);
            var counters: std.ArrayList(Range.Counter) = .empty;
            errdefer {
                for (counters.items) |*counter| counter.deinit();
                counters.deinit(a);
            }
            for (claims, 0..) |claim, index| {
                try limits.proof.require(claim);
                var local = try Range.Counter.init(a);
                defer local.deinit();
                var first = if (comptime resident) blk: {
                    var lease = try source.load_resident.?(source.context, @intCast(index));
                    defer lease.deinit();
                    try lease.require(claim, limits.max_resident_bytes);
                    break :blk try Api.commitFirstRoundResident(a, &lease, &session.?, @intCast(index), config, limits.proof, &local);
                } else blk: {
                    var trace = try source.load(source.context, @intCast(index));
                    defer trace.deinit();
                    if (!std.meta.eql(trace.claim, claim)) return error.V5RamLanesTraceReplayMismatch;
                    break :blk try Api.commitFirstRoundWithCounter(a, &trace, @intCast(index), config, false, limits.proof, &local);
                };
                defer first.deinit(a);
                pins[index] = first.pin;
                if (counters.items.len == 0 or counters.items[counters.items.len - 1].total + local.total > Range.MAX_REQUESTS) {
                    try limits.plan.require(claims.len, counters.items.len + 1);
                    const bytes = try std.math.mul(usize, counters.items.len + 1, Range.TABLE_SIZE * @sizeOf(u32));
                    if (bytes > limits.max_counter_bytes) return error.V5RamLanesResourceLimit;
                    var fresh = try Range.Counter.init(a);
                    counters.append(a, fresh) catch |err| {
                        fresh.deinit();
                        return err;
                    };
                }
                try counters.items[counters.items.len - 1].merge(&local);
            }
            var plan = try Plan.rangePlan(a, pins, total, limits.plan);
            errdefer plan.deinit(a);
            if (plan.shards.len != counters.items.len) return error.InvalidV5RamLanesRangeRoster;
            const roots = try a.alloc([2][32]u8, plan.shards.len);
            errdefer a.free(roots);
            for (plan.shards, counters.items, roots) |shard, *counter, *root| {
                var first = if (comptime resident) try Provider.commitFirstRoundResident(a, &session.?, counter, shard, plan.digest, config) else try Provider.commitFirstRound(a, counter, shard, plan.digest, config, false);
                defer first.deinit(a);
                root.* = first.roots();
            }
            const digest = try Plan.digest(a, pins, total, roots, limits.plan);
            return .{ .claims = owned_claims, .pins = pins, .plan = plan, .range_roots = roots, .counters = try counters.toOwnedSlice(a), .plan_digest = digest, .config = config, .limits = limits };
        }
        pub fn memoryEntry(self: *const Self, index: usize) !Seal.Entry {
            if (index >= self.pins.len) return error.InvalidV5RamLanesCensus;
            return self.pins[index].entry();
        }
        pub fn rangeEntry(self: *const Self, index: usize) !Seal.Entry {
            if (index >= self.plan.shards.len or index >= self.range_roots.len) return error.InvalidV5RamLanesRangeRoster;
            return .{ .family = .memory_range, .index = @intCast(index), .instance_id = Table.instanceId(self.plan.digest, @intCast(index)), .roots = self.range_roots[index] };
        }
        pub fn prove(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, pins: Seal.Pins, entries: []const Seal.Entry, expected_seal_digest: [32]u8, sealed: Seal.Sealed) !void {
            return self.proveWithBoundary(a, source, sink, pins, entries, expected_seal_digest, sealed, null);
        }
        pub fn proveWithBoundary(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, pins: Seal.Pins, entries: []const Seal.Entry, expected_seal_digest: [32]u8, sealed: Seal.Sealed, boundary: ?Boundary) !void {
            try Boundary.require(boundary);
            try sealed.require(pins, entries);
            try Plan.admit(a, &self.plan, self.pins, self.plan.total_events, self.limits.plan);
            const digest = try Plan.digest(a, self.pins, self.plan.total_events, self.range_roots, self.limits.plan);
            if (!std.meta.eql(digest, self.plan_digest) or !std.meta.eql(digest, pins.memory_plan_digest) or
                !std.meta.eql(expected_seal_digest, sealed.digest) or sealed.register_custody_mode != 1 or
                !std.meta.eql(pins.config, self.config) or self.claims.len != self.pins.len or
                self.pins.len != sealed.memory_instance_count or self.plan.shards.len != self.counters.len or
                self.range_roots.len != pins.counts[@intFromEnum(Seal.Family.memory_range) - 1]) return error.UntrustedV5RamLanesStage;
            // Validate every requester and provider entry before producing
            // the first interaction or transferring any proof to a sink.
            for (self.pins, self.claims) |expected, claim| {
                if (!std.meta.eql(claim, expected.claim)) return error.UntrustedV5RamLanesStage;
                try Proof.admit(expected, sealed, pins, entries);
            }
            // Validate range entries before allocating/proving any interaction.
            for (self.plan.shards, 0..) |_, index| {
                const expected = try self.rangeEntry(index);
                var found = false;
                for (entries) |entry| if (entry.family == .memory_range and entry.index == index) {
                    if (!std.meta.eql(expected, entry)) return error.UntrustedV5RamLanesRangeRoster;
                    found = true;
                };
                if (!found) return error.UntrustedV5RamLanesRangeRoster;
            }
            if (self.claims.len == 0) return;
            if (comptime @hasDecl(Backend, "RamLaneResident")) {
                return self.proveResidentAdmitted(a, source, sink, pins, entries, sealed, boundary);
            }
            const challenges = try Protocol.Challenges.draw(a, sealed);
            var table = try @import("block_v5_ram_lanes_interaction_v1.zig").RangeInverses.init(a, challenges.range16);
            defer table.deinit();
            for (self.claims, self.pins, 0..) |claim, expected, index| {
                try Boundary.require(boundary);
                try Proof.admit(expected, sealed, pins, entries);
                var trace = try source.load(source.context, @intCast(index));
                defer trace.deinit();
                if (!std.meta.eql(trace.claim, claim)) return error.V5RamLanesTraceReplayMismatch;
                var first = try Api.commitFirstRound(a, &trace, @intCast(index), self.config, true, self.limits.proof);
                defer first.deinit(a);
                try first.require(a, &trace, expected);
                try Boundary.require(boundary);
                var proof = try Api.provePrepared(a, &first, &trace, expected, sealed, pins, entries, &table, self.limits.proof);
                errdefer proof.deinit(a);
                try sink.memory(sink.context, @intCast(index), &proof);
            }
            for (self.plan.shards, self.counters, self.range_roots) |shard, *counter, roots| {
                try Boundary.require(boundary);
                var first = try Provider.commitFirstRound(a, counter, shard, self.plan.digest, self.config, true);
                defer first.deinit(a);
                if (!std.meta.eql(first.roots(), roots)) return error.V5RamLanesRangeReplayMismatch;
                var proof = try Provider.provePrepared(a, &first, counter, shard, self.plan.digest, sealed, pins, entries, &table);
                errdefer proof.deinit(a);
                try sink.range(sink.context, shard.index, &proof);
            }
        }
        fn proveResidentAdmitted(self: *const Self, a: std.mem.Allocator, source: Source, sink: Sink, pins: Seal.Pins, entries: []const Seal.Entry, sealed: Seal.Sealed, boundary: ?Boundary) !void {
            const load_resident = source.load_resident orelse return error.MissingSecureRamResidentSource;
            const challenges = try Protocol.Challenges.draw(a, sealed);
            var session = try Backend.RamLaneResident.Session.init(a, challenges.range16.z, .{ .max_resident_bytes = self.limits.max_resident_bytes });
            defer session.deinit();
            for (self.claims, self.pins, 0..) |claim, expected, index| {
                try Boundary.require(boundary);
                var resident = try load_resident(source.context, @intCast(index));
                defer resident.deinit();
                try resident.require(claim, self.limits.max_resident_bytes);
                try Boundary.require(boundary);
                var proof = try Api.proveResident(a, &resident, &session, expected, sealed, pins, entries, self.limits.proof);
                errdefer proof.deinit(a);
                try sink.memory(sink.context, @intCast(index), &proof);
            }
            for (self.plan.shards, self.counters, self.range_roots) |shard, *counter, roots| {
                try Boundary.require(boundary);
                var proof = try Provider.proveResident(a, &session, counter, shard, self.plan.digest, roots, sealed, pins, entries);
                errdefer proof.deinit(a);
                try sink.range(sink.context, shard.index, &proof);
            }
            if (source.report_resident) |report| {
                const stats = session.statistics;
                try report(source.context, .{ .sorted_ingress_bytes = stats.sorted_ingress_bytes, .histogram_ingress_bytes = stats.histogram_ingress_bytes, .claim_readback_bytes = stats.claim_readback_bytes, .status_readback_bytes = stats.status_readback_bytes, .device_blit_bytes = stats.device_blit_bytes });
            }
        }
    };
}
