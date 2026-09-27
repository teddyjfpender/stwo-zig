//! Opt-in compact v5 producer from the immutable sorted block Replay. A cheap
//! census pass derives exact variable-size claims; roots/counters and proofs
//! then stream one sixty-six-column trace at a time through the shared API.
const std = @import("std");
const core = @import("stwo_core");
const original = @import("block_v5_memory_replay_adapter_v1.zig");
const artifact = @import("block_v5_memory_batch_artifact_v1.zig");
const word_artifact = @import("block_v5_word_memory_artifact_v1.zig");
const word_trace = @import("../air/block/word_memory_trace_v5.zig");
const memory = @import("../air/block/memory_component.zig");
const trace = @import("../air/block/memory_component_trace.zig");
const transition = @import("../air/block/memory_transition.zig");
const instance = @import("../air/block/memory_instance.zig");
const planner = @import("../air/block/memory_size_plan.zig");
const seal = @import("block_v5_source_seal_v1.zig");
pub fn ForBackend(comptime Backend: type) type {
    return ForTrace(Backend, false);
}
pub fn ForPackedBackend(comptime Backend: type) type {
    return ForTrace(Backend, true);
}
fn ForTrace(comptime Backend: type, comptime word_mode: bool) type {
    const Api = if (word_mode) word_artifact.ForBackend(Backend) else artifact.ForCompactBackend(Backend);
    const Sink = if (word_mode) word_artifact.Sink else artifact.ProofSink;
    const Sequential = SequentialFor(word_mode);
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        first: Api,
        capacities: []u32,
        minimum_log_size: u32,
        /// Owns the sequential reader at a stable address. Returned traces
        /// belong to the caller; the lease retains no trace or PCS columns.
        /// The collected replay metadata must outlive this lease.
        pub const TraceLease = struct {
            a: std.mem.Allocator,
            state: *Sequential,
            pub fn source(self: *TraceLease) (if (word_mode) word_artifact.Source else artifact.CompactTraceSource) {
                return self.state.interface();
            }
            pub fn requireFinished(self: *const TraceLease) !void {
                if (!self.state.finished) return error.IncompleteV5CompactReplay;
            }
            pub fn deinit(self: *TraceLease) void {
                self.state.deinit();
                self.a.destroy(self.state);
                self.* = undefined;
            }
        };
        pub fn openTraceSource(self: *const Self, sorted: original.SortedSource) !TraceLease {
            const state = try self.a.create(Sequential);
            state.* = .{ .a = self.a, .sorted = sorted, .claims = self.first.claims, .capacities = self.capacities, .total = if (word_mode) self.first.plan.total_events else self.first.total_events, .minimum_log = self.minimum_log_size };
            if (word_mode and self.first.claims.len == 0) {
                errdefer self.a.destroy(state);
                if (state.total != 0 or self.capacities.len != 0) return error.UntrustedV5EmptyRwPlan;
                var reader = try sorted.open(sorted.context);
                defer reader.deinit();
                if (try reader.next() != null) return error.NonemptyV5EmptyRwReplay;
                state.finished = true;
            }
            return .{ .a = self.a, .state = state };
        }
        pub fn deinit(self: *Self) void {
            self.first.deinit(self.a);
            self.a.free(self.capacities);
            self.* = undefined;
        }
        pub fn collect(a: std.mem.Allocator, sorted: original.SortedSource, total: u64, maximum_log: u32, minimum_log: u32, config: core.pcs.PcsConfig) !Self {
            if (word_mode and maximum_log > 24) return error.InvalidMemorySizePlan;
            if (word_mode and total == 0) {
                if (minimum_log < 8 or maximum_log < minimum_log) return error.InvalidMemorySizePlan;
                var reader = try sorted.open(sorted.context);
                defer reader.deinit();
                if (try reader.next() != null) return error.NonemptyV5EmptyRwReplay;
                var first = try Api.collectEmpty(a, config);
                errdefer first.deinit(a);
                return .{ .a = a, .first = first, .capacities = try a.alloc(u32, 0), .minimum_log_size = minimum_log };
            }
            var selected = try planner.select(a, total, minimum_log, maximum_log);
            errdefer selected.deinit();
            var reader = try sorted.open(sorted.context);
            defer reader.deinit();
            var partitioner = try instance.Partitioner.initPlanned(&reader, total, selected.capacities);
            var claims: std.ArrayList(memory.Claim) = .empty;
            defer claims.deinit(a);
            var sink_context: u8 = 0;
            while (!partitioner.finished) {
                const preceding = partitioner.previous;
                const capacity = try partitioner.currentCapacity();
                const summary = (try partitioner.next(.{ .context = &sink_context, .append = ignore })) orelse return error.IncompleteV5CompactCensus;
                try claims.append(a, try memory.Claim.fromSummary(summary, total, @max(minimum_log, std.math.log2_int(u32, capacity)), preceding));
            }
            var source = Sequential{ .a = a, .sorted = sorted, .claims = claims.items, .capacities = selected.capacities, .total = total, .minimum_log = minimum_log };
            defer source.deinit();
            var first = try Api.collect(a, source.interface(), claims.items, total, config);
            errdefer first.deinit(a);
            if (!source.finished) return error.IncompleteV5CompactReplay;
            const capacities = selected.capacities;
            selected = undefined;
            return .{ .a = a, .first = first, .capacities = capacities, .minimum_log_size = minimum_log };
        }
        pub fn prove(self: *const Self, sorted: original.SortedSource, sink: Sink, pins: seal.Pins, entries: []const seal.Entry, expected_seal: [32]u8, sealed: seal.Sealed) !void {
            var lease = try self.openTraceSource(sorted);
            defer lease.deinit();
            try self.first.prove(self.a, lease.source(), sink, pins, entries, expected_seal, sealed);
            try lease.requireFinished();
        }
    };
}
fn ignore(_: *anyopaque, _: transition.Transition, _: ?@import("../air/block/memory_order.zig").Row) anyerror!void {}
fn SequentialFor(comptime word_mode: bool) type {
    return struct {
        const Self = @This();
        const Trace = if (word_mode) word_trace.Trace else trace.CompactTrace;
        const Source = if (word_mode) word_artifact.Source else artifact.CompactTraceSource;
        a: std.mem.Allocator,
        sorted: original.SortedSource,
        claims: []const memory.Claim,
        capacities: []const u32,
        total: u64,
        minimum_log: u32,
        reader: ?transition.Reader = null,
        partitioner: ?instance.Partitioner = null,
        next: u32 = 0,
        finished: bool = false,
        fn deinit(self: *Self) void {
            if (self.reader) |*reader| reader.deinit();
        }
        fn interface(self: *Self) Source {
            return .{ .context = self, .load = load };
        }
        fn load(context: *anyopaque, index: u32) anyerror!Trace {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.finished or index != self.next or index >= self.claims.len) return error.InvalidV5CompactReplayOrder;
            if (self.reader == null) {
                self.reader = try self.sorted.open(self.sorted.context);
                self.partitioner = try instance.Partitioner.initPlanned(&self.reader.?, self.total, self.capacities);
            }
            var result = (try Trace.nextFromPartitioner(self.a, &self.partitioner.?, self.minimum_log)) orelse return error.IncompleteV5CompactReplay;
            errdefer result.deinit();
            if (!std.meta.eql(result.claim, self.claims[index])) return error.V5MemoryTraceReplayMismatch;
            self.next += 1;
            if (self.next == self.claims.len) {
                if (!self.partitioner.?.finished or self.partitioner.?.emitted != self.total) return error.IncompleteV5CompactReplay;
                self.reader.?.deinit();
                self.reader = null;
                self.partitioner = null;
                self.finished = true;
            }
            return result;
        }
    };
}
