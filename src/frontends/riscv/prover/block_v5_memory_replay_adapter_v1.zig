//! Opt-in v5 memory producer over the block's immutable sorted Replay. This
//! transfers the existing count-first, roots-only first pass into a v5 plan,
//! then reopens the same sorted run for bounded v5 proof production.
const std = @import("std");
const core = @import("stwo_core");
const legacy = @import("block_memory_batch_produce_v2.zig");
const replay_mod = @import("block_memory_replay.zig");
const transition = @import("../air/block/memory_transition.zig");
const partition = @import("../air/block/memory_instance.zig");
const trace_mod = @import("../air/block/memory_component_trace.zig");
const artifact = @import("block_v5_memory_batch_artifact_v1.zig");
const batch = @import("block_v5_memory_batch_receiver_v1.zig");
const v5 = @import("block_v5_source_seal_v1.zig");

pub const SortedSource = legacy.SortedSource;

pub fn fromReplay(replay: *replay_mod.Replay) SortedSource {
    return .{ .context = replay, .open = reopenReplay };
}
fn reopenReplay(context: *anyopaque) anyerror!transition.Reader {
    const replay: *replay_mod.Replay = @ptrCast(@alignCast(context));
    return replay.reopenSortedTransitions();
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        first: artifact.ForBackend(Backend),
        capacities: []u32,
        minimum_log_size: u32,

        pub fn deinit(self: *Self) void {
            self.first.deinit(self.a);
            self.a.free(self.capacities);
            self.* = undefined;
        }

        /// One real sorted replay pass; first-round roots and counters are
        /// retained, while each trace and PCS scheme is promptly released.
        pub fn collect(a: std.mem.Allocator, source: SortedSource, total_events: u64, maximum_log_size: u32, minimum_log_size: u32, config: core.pcs.PcsConfig) !Self {
            if (maximum_log_size < minimum_log_size or maximum_log_size > 30)
                return error.InvalidMemorySizePlan;
            const capacity: u32 = @as(u32, 1) << @intCast(maximum_log_size);
            var first = try legacy.collectFirstPass(Backend, a, source, total_events, capacity, minimum_log_size, config);
            errdefer first.deinit();
            const plan_digest = try batch.memoryPlanDigest(first.claims, first.memory_roots, first.table_roots, &first.plan);
            const result = Self{
                .a = a,
                .first = .{
                    .claims = first.claims,
                    .plan = first.plan,
                    .memory_roots = first.memory_roots,
                    .table_roots = first.table_roots,
                    .counters = first.counters,
                    .plan_digest = plan_digest,
                    .total_events = first.total_events,
                    .config = config,
                },
                .capacities = first.capacity_plan,
                .minimum_log_size = first.minimum_log_size,
            };
            // Ownership of every first-pass buffer moved into `result`.
            first = undefined;
            return result;
        }

        /// The producer's seal and root roster are independently supplied by
        /// the caller. Sequential reopening checks the exact partition and
        /// predecessor context before each per-instance STARK is emitted.
        pub fn prove(self: *const Self, source: SortedSource, sink: artifact.ProofSink, pins: v5.Pins, entries: []const v5.Entry, expected_seal_digest: [32]u8, sealed: v5.Sealed) !void {
            var traces = Sequential{
                .a = self.a, .sorted = source, .capacities = self.capacities,
                .claims = self.first.claims, .total_events = self.first.total_events,
                .minimum_log_size = self.minimum_log_size,
            };
            defer traces.deinit();
            try self.first.prove(self.a, traces.interface(), sink, pins, entries, expected_seal_digest, sealed);
            if (!traces.finished) return error.IncompleteV5SortedReplay;
        }
    };
}

const Sequential = struct {
    a: std.mem.Allocator,
    sorted: SortedSource,
    capacities: []const u32,
    claims: []const @import("../air/block/memory_component.zig").Claim,
    total_events: u64,
    minimum_log_size: u32,
    reader: ?transition.Reader = null,
    partitioner: ?partition.Partitioner = null,
    next_index: u32 = 0,
    finished: bool = false,

    fn deinit(self: *Sequential) void {
        if (self.reader) |*reader| reader.deinit();
    }
    fn interface(self: *Sequential) artifact.TraceSource {
        return .{ .context = self, .load = load };
    }
    fn load(context: *anyopaque, index: u32) anyerror!trace_mod.Trace {
        const self: *Sequential = @ptrCast(@alignCast(context));
        if (self.finished or index != self.next_index or @as(usize, index) >= self.claims.len)
            return error.InvalidV5SortedReplayIndex;
        if (self.reader == null) {
            self.reader = try self.sorted.open(self.sorted.context);
            self.partitioner = try partition.Partitioner.initPlanned(&self.reader.?, self.total_events, self.capacities);
        }
        const trace = (try trace_mod.Trace.nextFromPartitioner(self.a, &self.partitioner.?, self.minimum_log_size)) orelse
            return error.V5SortedReplayUnderflow;
        if (!std.meta.eql(trace.claim, self.claims[index])) {
            var rejected = trace;
            rejected.deinit();
            return error.V5MemoryTraceReplayMismatch;
        }
        self.next_index += 1;
        if (@as(usize, self.next_index) == self.claims.len) {
            if (!self.partitioner.?.finished or self.partitioner.?.emitted != self.total_events) {
                var rejected = trace;
                rejected.deinit();
                return error.IncompleteV5SortedReplay;
            }
            self.reader.?.deinit();
            self.reader = null;
            self.partitioner = null;
            self.finished = true;
        }
        return trace;
    }
};
