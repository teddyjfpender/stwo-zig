//! Only interval fields and membership gaps are materialized. Original access
//! bytes, activity, clocks and values remain in their original columns.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Air = @import("block_v5_caller_readonly_component_v1.zig");
const Protocol = @import("block_v5_caller_readonly_protocol_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Source = @import("block_execution_external_trace_v2.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
pub const SlotClaim = struct { claim: Protocol.Claim, counters: []u64 };
pub const Metadata = struct {
    storage: []M,
    columns: [Air.META_COUNT]Column,
    counters: []u64,
    events: u64,
    readonly_events: u64 = 0, // metadata proposal, never verifier authority
    pub fn deinit(self: *Metadata, a: std.mem.Allocator) void {
        a.free(self.storage);
        a.free(self.counters);
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, trace: *const Source.Trace, plan: Plan.Owned, limits: Protocol.Limits) !Metadata {
        return initIntervals(a, trace, plan.intervals, limits);
    }
    /// Candidate physical first pass. No Plan/source/seal authority is minted.
    pub fn initIntervals(a: std.mem.Allocator, trace: *const Source.Trace, intervals: []const Plan.Interval, limits: Protocol.Limits) !Metadata {
        return initKernel(.histogram, a, trace, intervals, limits, null);
    }
    pub const Observer = struct {
        context: *anyopaque,
        observe: *const fn (*anyopaque, u32) anyerror!void,
    };
    /// Proposal-only first pass. No selection/seal/proof authority is minted.
    /// Every original active logical row synchronously reaches the collector.
    pub fn initIntervalsObserved(a: std.mem.Allocator, trace: *const Source.Trace, intervals: []const Plan.Interval, limits: Protocol.Limits, observer: Observer) !Metadata {
        return initKernel(.open_source, a, trace, intervals, limits, observer);
    }
    /// Replay uses only the root-owned independently reconstructed Plan.
    pub fn initOpenSource(a: std.mem.Allocator, trace: *const Source.Trace, roster: *const @import("block_v5_readonly_input_global_roster_v2.zig").Authority, sealed: @import("block_v5_source_seal_v1.zig").Sealed, limits: Protocol.Limits) !Metadata {
        const plan = try roster.borrowedPlan(sealed);
        return initKernel(.open_source, a, trace, plan.intervals, limits, null);
    }
    const CounterFlavor = enum { histogram, open_source };
    fn initKernel(comptime flavor: CounterFlavor, a: std.mem.Allocator, trace: *const Source.Trace, intervals: []const Plan.Interval, limits: Protocol.Limits, observer: ?Observer) !Metadata {
        if (intervals.len > limits.max_intervals or (flavor == .histogram and try std.math.mul(usize, intervals.len, @sizeOf(u64)) > limits.max_counter_bytes)) return error.CallerReadonlyResourceLimit;
        const size = trace.domainSize();
        const cells = try std.math.mul(usize, size, Air.META_COUNT);
        if (try std.math.mul(usize, cells, @sizeOf(M)) > limits.max_metadata_bytes) return error.CallerReadonlyResourceLimit;
        const storage = try a.alloc(M, cells);
        errdefer a.free(storage);
        @memset(storage, M.zero());
        const counters = try a.alloc(u64, if (flavor == .histogram) intervals.len else 0);
        errdefer a.free(counters);
        @memset(counters, 0);
        var result = Metadata{ .storage = storage, .columns = undefined, .counters = counters, .events = 0 };
        for (&result.columns, 0..) |*column, i| column.* = .{ .values = storage[i * size ..][0..size], .log_size = trace.descriptor.log_size };
        for (0..size) |logical| {
            const row = try trace.row(logical);
            if (!row.active) continue;
            const event = try @import("block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple);
            const interval = try Plan.findInterval(intervals, event.address);
            const metadata = try Air.witnessRow(event, intervals[interval]);
            const physical = Framework.committedRow(logical, trace.descriptor.log_size);
            for (metadata, 0..) |value, c| result.storage[c * size + physical] = value;
            if (flavor == .histogram) counters[interval] = try std.math.add(u64, counters[interval], 1);
            if (observer) |sink| try sink.observe(sink.context, @intCast(interval));
            result.events = try std.math.add(u64, result.events, 1);
            if (intervals[interval].readonly) result.readonly_events = try std.math.add(u64, result.readonly_events, 1);
            if (result.events > limits.max_events or result.events >= core.fields.m31.Modulus) return error.CallerReadonlyResourceLimit;
        }
        return result;
    }
    pub fn require(self: *const Metadata, trace: *const Source.Trace, intervals: usize, limits: Protocol.Limits) !void {
        const size = trace.domainSize();
        const cells = try std.math.mul(usize, size, Air.META_COUNT);
        if (self.storage.len != cells or try std.math.mul(usize, cells, @sizeOf(M)) > limits.max_metadata_bytes or self.counters.len != intervals or intervals > limits.max_intervals) return error.UntrustedCallerReadonlyMetadata;
        for (self.columns, 0..) |column, i| if (column.log_size != trace.descriptor.log_size or column.values.len != size or column.coefficient_values != null or column.values.ptr != self.storage[i * size ..].ptr) return error.UntrustedCallerReadonlyMetadata;
    }
};
pub const Generated = struct {
    storage: []M,
    columns: [Air.INTER_COUNT][]M,
    claim: Protocol.Claim,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
};
pub fn generate(a: std.mem.Allocator, trace: *const Source.Trace, metadata: *const Metadata, plan: Plan.Owned, challenges: *const Protocol.Challenges, limits: Protocol.Limits) !Generated {
    return generateKernel(.scoped_providers, a, trace, metadata, plan, challenges, limits);
}
/// Genuine source-only global2 witness: same original columns/149 equations,
/// with provider equality left to the separately committed grouped provider.
/// The admitted roster owner must outlive its distinct BorrowedPlan view.
pub fn generateOpenSource(a: std.mem.Allocator, trace: *const Source.Trace, metadata: *const Metadata, plan: @import("block_v5_readonly_input_global_roster_v2.zig").BorrowedPlan, challenges: *const Protocol.Challenges, limits: Protocol.Limits) !Generated {
    return generateKernel(.open_global_source, a, trace, metadata, plan, challenges, limits);
}
const Flavor = enum { scoped_providers, open_global_source };
fn generateKernel(comptime flavor: Flavor, a: std.mem.Allocator, trace: *const Source.Trace, metadata: *const Metadata, plan: anytype, challenges: *const Protocol.Challenges, limits: Protocol.Limits) !Generated {
    try metadata.require(trace, if (flavor == .scoped_providers) plan.intervals.len else 0, limits);
    const size = trace.domainSize();
    const storage = try a.alloc(M, try std.math.mul(usize, size, Air.INTER_COUNT));
    errdefer a.free(storage);
    var result = Generated{ .storage = storage, .columns = undefined, .claim = undefined };
    for (&result.columns, 0..) |*column, i| column.* = storage[i * size ..][0..size];
    var sums: [4]Q = @splat(Q.zero());
    for (0..size) |logical| {
        const physical = Framework.committedRow(logical, trace.descriptor.log_size);
        const pair = try trace.pairAt(logical);
        const witness = (try trace.witnessAt(logical)).columns();
        var row: Air.Metadata = undefined;
        for (&row, metadata.columns) |*value, column| value.* = Q.fromBase(column.values[physical]);
        const d = Air.denominators(pair, witness, row, challenges);
        const n = Air.numerators(pair, row);
        for (0..4) |i| {
            const term = if (n[i].isZero()) Q.zero() else if (i < 3) try n[i].div(d[i]) else n[i];
            sums[i] = sums[i].add(term);
            for (term.toM31Array(), 0..) |limb, j| storage[(4 * i + j) * size + physical] = limb;
        }
    }
    const count = sums[3].toM31Array();
    for (count[1..]) |limb| if (!limb.isZero()) return error.InvalidCallerReadonlyProviderCensus;
    result.claim = .{ .mutable_sum = sums[0], .classification_sum = sums[1], .read_sum = sums[2], .readonly_count = count[0].toU32() };
    if (flavor == .scoped_providers) {
        // Original1 always retains its exact scalar provider traversal.
        try Protocol.checkProviders(plan, metadata.events, result.claim, metadata.counters, challenges, limits);
    } else {
        if (metadata.events >= core.fields.m31.Modulus or metadata.events > limits.max_events or result.claim.readonly_count > metadata.events or result.claim.readonly_count != metadata.readonly_events) return error.InvalidCallerReadonlyProviderCensus;
    }
    var prefix: [4]Q = @splat(Q.zero());
    for (0..size) |logical| {
        const physical = Framework.committedRow(logical, trace.descriptor.log_size);
        for (0..4) |i| {
            var term: [4]M = undefined;
            for (&term, 0..) |*value, j| value.* = result.columns[4 * i + j][physical];
            prefix[i] = prefix[i].add(Q.fromM31Array(term)).sub(try sums[i].divM31(M.fromCanonical(@intCast(size))));
            for (prefix[i].toM31Array(), 0..) |limb, j| storage[(4 * i + j) * size + physical] = limb;
        }
    }
    for (prefix) |value| if (!value.isZero()) return error.InvalidCallerReadonlyPrefix;
    return result;
}
