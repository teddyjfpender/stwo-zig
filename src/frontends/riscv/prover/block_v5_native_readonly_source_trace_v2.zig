//! Streaming original classifier witness ownership. No source proof, receiver
//! receipt, transition-list copy or per-source interval counter vector.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Original = @import("block_v5_readonly_input_proof_v1.zig");
const Air = @import("block_v5_readonly_input_component_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Event = @import("../air/block/memory_transition.zig").Transition;
pub const Owned = struct {
    a: std.mem.Allocator,
    original: Original.Trace,
    pub fn deinit(self: *Owned) void {
        self.original.deinit(self.a);
        self.* = undefined;
    }
};
pub const Builder = struct {
    a: std.mem.Allocator,
    pin: Original.Pin,
    intervals: []const Plan.Interval,
    trace: ?Original.Trace,
    next_event: usize = 0,
    pub fn init(a: std.mem.Allocator, pin: Original.Pin, intervals: []const Plan.Interval, digest: [32]u8) !Builder {
        try pin.validate();
        if (!std.meta.eql(pin.plan_digest, digest) or intervals.len == 0 or intervals.len > pin.limits.max_intervals) return error.UntrustedNativeReadonlyV2TracePlan;
        var upper: u32 = 0;
        for (intervals) |interval| {
            if (interval.lower != upper or interval.upper <= upper or interval.upper > Plan.WORD_LIMIT or (interval.readonly and interval.upper != interval.lower + 1) or (!interval.readonly and interval.value != 0)) return error.InvalidReadonlyInputPartition;
            upper = interval.upper;
        }
        if (upper != Plan.WORD_LIMIT) return error.InvalidReadonlyInputPartition;
        return initBorrowed(a, pin, intervals, digest);
    }
    /// Witness-only constructor for one stable, already admitted complete
    /// partition. It does not traverse N intervals per source or confer any
    /// authority; fresh source/provider equations still check all requests.
    pub fn initBorrowed(a: std.mem.Allocator, pin: Original.Pin, intervals: []const Plan.Interval, digest: [32]u8) !Builder {
        try pin.validate();
        if (!std.meta.eql(pin.plan_digest, digest) or intervals.len == 0 or intervals.len > pin.limits.max_intervals) return error.UntrustedNativeReadonlyV2TracePlan;
        const rows: usize = @as(usize, 1) << @intCast(pin.row_log);
        const storage = try a.alloc(M, rows * (1 + Air.Spec.MAIN_COUNT));
        errdefer a.free(storage);
        @memset(storage, M.zero());
        const empty = try a.alloc(u64, 0);
        errdefer a.free(empty);
        var trace = Original.Trace{ .storage = storage, .fixed = .{.{ .values = storage[0..rows], .log_size = pin.row_log }}, .main = undefined, .counters = empty };
        for (&trace.main, 0..) |*column, i| column.* = .{ .values = storage[(1 + i) * rows ..][0..rows], .log_size = pin.row_log };
        return .{ .a = a, .pin = pin, .intervals = intervals, .trace = trace };
    }
    pub fn deinit(self: *Builder) void {
        if (self.trace) |*trace| trace.deinit(self.a);
        self.* = undefined;
    }
    /// Supplied ordinal is independently checked against the exact original
    /// partition. A caller may derive it once while observing source counters.
    pub fn append(self: *Builder, event: Event, interval_ordinal: usize) !void {
        const trace = if (self.trace) |*value| value else return error.NativeReadonlyV2TraceFinished;
        if (self.next_event >= self.pin.events or interval_ordinal >= self.intervals.len) return error.InvalidNativeReadonlyV2TraceCensus;
        const interval = self.intervals[interval_ordinal];
        // The complete ordered partition and this exact membership test are
        // sufficient; no second binary search is needed for an admitted ordinal.
        if (event.address & 3 != 0 or event.address / 4 < interval.lower or event.address / 4 >= interval.upper) return error.InvalidReadonlyInputClassification;
        const row = try Air.witnessRow(event, interval);
        const physical = Framework.committedRow(self.next_event, self.pin.row_log);
        trace.storage[physical] = M.one();
        for (row, 0..) |value, column| trace.mainValues(column)[physical] = value;
        self.next_event += 1;
    }
    pub fn finish(self: *Builder) !Owned {
        const trace = self.trace orelse return error.NativeReadonlyV2TraceFinished;
        if (self.next_event != self.pin.events) return error.InvalidNativeReadonlyV2TraceCensus;
        try trace.require(self.pin);
        self.trace = null;
        return .{ .a = self.a, .original = trace };
    }
};
