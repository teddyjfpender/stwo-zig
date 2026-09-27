//! Prover ownership boundary for experimental compact range witnesses.
//! Construct every provider before merging byte demand; failed preparation
//! cannot partially mutate the native lookup census.
const std = @import("std");
const core = @import("stwo_core");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const counter = @import("../air/lookups/tables/counter.zig");
const geometry = @import("../recursion/air/compact_range_geometry.zig");
const provider = @import("../recursion/air/compact_range_provider.zig");
const witness = @import("../recursion/air/compact_range_witness.zig");
const Witnesses = std.meta.Tuple(&.{ witness.Owner(.range_check_20), witness.Owner(.range_check_8_11), witness.Owner(.range_check_8_8_4) });
pub const COLUMN_COUNT = 23;
pub fn derivePlan(counters: *counter.Set) !geometry.Plan {
    var counts: [geometry.kinds.len]usize = @splat(0);
    for (geometry.kinds, &counts) |kind, *count| {
        const source = counters.get(kind);
        if (source.kind != kind or source.values.len != @import("../air/lookups/tables/schema.zig").size(kind)) return error.InvalidTraceShape;
        for (source.values) |value| {
            if (!value.isZero()) count.* += 1;
        }
    }
    return geometry.Plan.canonical(counts);
}
pub const Owner = struct {
    allocator: std.mem.Allocator,
    plan: geometry.Plan,
    identity: [32]u8,
    witnesses: Witnesses = undefined,
    initialized: usize = 0,
    columns: [COLUMN_COUNT]Column = undefined,
    merged: bool = false,
    pub fn init(a: std.mem.Allocator, counters: *counter.Set, plan: geometry.Plan, expected: [32]u8) !*Owner {
        try plan.admit(expected);
        const self = try a.create(Owner);
        self.* = .{ .allocator = a, .plan = plan, .identity = expected };
        errdefer self.deinit();
        var column_index: usize = 0;
        inline for (geometry.kinds, 0..) |kind, i| {
            self.witnesses[i] = try witness.Owner(kind).initAdmitted(a, counters.get(kind), plan, expected);
            self.initialized += 1;
            for (self.witnesses[i].columns) |values| {
                self.columns[column_index] = .{ .log_size = plan.shapes[i].log_size, .values = values };
                column_index += 1;
            }
        }
        std.debug.assert(column_index == COLUMN_COUNT);
        return self;
    }
    pub fn deinit(self: *Owner) void {
        const a = self.allocator;
        inline for (0..geometry.kinds.len) |i| {
            if (i < self.initialized) self.witnesses[i].deinit();
        }
        a.destroy(self);
    }
    /// Called once after all original lookup requests have been registered.
    /// Columns are borrowed views; the owner retains their backing allocations.
    pub fn mergeByteCounts(self: *Owner, destination: *counter.Counter) !void {
        if (self.merged) return error.CompactRangeByteCountsAlreadyMerged;
        if (destination.kind != .range_check_8_8 or destination.values.len != 65536) return error.InvalidTraceShape;
        // Reject accidental aliasing with any source census before the first write.
        const start = @intFromPtr(destination.values.ptr);
        const end = start + destination.values.len * @sizeOf(core.fields.m31.M31);
        inline for (0..geometry.kinds.len) |i| {
            const source = self.witnesses[i].byte_counts;
            const source_start = @intFromPtr(source.ptr);
            const source_end = source_start + source.len * @sizeOf(core.fields.m31.M31);
            if (start < source_end and source_start < end) return error.AliasedInput;
        }
        inline for (0..geometry.kinds.len) |i| {
            for (destination.values, self.witnesses[i].byte_counts) |*target, source| target.* = target.add(source);
        }
        self.merged = true;
    }
};
comptime {
    var total: usize = 0;
    for (geometry.kinds) |kind| total += provider.Provider(kind).PHYSICAL_MAIN_COLUMN_COUNT;
    if (total != COLUMN_COUNT) @compileError("compact range column count drift");
}
