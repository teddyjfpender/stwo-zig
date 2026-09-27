//! Fixed arithmetic cohorts rebuilt from the original authenticated fusion walk.
//! No private evaluations, invocation buffers, inverse values or main columns.
const std = @import("std");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Storage = @import("blake3_parent_row_storage.zig");
const Projection = @import("blake3_row_columns.zig");
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
pub const Airs = .{
    @import("detached_opening_accumulate4_v1.zig"),
    @import("qm31_mul_add_v1.zig"),
    @import("qm31_inv.zig"),
    @import("linear_ops.zig"),
};
const Metadata = std.meta.Tuple(&.{
    []Storage.FixedRow(Airs[0]), []Storage.FixedRow(Airs[1]),
    []Storage.FixedRow(Airs[2]), []Storage.FixedRow(Airs[3]),
});
pub const Fixed = struct {
    allocator: std.mem.Allocator,
    fixed: Metadata,
    /// Canonical opening-dot4, multiply-add, inverse, linear fixed columns.
    columns: []Column,
    logs: [4]u32,
    counts: [4]usize,
    dot4_matches: usize,
    fma_matches: usize,
    pub fn deinit(self: *Fixed) void {
        inline for (0..Airs.len) |i| self.allocator.free(self.fixed[i]);
        for (self.columns) |column| self.allocator.free(column.values);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
    pub fn columnRange(self: *const Fixed, comptime slot: usize) []const Column {
        comptime std.debug.assert(slot < Airs.len);
        const offset = comptime blk: {
            var n: usize = 0;
            for (Airs, 0..) |Air, i| {
                if (i < slot) n += Air.PREPROCESSED_COLUMN_COUNT;
            }
            break :blk n;
        };
        return self.columns[offset..][0..Airs[slot].PREPROCESSED_COLUMN_COUNT];
    }
};
pub const Sink = struct {
    pub const NEEDS_ROWS = false;
    pub const NEEDS_FIXED = true;
    a: std.mem.Allocator,
    fixed: Metadata,
    logs: [4]u32,
    counts: [4]usize,
    next: [4]usize = @splat(0),
    pub fn init(a: std.mem.Allocator, counts: [4]usize) !Sink {
        var out = Sink{ .a = a, .fixed = undefined, .logs = undefined, .counts = counts };
        inline for (0..Airs.len) |i| out.fixed[i] = &.{};
        errdefer out.deinit();
        for (counts, &out.logs) |count, *log| log.* = try Direct.rowLog(count);
        inline for (Airs, 0..) |Air, i| out.fixed[i] = try a.alloc(Storage.FixedRow(Air), counts[i]);
        return out;
    }
    pub fn deinit(self: *Sink) void {
        inline for (0..Airs.len) |i| self.a.free(self.fixed[i]);
        self.* = undefined;
    }
    fn append(self: *Sink, comptime slot: usize, row: Airs[slot].Row) !void {
        if (self.next[slot] >= self.counts[slot]) return error.DirectRecursiveRowCountMismatch;
        self.fixed[slot][self.next[slot]] = Storage.compactFixed(Airs[slot], row);
        self.next[slot] += 1;
    }
    pub fn opening(self: *Sink, row: Airs[0].Row) !void {
        try self.append(0, row);
    }
    pub fn multiply(self: *Sink, row: Airs[1].Row) !void {
        try self.append(1, row);
    }
    pub fn inverse(self: *Sink, row: Airs[2].Row) !void {
        try self.append(2, row);
    }
    pub fn linear(self: *Sink, row: Airs[3].Row) !void {
        try self.append(3, row);
    }
    pub fn take(self: *Sink, stats: anytype) !Fixed {
        if (!std.mem.eql(usize, &self.next, &self.counts)) return error.DirectRecursiveRowCountMismatch;
        var columns: std.ArrayList(Column) = .empty;
        errdefer {
            for (columns.items) |column| self.a.free(column.values);
            columns.deinit(self.a);
        }
        inline for (Airs, 0..) |Air, i| try Projection.projectFixed(Air, self.a, self.fixed[i], self.logs[i], &columns);
        const result = Fixed{ .allocator = self.a, .fixed = self.fixed, .columns = try columns.toOwnedSlice(self.a), .logs = self.logs, .counts = self.counts, .dot4_matches = stats.dot4_matches, .fma_matches = stats.fma_matches };
        inline for (0..Airs.len) |i| self.fixed[i] = &.{};
        self.next = @splat(0);
        return result;
    }
};
