//! Count-first columns for source-derived PCS/public cohorts. The shared source
//! append routine supplies row order twice; only inventory-dependent cohorts
//! remain in the legacy builder. No source row or trace lifetime is extended.
const std = @import("std");
const storage = @import("blake3_parent_row_storage.zig");
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
pub const cohorts = .{ 2, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
fn selected(comptime i: usize) bool {
    inline for (cohorts) |slot| if (i == slot) return true;
    return false;
}
fn position(comptime i: usize) usize {
    inline for (cohorts, 0..) |slot, index| if (slot == i) return index;
    @compileError("cohort does not have a direct source column owner");
}
const Owners = blk: {
    var types: [cohorts.len]type = undefined;
    for (cohorts, &types) |slot, *T| T.* = Direct.ForAir(storage.Airs[slot]);
    break :blk std.meta.Tuple(&types);
};
pub const Counts = struct {
    counts: [storage.Airs.len]usize = @splat(0),
    fn add(self: *Counts, comptime i: usize, rows: anytype, fixed: anytype) !void {
        if (rows.len != fixed.len) return error.InvalidNativeParentRows;
        self.counts[i] = try std.math.add(usize, self.counts[i], rows.len);
    }
    pub fn append(self: *Counts, comptime i: usize, rows: []const storage.Airs[i].Row, fixed: []const storage.Airs[i].Row) !void {
        try self.add(i, rows, fixed);
    }
    pub fn appendCompact(self: *Counts, comptime i: usize, rows: []const storage.Airs[i].Row, fixed: []const storage.FixedRow(storage.Airs[i])) !void {
        try self.add(i, rows, fixed);
    }
    pub fn appendMetadata(self: *Counts, comptime i: usize, rows: []const storage.FixedRow(storage.Airs[i]), fixed: anytype) !void {
        try self.add(i, rows, fixed);
    }
    pub fn appendBorrowed(self: *Counts, comptime i: usize, rows: @import("blake3_recursive_column_rows_v1.zig").ForAir(storage.Airs[i])) !void {
        try rows.validate();
        self.counts[i] = try std.math.add(usize, self.counts[i], rows.rowCount());
    }
};
pub const Builder = struct {
    legacy: *storage.Builder,
    owners: Owners,
    pub fn init(a: std.mem.Allocator, legacy: *storage.Builder, counts: [storage.Airs.len]usize) !Builder {
        var owners: Owners = undefined;
        var initialized: usize = 0;
        errdefer inline for (cohorts, 0..) |_, index| {
            if (index < initialized) owners[index].deinit();
        };
        inline for (cohorts, 0..) |slot, index| {
            owners[index] = try Direct.ForAir(storage.Airs[slot]).init(a, counts[slot]);
            initialized += 1;
        }
        return .{ .legacy = legacy, .owners = owners };
    }
    pub fn deinit(self: *Builder) void {
        inline for (cohorts, 0..) |_, index| self.owners[index].deinit();
    }
    pub fn append(self: *Builder, comptime i: usize, rows: []const storage.Airs[i].Row, fixed: []const storage.Airs[i].Row) !void {
        if (comptime selected(i)) {
            if (rows.len != fixed.len) return error.InvalidNativeParentRows;
            // Exactly the legacy builder's independently supplied fixed-tail check.
            for (rows, fixed) |live, trusted| {
                for (live[storage.Airs[i].PHYSICAL_MAIN_COLUMN_COUNT..], storage.compactFixed(storage.Airs[i], trusted)) |actual, expected| {
                    if (!actual.eql(expected)) return error.InvalidNativeParentRows;
                }
            }
            for (rows) |row| try self.owners[comptime position(i)].append(row);
        } else return self.legacy.append(i, rows, fixed);
    }
    pub fn appendCompact(self: *Builder, comptime i: usize, rows: []const storage.Airs[i].Row, fixed: []const storage.FixedRow(storage.Airs[i])) !void {
        try self.legacy.appendCompact(i, rows, fixed);
    }
    pub fn appendMetadata(self: *Builder, comptime i: usize, rows: []const storage.FixedRow(storage.Airs[i]), fixed: anytype) !void {
        try self.legacy.appendMetadata(i, rows, fixed);
    }
    /// One transient row from already-owned upstream columns. Compact fixed
    /// metadata is the logical row tail, never another dense fixed-row roster.
    pub fn appendBorrowed(self: *Builder, comptime i: usize, rows: @import("blake3_recursive_column_rows_v1.zig").ForAir(storage.Airs[i])) !void {
        try rows.validate();
        for (0..rows.rowCount()) |index| {
            const row = rows.rowAt(index);
            try self.append(i, &.{row}, &.{row});
        }
    }
    pub fn takeInto(self: *Builder, main: *[storage.Airs.len][]Column, fixed: *storage.FixedTuple(false)) !void {
        // Preflight all destinations/counts before any ownership transfer.
        inline for (cohorts, 0..) |slot, index| {
            if (main[slot].len != 0 or fixed[slot].len != 0 or self.legacy.rows[slot].items.len != 0 or self.legacy.fixed[slot].items.len != 0) return error.InvalidNativeParentRows;
            try self.owners[index].requireFinished();
        }
        inline for (cohorts, 0..) |slot, index| {
            const taken = try self.owners[index].take();
            main[slot] = taken.main;
            fixed[slot] = taken.fixed;
        }
    }
};
