//! Fixed metadata only. There are no physical-main placeholders or proof tokens.
//! Construction is count admitted; callers own all source policy lifetimes.
const std = @import("std");
const Storage = @import("blake3_parent_row_storage.zig");
const Projection = @import("blake3_row_columns.zig");
const Direct = @import("blake3_direct_cohort_columns_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;

pub fn ForSlots(comptime slots: anytype) type {
    const Metadata = blk: {
        var types: [slots.len]type = undefined;
        for (slots, &types) |slot, *T| T.* = []Storage.FixedRow(Storage.Airs[slot]);
        break :blk std.meta.Tuple(&types);
    };
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        lease: ?*Budget,
        rows: Metadata,
        counts: [slots.len]usize,
        next: [slots.len]usize = @splat(0),
        pub fn init(a: std.mem.Allocator, counts: [slots.len]usize) !Self {
            // The same count-admitted kernel now also serves all original
            // cohorts. This only budgets static tuple/cleanup expansion.
            @setEvalBranchQuota(10_000);
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            var result = Self{ .allocator = a, .lease = lease, .rows = undefined, .counts = counts };
            inline for (0..slots.len) |i| result.rows[i] = &.{};
            errdefer inline for (0..slots.len) |i| a.free(result.rows[i]);
            inline for (slots, 0..) |slot, i| {
                _ = try Direct.rowLog(counts[i]);
                result.rows[i] = try a.alloc(Storage.FixedRow(Storage.Airs[slot]), counts[i]);
            }
            return result;
        }
        fn position(comptime slot: usize) usize {
            inline for (slots, 0..) |s, i| if (slot == s) return i;
            @compileError("fixed port does not own this cohort");
        }
        pub fn append(self: *Self, comptime slot: usize, tail: Storage.FixedRow(Storage.Airs[slot])) !void {
            const i = comptime position(slot);
            if (self.next[i] >= self.counts[i]) return error.RecursiveFixedPortCountMismatch;
            self.rows[i][self.next[i]] = tail;
            self.next[i] += 1;
        }
        pub fn appendLogicalFixed(self: *Self, comptime slot: usize, row: Storage.Airs[slot].Row) !void {
            try self.append(slot, Storage.compactFixed(Storage.Airs[slot], row));
        }
        pub fn finish(self: *const Self) !void {
            if (!std.mem.eql(usize, &self.counts, &self.next)) return error.RecursiveFixedPortCountMismatch;
        }
        pub fn metadata(self: *const Self, comptime slot: usize) ![]const Storage.FixedRow(Storage.Airs[slot]) {
            try self.finish();
            return self.rows[comptime position(slot)];
        }
        /// Original projection/scatter and padding; never projects main columns.
        /// On failure no partially appended column escapes into the caller list.
        pub fn project(self: *const Self, comptime slot: usize, a: std.mem.Allocator, columns: *std.ArrayList(Column)) !void {
            const rows = try self.metadata(slot);
            try Projection.projectFixed(Storage.Airs[slot], a, rows, try Direct.rowLog(rows.len), columns);
        }
        pub fn deinit(self: *Self) void {
            const a = self.allocator;
            const lease = self.lease;
            inline for (0..slots.len) |i| a.free(self.rows[i]);
            self.* = undefined;
            if (lease) |owner| owner.destroy();
        }
    };
}
