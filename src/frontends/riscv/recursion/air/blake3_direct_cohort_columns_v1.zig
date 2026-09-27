//! Count-admitted recursive row emitter: one transient logical row writes its
//! final committed main coordinates plus compact fixed metadata. No full row
//! roster or second transpose/scatter buffer is retained.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const framework = @import("framework_interaction.zig");
const storage = @import("blake3_parent_row_storage.zig");

/// Shared canonical capacity policy for main and independently rebuilt fixed columns.
pub fn rowLog(count: usize) !u32 {
    if (count > 1 << 24) return error.InvalidTraceShape;
    return if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
}

pub fn ForAir(comptime Air: type) type {
    return struct {
        const Self = @This();
        a: std.mem.Allocator,
        main: []Column,
        // Allocation-owned mutable aliases used only while emitting. Public
        // ColumnEvaluation exposes the same buffers as read-only evaluations.
        mutable_main: [Air.PHYSICAL_MAIN_COLUMN_COUNT][]M,
        fixed: []storage.FixedRow(Air),
        log: u32,
        next: usize = 0,

        pub fn init(a: std.mem.Allocator, count: usize) !Self {
            // Same padding/capacity policy as canonical row projection.
            const log = try rowLog(count);
            const fixed = try a.alloc(storage.FixedRow(Air), count);
            errdefer a.free(fixed);
            const main = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
            errdefer a.free(main);
            for (main) |*column| column.* = .{ .log_size = log, .values = &.{} };
            errdefer for (main) |column| a.free(column.values);
            var mutable_main: [Air.PHYSICAL_MAIN_COLUMN_COUNT][]M = @splat(&.{});
            for (main, &mutable_main) |*column, *owned| {
                const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
                @memset(values, M.zero());
                owned.* = values;
                column.values = values;
            }
            return .{ .a = a, .main = main, .mutable_main = mutable_main, .fixed = fixed, .log = log };
        }
        pub fn deinit(self: *Self) void {
            for (self.main) |column| self.a.free(column.values);
            self.a.free(self.main);
            self.a.free(self.fixed);
            self.* = undefined;
        }
        /// Row order and fixed selectors are identical to legacy projection.
        /// Count-first planning cannot silently resize an admitted geometry.
        pub fn append(self: *Self, row: Air.Row) !void {
            if (self.next >= self.fixed.len) return error.DirectRecursiveRowCountMismatch;
            const at = framework.committedRow(self.next, self.log);
            for (self.mutable_main, row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT]) |owned, value| owned[at] = value;
            self.fixed[self.next] = storage.compactFixed(Air, row);
            self.next += 1;
        }
        pub fn requireFinished(self: *const Self) !void {
            if (self.next != self.fixed.len) return error.DirectRecursiveRowCountMismatch;
        }
        /// Transfers buffers to canonical Prepared storage; no alternate proof
        /// encoding, component order, AIR constraints or release path is added.
        pub const Taken = struct { main: []Column, fixed: []storage.FixedRow(Air) };
        pub fn take(self: *Self) !Taken {
            try self.requireFinished();
            const result = Taken{ .main = self.main, .fixed = self.fixed };
            self.main = &.{};
            self.mutable_main = @splat(&.{});
            self.fixed = &.{};
            self.next = 0;
            return result;
        }
    };
}

test "direct recursive columns preserve canonical scattered layout and fixed metadata" {
    const Air = @import("qm31_mul_add_v1.zig");
    const a = std.testing.allocator;
    for ([_]usize{ 0, 1, 3, 9, 33 }) |count| {
        const rows = try a.alloc(Air.Row, count);
        defer a.free(rows);
        for (rows, 0..) |*row, i| {
            for (row, 0..) |*value, j| value.* = M.fromCanonical(@intCast(17 * i + j));
        }
        var direct = try ForAir(Air).init(a, count);
        defer direct.deinit();
        for (rows) |row| try direct.append(row);
        try direct.requireFinished();
        var reference: std.ArrayList(Column) = .empty;
        defer {
            for (reference.items) |column| a.free(column.values);
            reference.deinit(a);
        }
        try @import("blake3_row_columns.zig").project(Air, a, rows, direct.log, 1, &reference);
        try std.testing.expectEqual(reference.items.len, direct.main.len);
        for (reference.items, direct.main) |old, new| try std.testing.expectEqualSlices(M, old.values, new.values);
        for (rows, direct.fixed) |row, fixed| try std.testing.expectEqualDeep(storage.compactFixed(Air, row), fixed);
        try std.testing.expectError(error.DirectRecursiveRowCountMismatch, direct.append(@splat(M.zero())));
    }
}
test "direct recursive columns reject incomplete count and clean up cap failures" {
    const Air = @import("qm31_inv.zig");
    var direct = try ForAir(Air).init(std.testing.allocator, 2);
    defer direct.deinit();
    try direct.append(@splat(M.zero()));
    try std.testing.expectError(error.DirectRecursiveRowCountMismatch, direct.take());
    try std.testing.expectError(error.InvalidTraceShape, ForAir(Air).init(std.testing.allocator, (1 << 24) + 1));
}
