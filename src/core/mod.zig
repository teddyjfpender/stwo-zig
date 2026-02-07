const std = @import("std");

pub const fields = @import("fields/mod.zig");
pub const circle = @import("circle.zig");
pub const vcs = @import("vcs/mod.zig");
pub const vcs_lifted = @import("vcs_lifted/mod.zig");
pub const channel = @import("channel/mod.zig");
pub const proof_of_work = @import("proof_of_work.zig");
pub const crypto = @import("crypto/mod.zig");
pub const utils = @import("utils.zig");
pub const queries = @import("queries.zig");
pub const fraction = @import("fraction.zig");
pub const fft = @import("fft.zig");
pub const poly = @import("poly/mod.zig");
pub const constraints = @import("constraints.zig");
pub const air = @import("air/mod.zig");
pub const fri = @import("fri.zig");
pub const pcs = @import("pcs/mod.zig");
pub const proof = @import("proof.zig");
pub const test_utils = @import("test_utils.zig");
pub const verifier_types = @import("verifier_types.zig");
pub const verifier = @import("verifier.zig");

/// Vector where each element relates by index to a trace column.
pub fn ColumnVec(comptime T: type) type {
    return []T;
}

/// Vector of `ColumnVec`s, one entry per AIR component.
pub fn ComponentVec(comptime T: type) type {
    return struct {
        items: [][]T,

        const Self = @This();

        pub inline fn initOwned(items: [][]T) Self {
            return .{ .items = items };
        }

        pub fn deinitDeep(self: *Self, allocator: std.mem.Allocator) void {
            for (self.items) |item| allocator.free(item);
            allocator.free(self.items);
            self.* = undefined;
        }

        pub fn flatten(self: Self, allocator: std.mem.Allocator) ![]T {
            var total: usize = 0;
            for (self.items) |col| total += col.len;
            const out = try allocator.alloc(T, total);
            var at: usize = 0;
            for (self.items) |col| {
                @memcpy(out[at .. at + col.len], col);
                at += col.len;
            }
            return out;
        }

        /// Flattens `ComponentVec<ColumnVec<T>>` into `[]T`.
        pub fn flattenCols(self: Self, allocator: std.mem.Allocator) ![]childType(T) {
            const ti = @typeInfo(T);
            if (ti != .pointer or ti.pointer.size != .slice) {
                @compileError("flattenCols requires ComponentVec of column vectors");
            }
            const Child = childType(T);

            var total: usize = 0;
            for (self.items) |col_vec| {
                for (col_vec) |col| total += col.len;
            }

            const out = try allocator.alloc(Child, total);
            var at: usize = 0;
            for (self.items) |col_vec| {
                for (col_vec) |col| {
                    @memcpy(out[at .. at + col.len], col);
                    at += col.len;
                }
            }
            return out;
        }
    };
}

fn childType(comptime SliceType: type) type {
    return @typeInfo(SliceType).pointer.child;
}

test "component vec: flatten and flatten cols" {
    const alloc = std.testing.allocator;

    const c0 = try alloc.dupe(u32, &[_]u32{ 1, 2 });
    const c1 = try alloc.dupe(u32, &[_]u32{3});
    var cv = ComponentVec(u32).initOwned(try alloc.dupe([]u32, &[_][]u32{ c0, c1 }));
    defer cv.deinitDeep(alloc);
    const flat = try cv.flatten(alloc);
    defer alloc.free(flat);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 2, 3 }, flat);

    const n00 = try alloc.dupe(u32, &[_]u32{ 1, 2 });
    const n01 = try alloc.dupe(u32, &[_]u32{3});
    const n10 = try alloc.dupe(u32, &[_]u32{ 4, 5, 6 });
    const cols0 = try alloc.dupe([]u32, &[_][]u32{ n00, n01 });
    const cols1 = try alloc.dupe([]u32, &[_][]u32{n10});
    var nested = ComponentVec([]u32).initOwned(try alloc.dupe([][]u32, &[_][][]u32{ cols0, cols1 }));
    defer {
        for (nested.items) |cols| {
            for (cols) |col| alloc.free(col);
            alloc.free(cols);
        }
        alloc.free(nested.items);
    }
    const flat_cols = try nested.flattenCols(alloc);
    defer alloc.free(flat_cols);
    try std.testing.expectEqualSlices(u32, &[_]u32{ 1, 2, 3, 4, 5, 6 }, flat_cols);
}
