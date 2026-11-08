const std = @import("std");
const m31_mod = @import("../../fields/m31.zig");

const M31 = m31_mod.M31;

pub const Error = error{
    ShapeMismatch,
};

pub fn RowMut(comptime N: usize) type {
    return struct {
        cells: [N]*M31,

        const Self = @This();

        pub inline fn at(self: Self, comptime i: usize) *M31 {
            return self.cells[i];
        }

        pub inline fn asArray(self: Self) [N]*M31 {
            return self.cells;
        }
    };
}

/// Mutable row iterator over column-major `[N][]M31` storage.
pub fn RowIterMut(comptime N: usize) type {
    return struct {
        columns: [N][]M31,
        front: usize,
        back: usize,

        const Self = @This();

        pub fn init(columns: [N][]M31) Error!Self {
            const row_count = columns[0].len;
            inline for (1..N) |i| {
                if (columns[i].len != row_count) return Error.ShapeMismatch;
            }
            return .{
                .columns = columns,
                .front = 0,
                .back = row_count,
            };
        }

        pub inline fn len(self: Self) usize {
            return self.back - self.front;
        }

        pub fn next(self: *Self) ?RowMut(N) {
            if (self.front >= self.back) return null;
            const index = self.front;
            self.front += 1;
            return self.rowAt(index);
        }

        pub fn nextBack(self: *Self) ?RowMut(N) {
            if (self.front >= self.back) return null;
            self.back -= 1;
            return self.rowAt(self.back);
        }

        fn rowAt(self: *Self, index: usize) RowMut(N) {
            var cells: [N]*M31 = undefined;
            inline for (0..N) |i| {
                cells[i] = &self.columns[i][index];
            }
            return .{ .cells = cells };
        }
    };
}

test "air trace row iterator: forward iteration updates rows" {
    var c0 = [_]M31{ M31.zero(), M31.zero(), M31.zero() };
    var c1 = [_]M31{ M31.zero(), M31.zero(), M31.zero() };

    var iter = try RowIterMut(2).init(.{ c0[0..], c1[0..] });
    var i: usize = 0;
    while (iter.next()) |row| : (i += 1) {
        row.at(0).* = M31.fromU64(i + 1);
        row.at(1).* = M31.fromU64((i + 1) * 10);
    }

    try std.testing.expect(c0[0].eql(M31.fromU64(1)));
    try std.testing.expect(c0[1].eql(M31.fromU64(2)));
    try std.testing.expect(c0[2].eql(M31.fromU64(3)));
    try std.testing.expect(c1[0].eql(M31.fromU64(10)));
    try std.testing.expect(c1[1].eql(M31.fromU64(20)));
    try std.testing.expect(c1[2].eql(M31.fromU64(30)));
}

test "air trace row iterator: reverse iteration updates rows" {
    var c0 = [_]M31{ M31.zero(), M31.zero(), M31.zero(), M31.zero() };
    var c1 = [_]M31{ M31.zero(), M31.zero(), M31.zero(), M31.zero() };

    var iter = try RowIterMut(2).init(.{ c0[0..], c1[0..] });
    var v: u64 = 1;
    while (iter.nextBack()) |row| : (v += 1) {
        row.at(0).* = M31.fromU64(v);
        row.at(1).* = M31.fromU64(v * 2);
    }

    // Reverse fill should place smallest value at the end.
    try std.testing.expect(c0[3].eql(M31.fromU64(1)));
    try std.testing.expect(c1[3].eql(M31.fromU64(2)));
    try std.testing.expect(c0[0].eql(M31.fromU64(4)));
    try std.testing.expect(c1[0].eql(M31.fromU64(8)));
}

test "air trace row iterator: mismatched column lengths fail" {
    var c0 = [_]M31{ M31.zero(), M31.zero(), M31.zero() };
    var c1 = [_]M31{ M31.zero(), M31.zero() };

    try std.testing.expectError(
        Error.ShapeMismatch,
        RowIterMut(2).init(.{ c0[0..], c1[0..] }),
    );
}
