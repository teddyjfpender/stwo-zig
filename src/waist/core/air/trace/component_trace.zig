const std = @import("std");
const m31_mod = @import("../../fields/m31.zig");
const row_iterator = @import("row_iterator.zig");

const M31 = m31_mod.M31;

pub const Error = error{
    InvalidLogSize,
    PositionOutOfRange,
} || std.mem.Allocator.Error || row_iterator.Error;

pub fn ComponentTrace(comptime N: usize) type {
    return struct {
        data: [N][]M31,
        log_size: u32,

        const Self = @This();

        pub fn initZeroed(allocator: std.mem.Allocator, log_size: u32) Error!Self {
            const n = try checkedPow2(log_size);
            var out: Self = .{
                .data = undefined,
                .log_size = log_size,
            };

            var initialized: usize = 0;
            errdefer {
                var i: usize = 0;
                while (i < initialized) : (i += 1) {
                    allocator.free(out.data[i]);
                }
            }

            inline for (0..N) |i| {
                out.data[i] = try allocator.alloc(M31, n);
                @memset(out.data[i], M31.zero());
                initialized += 1;
            }
            return out;
        }

        pub fn initUninitialized(allocator: std.mem.Allocator, log_size: u32) Error!Self {
            const n = try checkedPow2(log_size);
            var out: Self = .{
                .data = undefined,
                .log_size = log_size,
            };

            var initialized: usize = 0;
            errdefer {
                var i: usize = 0;
                while (i < initialized) : (i += 1) {
                    allocator.free(out.data[i]);
                }
            }

            inline for (0..N) |i| {
                out.data[i] = try allocator.alloc(M31, n);
                initialized += 1;
            }
            return out;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            inline for (0..N) |i| {
                allocator.free(self.data[i]);
            }
            self.* = undefined;
        }

        pub inline fn logSize(self: Self) u32 {
            return self.log_size;
        }

        pub fn nRows(self: Self) usize {
            return checkedPow2(self.log_size) catch unreachable;
        }

        pub fn rowAt(self: *const Self, row: usize) Error![N]M31 {
            const n = self.nRows();
            if (row >= n) return Error.PositionOutOfRange;

            var values: [N]M31 = undefined;
            inline for (0..N) |i| {
                values[i] = self.data[i][row];
            }
            return values;
        }

        pub fn iterMut(self: *Self) Error!row_iterator.RowIterMut(N) {
            return row_iterator.RowIterMut(N).init(self.data);
        }

        pub fn asColumns(self: *const Self) [N][]M31 {
            return self.data;
        }
    };
}

pub fn checkedPow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return Error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "air component trace: zeroed init and row read" {
    const alloc = std.testing.allocator;

    var trace = try ComponentTrace(3).initZeroed(alloc, 5);
    defer trace.deinit(alloc);

    try std.testing.expectEqual(@as(u32, 5), trace.logSize());
    try std.testing.expectEqual(@as(usize, 32), trace.nRows());

    const row0 = try trace.rowAt(0);
    inline for (row0) |value| {
        try std.testing.expect(value.isZero());
    }
}

test "air component trace: row iterator populates columns" {
    const alloc = std.testing.allocator;

    var trace = try ComponentTrace(2).initUninitialized(alloc, 3);
    defer trace.deinit(alloc);

    var iter = try trace.iterMut();
    var idx: usize = 0;
    while (iter.next()) |row| : (idx += 1) {
        row.at(0).* = M31.fromU64(idx + 1);
        row.at(1).* = M31.fromU64((idx + 1) * 7);
    }

    try std.testing.expectEqual(@as(usize, 8), idx);

    const row4 = try trace.rowAt(4);
    try std.testing.expect(row4[0].eql(M31.fromU64(5)));
    try std.testing.expect(row4[1].eql(M31.fromU64(35)));
}

test "air component trace: invalid row and log size fail" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(Error.InvalidLogSize, checkedPow2(@bitSizeOf(usize)));

    var trace = try ComponentTrace(1).initZeroed(alloc, 2);
    defer trace.deinit(alloc);
    try std.testing.expectError(Error.PositionOutOfRange, trace.rowAt(4));
}
