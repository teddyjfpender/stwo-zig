const std = @import("std");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

/// Column-major representation of secure field coordinates.
pub const SecureColumnByCoords = struct {
    columns: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    owns_columns: bool = true,

    pub const Error = error{
        InconsistentColumnLength,
    };

    pub fn initOwned(columns: [qm31.SECURE_EXTENSION_DEGREE][]M31) Error!SecureColumnByCoords {
        const column_len = columns[0].len;
        for (columns[1..]) |column| {
            if (column.len != column_len) return Error.InconsistentColumnLength;
        }
        return .{
            .columns = columns,
            .owns_columns = true,
        };
    }

    pub fn deinit(self: *SecureColumnByCoords, allocator: std.mem.Allocator) void {
        if (self.owns_columns) {
            for (self.columns) |column| allocator.free(column);
        }
        self.* = undefined;
    }

    pub fn at(self: SecureColumnByCoords, index: usize) QM31 {
        return QM31.fromM31Array(.{
            self.columns[0][index],
            self.columns[1][index],
            self.columns[2][index],
            self.columns[3][index],
        });
    }

    pub fn zeros(allocator: std.mem.Allocator, column_len: usize) !SecureColumnByCoords {
        var columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
        for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
            columns[i] = try allocator.alloc(M31, column_len);
            @memset(columns[i], M31.zero());
        }
        return .{
            .columns = columns,
            .owns_columns = true,
        };
    }

    pub fn uninitialized(allocator: std.mem.Allocator, column_len: usize) !SecureColumnByCoords {
        var columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
        for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
            columns[i] = try allocator.alloc(M31, column_len);
        }
        return .{
            .columns = columns,
            .owns_columns = true,
        };
    }

    pub fn fromBaseFieldCol(
        allocator: std.mem.Allocator,
        column: []const M31,
    ) !SecureColumnByCoords {
        var columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
        columns[0] = try allocator.dupe(M31, column);
        for (1..qm31.SECURE_EXTENSION_DEGREE) |i| {
            columns[i] = try allocator.alloc(M31, column.len);
            @memset(columns[i], M31.zero());
        }
        return .{
            .columns = columns,
            .owns_columns = true,
        };
    }

    pub fn len(self: SecureColumnByCoords) usize {
        return self.columns[0].len;
    }

    pub fn isEmpty(self: SecureColumnByCoords) bool {
        return self.columns[0].len == 0;
    }

    pub fn cloneOwned(
        self: SecureColumnByCoords,
        allocator: std.mem.Allocator,
    ) !SecureColumnByCoords {
        var columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
        for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
            columns[i] = try allocator.dupe(M31, self.columns[i]);
        }
        return .{
            .columns = columns,
            .owns_columns = true,
        };
    }

    pub fn set(self: *SecureColumnByCoords, index: usize, value: QM31) void {
        const coords = value.toM31Array();
        for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
            self.columns[i][index] = coords[i];
        }
    }

    pub fn toVec(self: SecureColumnByCoords, allocator: std.mem.Allocator) ![]QM31 {
        const out = try allocator.alloc(QM31, self.len());
        for (0..out.len) |i| out[i] = self.at(i);
        return out;
    }

    pub fn fromSecureSlice(
        allocator: std.mem.Allocator,
        values: []const QM31,
    ) !SecureColumnByCoords {
        var columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
        for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
            columns[i] = try allocator.alloc(M31, values.len);
        }
        for (values, 0..) |value, row| {
            const coords = value.toM31Array();
            for (0..qm31.SECURE_EXTENSION_DEGREE) |i| {
                columns[i][row] = coords[i];
            }
        }
        return .{
            .columns = columns,
            .owns_columns = true,
        };
    }

    pub fn iter(self: *const SecureColumnByCoords) Iterator {
        return .{
            .column = self,
            .index = 0,
        };
    }

    pub const Iterator = struct {
        column: *const SecureColumnByCoords,
        index: usize,

        pub fn next(self: *Iterator) ?QM31 {
            if (self.index >= self.column.len()) return null;
            const value = self.column.at(self.index);
            self.index += 1;
            return value;
        }
    };
};

test "secure column: set and at roundtrip" {
    const alloc = std.testing.allocator;
    var column = try SecureColumnByCoords.zeros(alloc, 4);
    defer column.deinit(alloc);

    const value = QM31.fromU32Unchecked(1, 2, 3, 4);
    column.set(2, value);
    try std.testing.expect(column.at(2).eql(value));
}

test "secure column: from base field col embeds in first coordinate" {
    const alloc = std.testing.allocator;
    const base = [_]M31{
        M31.fromCanonical(5),
        M31.fromCanonical(8),
        M31.fromCanonical(13),
    };
    var column = try SecureColumnByCoords.fromBaseFieldCol(alloc, base[0..]);
    defer column.deinit(alloc);

    try std.testing.expectEqual(base.len, column.len());
    for (base, 0..) |v, i| {
        const got = column.at(i);
        try std.testing.expect(got.c0.a.eql(v));
        try std.testing.expect(got.c0.b.isZero());
        try std.testing.expect(got.c1.a.isZero());
        try std.testing.expect(got.c1.b.isZero());
    }
}

test "secure column: from secure slice and iterator" {
    const alloc = std.testing.allocator;
    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
    };
    var column = try SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    var it = column.iter();
    var i: usize = 0;
    while (it.next()) |value| : (i += 1) {
        try std.testing.expect(value.eql(values[i]));
    }
    try std.testing.expectEqual(values.len, i);

    const roundtrip = try column.toVec(alloc);
    defer alloc.free(roundtrip);
    for (roundtrip, 0..) |value, idx| try std.testing.expect(value.eql(values[idx]));
}
