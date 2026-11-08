const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const ResidentStorage = @import("resident_storage.zig").ResidentStorage;

const M31 = m31.M31;
const QM31 = qm31.QM31;

/// Column-major host representation of secure field coordinates.
pub const SecureColumnByCoords = SecureColumnByCoordsFor(QM31);

pub fn SecureColumnByCoordsFor(comptime Secure: type) type {
    return struct {
        const ColumnSlice = []M31;
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;

        const Self = @This();

        pub const Representation = enum { evaluations, coefficients };

        columns: [@typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len]ColumnSlice,
        representation: Representation = .evaluations,
        owns_columns: bool = true,
        /// When true, all 4 column slices point into a single contiguous
        /// allocation starting at columns[0].ptr with total length
        /// DEGREE * columns[0].len.  When false, each column is a
        /// separate heap allocation.
        contiguous: bool = false,
        resident_storage: ?ResidentStorage = null,

        pub const Error = error{
            InconsistentColumnLength,
        };

        pub fn initOwned(columns: [@typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len]ColumnSlice) Error!Self {
            const column_len = columns[0].len;
            for (columns[1..]) |column| {
                if (column.len != column_len) return Error.InconsistentColumnLength;
            }
            return .{
                .columns = columns,
                .owns_columns = true,
                .contiguous = false,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self.resident_storage) |storage| {
                storage.deinit();
            } else if (self.owns_columns and self.columns[0].len > 0) {
                if (self.contiguous) {
                    // Free the single contiguous block starting at columns[0].ptr
                    const total = DEGREE * self.columns[0].len;
                    allocator.free(self.columns[0].ptr[0..total]);
                } else {
                    for (self.columns) |column| allocator.free(column);
                }
            }
            self.* = undefined;
        }

        pub fn initResident(
            columns: [DEGREE]ColumnSlice,
            storage: ResidentStorage,
        ) Error!Self {
            const column_len = columns[0].len;
            for (columns[1..]) |column| {
                if (column.len != column_len) return Error.InconsistentColumnLength;
            }
            return .{
                .columns = columns,
                .owns_columns = false,
                .contiguous = true,
                .resident_storage = storage,
            };
        }

        pub fn at(self: Self, index: usize) Secure {
            var coordinates: [DEGREE]M31 = undefined;
            for (&coordinates, self.columns) |*v, column| v.* = column[index];
            return Secure.fromM31Array(coordinates);
        }

        pub fn zeros(allocator: std.mem.Allocator, column_len: usize) !Self {
            // Single contiguous allocation for all 4 coordinate columns
            const total = DEGREE * column_len;
            const buffer = try allocator.alloc(M31, total);
            @memset(buffer, M31.zero());
            var columns: [DEGREE]ColumnSlice = undefined;
            for (0..DEGREE) |i| {
                columns[i] = buffer[i * column_len .. (i + 1) * column_len];
            }
            return .{ .columns = columns, .owns_columns = true, .contiguous = true };
        }

        pub fn uninitialized(allocator: std.mem.Allocator, column_len: usize) !Self {
            const total = DEGREE * column_len;
            const buffer = try allocator.alloc(M31, total);
            var columns: [DEGREE]ColumnSlice = undefined;
            for (0..DEGREE) |i| {
                columns[i] = buffer[i * column_len .. (i + 1) * column_len];
            }
            return .{ .columns = columns, .owns_columns = true, .contiguous = true };
        }

        pub fn fromBaseFieldCol(
            allocator: std.mem.Allocator,
            column: []const M31,
        ) !Self {
            const column_len = column.len;
            const total = DEGREE * column_len;
            const buffer = try allocator.alloc(M31, total);
            // Copy base field into first coordinate
            @memcpy(buffer[0..column_len], column);
            // Zero the remaining 3 coordinates
            @memset(buffer[column_len..], M31.zero());
            var columns: [DEGREE]ColumnSlice = undefined;
            for (0..DEGREE) |i| {
                columns[i] = buffer[i * column_len .. (i + 1) * column_len];
            }
            return .{ .columns = columns, .owns_columns = true, .contiguous = true };
        }

        pub fn len(self: Self) usize {
            return self.columns[0].len;
        }

        pub fn isEmpty(self: Self) bool {
            return self.columns[0].len == 0;
        }

        pub fn cloneOwned(
            self: Self,
            allocator: std.mem.Allocator,
        ) !Self {
            const column_len = self.columns[0].len;
            const total = DEGREE * column_len;
            const buffer = try allocator.alloc(M31, total);
            for (0..DEGREE) |i| {
                @memcpy(buffer[i * column_len .. (i + 1) * column_len], self.columns[i]);
            }
            var columns: [DEGREE]ColumnSlice = undefined;
            for (0..DEGREE) |i| {
                columns[i] = buffer[i * column_len .. (i + 1) * column_len];
            }
            return .{
                .columns = columns,
                .representation = self.representation,
                .owns_columns = true,
                .contiguous = true,
            };
        }

        pub fn set(self: *Self, index: usize, value: Secure) void {
            const coords = value.toM31Array();
            for (0..@typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len) |i| {
                self.columns[i][index] = coords[i];
            }
        }

        pub fn toVec(self: Self, allocator: std.mem.Allocator) ![]Secure {
            const out = try allocator.alloc(Secure, self.len());
            for (0..out.len) |i| out[i] = self.at(i);
            return out;
        }

        pub fn fromSecureSlice(
            allocator: std.mem.Allocator,
            values: []const Secure,
        ) !Self {
            const column_len = values.len;
            const total = DEGREE * column_len;
            const buffer = try allocator.alloc(M31, total);
            var columns: [DEGREE]ColumnSlice = undefined;
            for (0..DEGREE) |i| {
                columns[i] = buffer[i * column_len .. (i + 1) * column_len];
            }
            for (values, 0..) |value, row| {
                const coords = value.toM31Array();
                for (0..DEGREE) |i| {
                    columns[i][row] = coords[i];
                }
            }
            return .{ .columns = columns, .owns_columns = true, .contiguous = true };
        }

        pub fn iter(self: *const Self) Iterator {
            return .{
                .column = self,
                .index = 0,
            };
        }

        pub const Iterator = struct {
            column: *const Self,
            index: usize,

            pub fn next(self: *Iterator) ?Secure {
                if (self.index >= self.column.len()) return null;
                const value = self.column.at(self.index);
                self.index += 1;
                return value;
            }
        };
    };
}

/// Compatibility type function for host-column backends.
/// Device-specific column ownership belongs in a backend implementation; this
/// type intentionally exposes mutable host slices for protocol code.
pub fn SecureColumnByCoordsGeneric(comptime B: type) type {
    if (B.ColumnType(M31) != []M31) {
        @compileError("SecureColumnByCoords requires host []M31 columns");
    }
    return SecureColumnByCoords;
}

test "secure column: generic type preserves host representation" {
    const HostBackend = struct {
        pub fn ColumnType(comptime F: type) type {
            return []F;
        }
    };
    try std.testing.expect(SecureColumnByCoordsGeneric(HostBackend) == SecureColumnByCoords);
}

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
