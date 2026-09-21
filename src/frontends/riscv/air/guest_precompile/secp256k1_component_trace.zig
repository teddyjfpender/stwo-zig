//! Compact transposed trace storage shared by all secp256k1 row families.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const core_utils = @import("stwo_core").utils;

pub const preprocessed_column_count: usize = 3;
pub const logup_first_column: usize = 0;
pub const group_first_column: usize = 1;
pub const group_last_column: usize = 2;

pub fn Trace(comptime Config: type) type {
    return struct {
        const Self = @This();
        pub const Row = [Config.main_column_count]M31;

        allocator: std.mem.Allocator,
        preprocessed_storage: []M31,
        main_storage: []M31,
        log_size: u32,
        n_rows: usize,

        pub fn init(
            allocator: std.mem.Allocator,
            rows: []const Row,
            group_first_rows: []const usize,
            group_last_rows: []const usize,
        ) !Self {
            if (rows.len == 0) return error.EmptyTrace;
            const log_size: u32 = @max(
                1,
                @as(u32, @intCast(std.math.log2_int_ceil(usize, rows.len))),
            );
            const size = @as(usize, 1) << @intCast(log_size);
            const preprocessed = try allocator.alloc(
                M31,
                preprocessed_column_count * size,
            );
            errdefer allocator.free(preprocessed);
            const main = try allocator.alloc(M31, Config.main_column_count * size);
            errdefer allocator.free(main);
            @memset(preprocessed, M31.zero());
            @memset(main, M31.zero());
            preprocessed[committedRow(0, log_size)] = M31.one();
            for (group_first_rows) |row| {
                if (row >= rows.len) return error.InvalidGroupBoundary;
                preprocessed[group_first_column * size + committedRow(row, log_size)] = M31.one();
            }
            for (group_last_rows) |row| {
                if (row >= rows.len) return error.InvalidGroupBoundary;
                preprocessed[group_last_column * size + committedRow(row, log_size)] = M31.one();
            }
            for (rows, 0..) |row, logical| {
                const destination = committedRow(logical, log_size);
                for (row, 0..) |value, column| {
                    main[column * size + destination] = value;
                }
            }
            return .{
                .allocator = allocator,
                .preprocessed_storage = preprocessed,
                .main_storage = main,
                .log_size = log_size,
                .n_rows = rows.len,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.main_storage);
            self.allocator.free(self.preprocessed_storage);
            self.* = undefined;
        }

        pub fn domainSize(self: *const Self) usize {
            return @as(usize, 1) << @intCast(self.log_size);
        }

        pub fn preprocessedColumn(self: *const Self, column: usize) []const M31 {
            std.debug.assert(column < preprocessed_column_count);
            const size = self.domainSize();
            return self.preprocessed_storage[column * size ..][0..size];
        }

        pub fn mainColumn(self: *const Self, column: usize) []const M31 {
            std.debug.assert(column < Config.main_column_count);
            const size = self.domainSize();
            return self.main_storage[column * size ..][0..size];
        }

        pub fn mainRow(self: *const Self, logical: usize) Row {
            var result: Row = undefined;
            const committed = committedRow(logical % self.domainSize(), self.log_size);
            for (&result, 0..) |*value, column| {
                value.* = self.mainColumn(column)[committed];
            }
            return result;
        }

        pub fn groupFirst(self: *const Self, logical: usize) M31 {
            return self.preprocessedColumn(group_first_column)[
                committedRow(logical % self.domainSize(), self.log_size)
            ];
        }

        pub fn groupLast(self: *const Self, logical: usize) M31 {
            return self.preprocessedColumn(group_last_column)[
                committedRow(logical % self.domainSize(), self.log_size)
            ];
        }
    };
}

pub inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}
