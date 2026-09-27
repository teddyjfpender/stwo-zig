//! Borrowed logical rows from canonical committed columns and compact fixed
//! metadata. Inventory audits one transient row; no duplicate row roster.
const std = @import("std");
const storage = @import("blake3_parent_row_storage.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const framework = @import("framework_interaction.zig");
pub fn ForAir(comptime Air: type) type {
    return struct {
        main: []const Column,
        fixed: []const storage.FixedRow(Air),
        log: u32,
        first: usize = 0,
        length: usize,
        pub fn init(main: []const Column, fixed: []const storage.FixedRow(Air)) !@This() {
            if (main.len != Air.PHYSICAL_MAIN_COLUMN_COUNT or main.len == 0 or main[0].log_size < 1 or main[0].log_size > 24) return error.InvalidNativeParentRows;
            const log = main[0].log_size;
            const capacity = @as(usize, 1) << @intCast(log);
            if (fixed.len > capacity) return error.InvalidNativeParentRows;
            for (main) |column| if (column.log_size != log or column.values.len != capacity) return error.InvalidNativeParentRows;
            return .{ .main = main, .fixed = fixed, .log = log, .length = fixed.len };
        }
        pub fn rowCount(self: @This()) usize {
            return self.length;
        }
        pub fn validate(self: @This()) !void {
            const whole = try @This().init(self.main, self.fixed);
            if (self.log != whole.log or self.first > self.fixed.len or self.length > self.fixed.len - self.first) return error.InvalidNativeParentRows;
        }
        pub fn subview(self: @This(), start: usize, count: usize) !@This() {
            try self.validate();
            if (start > self.length or count > self.length - start) return error.InvalidNativeParentRows;
            var result = self;
            result.first += start;
            result.length = count;
            return result;
        }
        pub fn rowAt(self: @This(), logical: usize) Air.Row {
            std.debug.assert(self.first <= self.fixed.len and self.length <= self.fixed.len - self.first);
            std.debug.assert(logical < self.length);
            const at = self.first + logical;
            const physical = framework.committedRow(at, self.log);
            var row: Air.Row = undefined;
            for (self.main, row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT]) |column, *word| word.* = column.values[physical];
            row[Air.PHYSICAL_MAIN_COLUMN_COUNT..].* = self.fixed[at];
            return row;
        }
    };
}
