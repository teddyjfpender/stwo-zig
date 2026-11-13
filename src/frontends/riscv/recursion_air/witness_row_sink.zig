//! Output layouts for bulk-admitted witness row generators. Neither sink admits
//! a reference or witness; callers must do so before emitting any rows.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

pub fn Columns(comptime count: usize) type {
    return struct {
        columns: *[count][]M31,
        pub fn write(self: *@This(), index: usize, _: anytype, main: anytype) void {
            for (self.columns, main.values()) |column, value| column[index] = value;
        }
    };
}
pub const Discard = struct {
    pub fn write(_: *@This(), _: usize, _: anytype, _: anytype) void {}
};

pub fn Logical(comptime Air: type) type {
    return struct {
        const Self = @This();
        const Row = [Air.LOGICAL_INPUT_COUNT]M31;
        const parameter_count = Air.LOGICAL_INPUT_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT - Air.PREPROCESSED_COLUMN_COUNT;
        rows: []Row,
        first: usize,
        lane: u32,
        parameters: [parameter_count]M31,

        pub fn init(allocator: std.mem.Allocator, metadata: anytype, lane: u32, parameters: [parameter_count]M31) !Self {
            var first: usize = metadata.len;
            var count: usize = 0;
            for (metadata, 0..) |row, index| if (row.verifier_id == lane) {
                if (count == 0) first = index;
                if (index != first + count) return error.InvalidWitness;
                count += 1;
            };
            return .{ .rows = try allocator.alloc(Row, count), .first = first, .lane = lane, .parameters = parameters };
        }
        pub fn write(self: *Self, index: usize, metadata: anytype, main: anytype) void {
            if (metadata.verifier_id != self.lane) return;
            self.rows[index - self.first] = main.values() ++ metadata.values() ++ self.parameters;
        }
    };
}
