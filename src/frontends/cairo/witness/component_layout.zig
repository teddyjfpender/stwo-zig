//! Backend-neutral runtime geometry for one Cairo witness component.

const std = @import("std");

pub const Error = error{
    EmptyComponent,
    InvalidColumnCount,
    InvalidRowCount,
};

pub const ComponentLayout = struct {
    ordinal: u32,
    label: []const u8,
    row_count: u32,
    column_count: u32,

    pub fn validate(self: ComponentLayout) Error!void {
        if (self.label.len == 0) return Error.EmptyComponent;
        if (self.column_count == 0) return Error.InvalidColumnCount;
        if (self.row_count < 16 or !std.math.isPowerOfTwo(self.row_count))
            return Error.InvalidRowCount;
    }

    pub fn logSize(self: ComponentLayout) u32 {
        return std.math.log2_int(u32, self.row_count);
    }
};

test "Cairo component layout admits only nonempty power-of-two domains" {
    const valid = ComponentLayout{
        .ordinal = 7,
        .label = "ret_opcode",
        .row_count = 16,
        .column_count = 3,
    };
    try valid.validate();
    try std.testing.expectEqual(@as(u32, 4), valid.logSize());

    var invalid = valid;
    invalid.row_count = 17;
    try std.testing.expectError(Error.InvalidRowCount, invalid.validate());
    invalid = valid;
    invalid.column_count = 0;
    try std.testing.expectError(Error.InvalidColumnCount, invalid.validate());
}
