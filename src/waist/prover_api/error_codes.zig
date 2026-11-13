//! Exact column-admission diagnostics, not an outer anyerror classifier.
const Entry = @import("stwo_core").error_codes.Entry;
const ColumnError = @import("column.zig").QuotientOpsError;
pub const ColumnFailure = struct { cause: ColumnError, entry: Entry };
pub const table = [_]Entry{
    .{ .tag = "ShapeMismatch", .code = 0x3001, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidColumnLogSize", .code = 0x3002, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidColumnLength", .code = 0x3003, .class = .invalid_input, .since = "1.0.0-rc.2" },
};

pub fn fromColumn(err: ColumnError) Entry {
    return switch (err) {
        error.ShapeMismatch => table[0],
        error.InvalidColumnLogSize => table[1],
        error.InvalidColumnLength => table[2],
    };
}

pub fn recordColumnFailure(output: ?*?ColumnFailure, err: ColumnError) ColumnError {
    if (output) |sink| if (sink.* == null) {
        sink.* = .{ .cause = err, .entry = fromColumn(err) };
    };
    return err;
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}

test {
    _ = @import("error_codes_test.zig");
}
