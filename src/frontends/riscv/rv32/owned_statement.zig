//! Explicit ownership for variable-length RISC-V statement data.

const std = @import("std");
const public_data = @import("air/public_data.zig");
const statement = @import("air/statement.zig");

/// A statement whose variable-length public I/O is owned by this value.
///
/// Plain `RiscVStatement` values borrow their public-I/O slices. ELF adapters
/// that return a statement use this wrapper so those slices cannot point into
/// execution buffers released before the caller inspects the statement.
pub const OwnedRiscVStatement = struct {
    statement: statement.RiscVStatement,
    input_words: []u32,
    output_words: []public_data.OutputWord,

    pub fn init(
        value: statement.RiscVStatement,
        input_words: []u32,
        output_words: []public_data.OutputWord,
    ) OwnedRiscVStatement {
        return .{ .statement = value, .input_words = input_words, .output_words = output_words };
    }

    pub fn deinit(self: *OwnedRiscVStatement, allocator: std.mem.Allocator) void {
        allocator.free(self.input_words);
        allocator.free(self.output_words);
        self.* = undefined;
    }
};

test {
    std.testing.refAllDecls(@This());
}
