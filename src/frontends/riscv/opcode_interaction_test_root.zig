const std = @import("std");

test {
    _ = @import("air/lookups/opcode_interaction_test.zig");
    std.testing.refAllDecls(@This());
}
