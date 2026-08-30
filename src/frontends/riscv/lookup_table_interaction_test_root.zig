const std = @import("std");

test {
    _ = @import("air/lookups/tables/interaction.zig");
    std.testing.refAllDecls(@This());
}
