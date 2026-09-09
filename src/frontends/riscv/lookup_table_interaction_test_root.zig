const std = @import("std");

test {
    _ = @import("air/lookups/tables/interaction.zig");
    _ = @import("air/lookups/tables/framework_export.zig");
    std.testing.refAllDecls(@This());
}
