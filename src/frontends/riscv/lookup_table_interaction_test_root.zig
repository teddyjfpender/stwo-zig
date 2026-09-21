const std = @import("std");

test {
    _ = @import("air/lookups/tables/interaction.zig");
    _ = @import("air/lookups/tables/framework_export.zig");
    _ = @import("air/lookups/tables/component_prepared_test.zig");
    std.testing.refAllDecls(@This());
}
