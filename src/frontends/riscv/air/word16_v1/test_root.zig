//! Dormant standalone test root; not added to any live suite or inventory.
comptime {
    _ = @import("spec_test.zig");
    _ = @import("projection_test.zig");
}
