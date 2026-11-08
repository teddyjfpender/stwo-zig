//! Focused component orchestration and allocation-rollback regression.
comptime {
    _ = @import("air/components.zig");
    // The public wrapper exports lazy aliases. Discover the test owners
    // directly so the exact-name guard cannot mistake zero tests for success.
    _ = @import("air/components_family.zig");
    _ = @import("pcs/utils.zig");
}
