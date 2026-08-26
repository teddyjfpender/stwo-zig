//! Focused compile/run root for the complete native typed-AIR profile registry.

comptime {
    _ = @import("air/lang/static_profile_registry_artifact_test.zig");
    _ = @import("air/lang/static_profile_registry_test.zig");
}
