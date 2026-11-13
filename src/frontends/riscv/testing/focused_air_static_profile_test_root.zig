//! Focused compile/run root for deterministic typed-AIR static profiling.

comptime {
    _ = @import("cases/air/lang/tests/static_profile_test.zig");
}
