//! Pure source fixtures only. No CUDA ABI or device execution.
test {
    _ = @import("scheduled_admission_test_v1.zig");
    _ = @import("common/scheduled_executor.zig");
    _ = @import("common/driver.zig");
}
