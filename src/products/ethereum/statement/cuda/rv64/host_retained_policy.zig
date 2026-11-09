//! Explicit basket control: host-spilled MAIN, GPU numerical stages.
//! Device-only MAIN and binding leases cannot be evicted at the manifest barrier.
const std = @import("std");
pub fn validate(enabled: bool, library: bool, pool: bool, device_trace: bool, device_binding: bool) !void {
    if (!enabled) return;
    if (!library) return error.HostRetainedRequiresNativeLibrary;
    if (pool or device_trace or device_binding) return error.HostRetainedRequiresHostTrace;
}
test "host retained control requires native GPU stages and host backed traces" {
    try validate(true, true, false, false, false);
    try std.testing.expectError(error.HostRetainedRequiresNativeLibrary, validate(true, false, false, false, false));
    try std.testing.expectError(error.HostRetainedRequiresHostTrace, validate(true, true, true, false, false));
    try std.testing.expectError(error.HostRetainedRequiresHostTrace, validate(true, true, false, true, false));
    try std.testing.expectError(error.HostRetainedRequiresHostTrace, validate(true, true, false, false, true));
    try validate(false, false, true, true, true);
}
