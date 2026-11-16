//! Explicit basket control: host-spilled MAIN, GPU numerical stages.
//! Device-only MAIN and binding leases cannot be evicted at the manifest barrier.
const std = @import("std");
pub fn validate(enabled: bool, library: bool, pool: bool, device_trace: bool, device_binding: bool) !void {
    if (!enabled) return;
    if (!library) return error.HostRetainedRequiresNativeLibrary;
    if (pool or device_trace or device_binding) return error.HostRetainedRequiresHostTrace;
}
/// Trace selection owns binding; validate actual installed stage capability.
pub fn requireBinding(device_trace: bool, binding_ready: bool) !void {
    if (binding_ready and !device_trace) return error.DeviceBindingRequiresResidentTraceCommit;
    if (device_trace and !binding_ready) return error.FullyResidentBindingRequired;
}
test "host retained control requires native GPU stages and host backed traces" {
    try validate(true, true, false, false, false);
    try std.testing.expectError(error.HostRetainedRequiresNativeLibrary, validate(true, false, false, false, false));
    try std.testing.expectError(error.HostRetainedRequiresHostTrace, validate(true, true, true, false, false));
    try std.testing.expectError(error.HostRetainedRequiresHostTrace, validate(true, true, false, true, false));
    try std.testing.expectError(error.HostRetainedRequiresHostTrace, validate(true, true, false, false, true));
    try validate(false, false, true, true, true);
}

test "device trace requires real binding while hybrid cannot retain a binding capability" {
    try requireBinding(false, false);
    try requireBinding(true, true);
    try std.testing.expectError(error.DeviceBindingRequiresResidentTraceCommit, requireBinding(false, true));
    try std.testing.expectError(error.FullyResidentBindingRequired, requireBinding(true, false));
}
