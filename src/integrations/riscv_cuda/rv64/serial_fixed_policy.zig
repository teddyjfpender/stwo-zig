//! Candidate admission only. Runtime backend telemetry comes from the factory.
const std = @import("std");
pub fn validate(combined: bool, recursion_mode: []const u8, requested: bool) !void {
    if (!requested) return;
    if (!combined or !std.mem.eql(u8, recursion_mode, "serial")) return error.DeviceFixedCandidateRequiresSerialCombined;
    // Physical device count is checked by the unchanged combined1-GPU guard.
}
test "device fixed manifest flag stays off by default and cannot combine with ready or native routes" {
    try validate(false, "serial", false);
    try validate(true, "serial", false);
    try validate(true, "serial", true);
    try std.testing.expectError(error.DeviceFixedCandidateRequiresSerialCombined, validate(false, "serial", true));
    try std.testing.expectError(error.DeviceFixedCandidateRequiresSerialCombined, validate(true, "ready_candidate", true));
    try std.testing.expectError(error.DeviceFixedCandidateRequiresSerialCombined, validate(true, "unknown", true));
}
