//! Candidate admission only. Runtime backend telemetry comes from the factory.
const std = @import("std");
pub fn validate(combined: bool, recursion_mode: []const u8, requested: bool) !void {
    if (!requested) return;
    if (!combined or !(std.mem.eql(u8, recursion_mode, "serial") or std.mem.eql(u8, recursion_mode, "ready_candidate"))) return error.DeviceFixedCandidateRequiresCombined;
    // Serial keeps its one-device guard; ready keeps per-device lanes and bounds.
}
test "device fixed manifest flag stays off by default and requires explicit combined serial or ready routes" {
    try validate(false, "serial", false);
    try validate(true, "serial", false);
    try validate(true, "serial", true);
    try std.testing.expectError(error.DeviceFixedCandidateRequiresCombined, validate(false, "serial", true));
    try validate(true, "ready_candidate", true);
    try std.testing.expectError(error.DeviceFixedCandidateRequiresCombined, validate(true, "unknown", true));
}
