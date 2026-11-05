//! Explicit operational candidate admission; serial remains the default.
const std = @import("std");
pub const Mode = enum { serial, ready_candidate };
pub const helper_stack_bytes: usize = 1 << 20;
/// sched M6: concurrent outer proofs per physical device (1 = M5). Each lane
/// has its own outer context and helper pool; the device and its native
/// session are shared. Scheduling only.
pub fn lanesPerDevice() !usize {
    const text = std.posix.getenv("STWO_RV64_RECURSION_LANES_PER_DEVICE") orelse return 1;
    const value = std.fmt.parseUnsigned(usize, text, 10) catch return error.InvalidResidentReadyAdmission;
    if (value == 0 or value > 2) return error.InvalidResidentReadyAdmission;
    return value;
}
/// Independent native owner per recursion lane. Operational opt-in until
/// the paired memory/throughput gate passes with the physical arena cap.
pub fn parseLaneSessions(text: ?[]const u8) !bool {
    const value = text orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidRecursionLaneSessions;
}
pub fn laneSessions() !bool {
    return parseLaneSessions(std.posix.getenv("STWO_RV64_RECURSION_LANE_SESSIONS"));
}
pub fn workers(mode: Mode, ids: []const u32, total: usize, pending: usize) ![4]usize {
    if (mode == .serial) {
        if (ids.len != 1) return error.MultiGpuCombinedRecursionNotImplemented;
        return @splat(0);
    }
    if (ids.len == 0 or ids.len > 4 or total < ids.len or total > 32 or pending < 9 + 2 * ids.len or pending > 256) return error.InvalidResidentReadyAdmission;
    for (ids, 0..) |id, i| for (ids[0..i]) |previous| if (previous == id) return error.DuplicateResidentDevice;
    var out: [4]usize = @splat(0);
    for (0..ids.len) |i| out[i] = total / ids.len + @intFromBool(i < total % ids.len);
    return out;
}
test "resident ready mode is explicit and distributes a bounded total worker budget" {
    try std.testing.expectError(error.MultiGpuCombinedRecursionNotImplemented, workers(.serial, &.{ 0, 1 }, 8, 17));
    try std.testing.expectEqual([_]usize{ 8, 0, 0, 0 }, try workers(.ready_candidate, &.{0}, 8, 17));
    try std.testing.expectEqual([_]usize{ 4, 4, 0, 0 }, try workers(.ready_candidate, &.{ 1, 3 }, 8, 17));
    try std.testing.expectEqual([_]usize{ 2, 2, 2, 2 }, try workers(.ready_candidate, &.{ 0, 1, 2, 3 }, 8, 17));
    try std.testing.expectEqual([_]usize{ 3, 2, 0, 0 }, try workers(.ready_candidate, &.{ 0, 1 }, 5, 17));
    try std.testing.expectError(error.DuplicateResidentDevice, workers(.ready_candidate, &.{ 1, 1 }, 8, 17));
    try std.testing.expectError(error.InvalidResidentReadyAdmission, workers(.ready_candidate, &.{ 0, 1 }, 1, 17));
    try std.testing.expectError(error.InvalidResidentReadyAdmission, workers(.ready_candidate, &.{0}, 33, 17));
    try std.testing.expectError(error.InvalidResidentReadyAdmission, workers(.ready_candidate, &.{ 0, 1, 2, 3 }, 8, 16));
    try std.testing.expectError(error.InvalidResidentReadyAdmission, workers(.ready_candidate, &.{}, 8, 17));
}


test "recursion lane sessions are a strict independent opt-in" {
    try std.testing.expect(!try parseLaneSessions(null));
    try std.testing.expect(!try parseLaneSessions("0"));
    try std.testing.expect(try parseLaneSessions("1"));
    for ([_][]const u8{ "", "true", "2", "01", " 1" }) |value| try std.testing.expectError(error.InvalidRecursionLaneSessions, parseLaneSessions(value));
}
