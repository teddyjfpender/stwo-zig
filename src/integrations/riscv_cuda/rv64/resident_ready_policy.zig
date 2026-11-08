//! Explicit operational candidate admission; serial remains the default.
const std = @import("std");
pub const Mode = enum { serial, ready_candidate };
pub const helper_stack_bytes: usize = 1 << 20;
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
