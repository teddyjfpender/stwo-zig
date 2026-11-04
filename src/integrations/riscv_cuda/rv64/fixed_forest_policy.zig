//! Allocation policy only; this never grants device pointer authority.
//! Scoped token/generation/range validation remains at coefficient ingress.
const std = @import("std");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
pub fn isDeviceOnly(columns: []const D.Column) bool {
    if (columns.len == 0) return false;
    for (columns) |column| if (column.device == null) return false;
    return true;
}
test "only a complete device fixed forest bypasses immutable cloning" {
    var columns = [_]D.Column{
        .{ .log_size = 4, .device = .{ .words = @ptrFromInt(4096), .count = 16, .context_token = 1, .generation = 2 } },
        .{ .log_size = 4, .device = .{ .words = @ptrFromInt(8192), .count = 16, .context_token = 1, .generation = 3 } },
    };
    try std.testing.expect(isDeviceOnly(&columns));
    columns[1].device = null;
    try std.testing.expect(!isDeviceOnly(&columns));
    columns[0].device = null;
    try std.testing.expect(!isDeviceOnly(&columns));
    try std.testing.expect(!isDeviceOnly(&.{}));
}
