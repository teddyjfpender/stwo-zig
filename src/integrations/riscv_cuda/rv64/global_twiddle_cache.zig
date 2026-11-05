//! The cache is indexed directly by domain log, including the separately
//! admitted public-boundary domain. Slot count must include that final index.
const std = @import("std");
const Boundary = @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.DeviceGlobal;
pub fn Table(comptime Twiddle: type) type {
    return [Boundary.MAX_PUBLIC_BOUNDARY_LOG + 1]?Twiddle;
}
test "global twiddle cache covers the highest admitted public boundary log" {
    var slots: Table(u32) = @splat(null);
    slots[Boundary.MAX_PUBLIC_BOUNDARY_LOG] = 17;
    try std.testing.expectEqual(@as(usize, Boundary.MAX_PUBLIC_BOUNDARY_LOG + 1), slots.len);
    try std.testing.expectEqual(@as(?u32, 17), slots[Boundary.MAX_PUBLIC_BOUNDARY_LOG]);
}
