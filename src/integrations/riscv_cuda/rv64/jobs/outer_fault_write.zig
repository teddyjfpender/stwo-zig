//! Test-owned PCS enqueue mutation. Production has no process fault selector.
const Buffer = @import("resources.zig").DeviceBuffer;
const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;

pub fn pcs(ctx: *anyopaque, fill: Memset, buffer: Buffer, at: u64) !void {
    if (!@import("builtin").is_test) return error.TestOnlyOuterFault;
    if (at >= buffer.words) return error.OuterEncodeFaultOutOfRange;
    if (fill(ctx, @ptrCast(buffer.ptr + @as(usize, @intCast(at))), 0xff, 4) != 0)
        return error.OuterEncodeEnqueueFailed;
}
test {
    _ = @import("outer_fault_write_test.zig");
}
