//! Structural OUT selection only; CPU dispatch still owns mode/profile admission.
const std = @import("std");
pub fn directory(a: std.mem.Allocator, args: []const [:0]const u8) !?[]u8 {
    const offset: usize = if (args.len > 1 and std.mem.eql(u8, args[1], "--security-profile")) 2 else 0;
    if (args.len != 7 + offset) return null;
    const mode = args[1 + offset];
    if (!std.mem.eql(u8, mode, "produce-candidate") and !std.mem.eql(u8, mode, "produce-control")) return null;
    if (args[4 + offset].len == 0) return null;
    return try std.fs.path.join(a, &.{ args[4 + offset], ".gpu-hybrid" });
}
test {
    _ = @import("hybrid_scratch_output_test.zig");
}
