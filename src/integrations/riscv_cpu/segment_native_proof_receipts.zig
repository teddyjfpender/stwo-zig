const std = @import("std");
const channel = @import("stwo_riscv_frontend").recursion.poseidon2_channel;

pub fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

pub fn printDigest(label: []const u8, value: channel.Digest) void {
    std.debug.print("  {s}=", .{label});
    for (value) |word| std.debug.print("{x:0>8}", .{word});
    std.debug.print("\n", .{});
}
