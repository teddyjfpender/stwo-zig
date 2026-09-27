//! Reopens the already-produced native proof under independent expected pins.
const std = @import("std");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Codec = @import("block_v5_native_codec_v3.zig");

pub fn reopen(a: std.mem.Allocator, proof: *const Native.Proof, expected: Codec.Expected) !Native.Proof {
    const raw = try Codec.encode(a, proof, expected, .{});
    defer a.free(raw);
    var changed = expected;
    changed.instance_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeV3WireIdentity, Codec.decode(a, raw, changed, .{}));
    const trailing = try a.alloc(u8, raw.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..raw.len], raw);
    trailing[raw.len] = 0;
    try std.testing.expectError(error.TrailingSectionBytes, Codec.decode(a, trailing, expected, .{}));
    return Codec.decode(a, raw, expected, .{});
}
