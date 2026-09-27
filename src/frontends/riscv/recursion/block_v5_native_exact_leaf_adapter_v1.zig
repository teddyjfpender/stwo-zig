//! Existing NativeV3 exact leaf policy; default behavior is preserved.
const std = @import("std");
const normalized = @import("block_v5_open_child_frames_v2.zig");
pub const Policy = @import("block_v5_open_parent_receiver_v1.zig").ExpectedChild;
pub const Wire = @import("block_v5_recursive_public_bus_v1.zig").Wire;
pub fn normalize(a: std.mem.Allocator, policy: Policy) !normalized.Child {
    return normalized.fromNative(a, policy.native, policy.exported, policy.recursive_key, policy.recursive_key_id, policy.recursive_schedule);
}
pub fn verify(a: std.mem.Allocator, bytes: []const u8, policy: Policy) !@import("blake3_native_parent_verifier.zig").Verified {
    const checked = try @import("block_v5_reusable_native_leaf_v1.zig").verify(a, bytes, policy.recursive_key, policy.recursive_key_id, policy.recursive_schedule, policy.native, policy.exported);
    return checked.equation;
}
