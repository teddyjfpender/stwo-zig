//! Genuine capacity-native exact leaf policy. Fresh native OpenReceipt must
//! originate inside the independent base receiver; it is not proof authority.
const std = @import("std");
const normalized = @import("block_v5_open_child_frames_v2.zig");
const bus = @import("block_v5_capacity_recursive_public_bus_v1.zig");
const protocol = @import("block_v5_reusable_capacity_parent_protocol_v1.zig");
pub const Wire = bus.Wire;
pub const Policy = struct {
    native: *const @import("../prover/block_v5_native_capacity_recursive_admission_v1.zig").Prepared,
    exported: @import("../prover/block_v5_native_capacity_proof_v1.zig").OpenReceipt,
    recursive_key: protocol.Key,
    recursive_key_id: [32]u8,
    recursive_schedule: []const Wire,
};
pub fn normalize(a: std.mem.Allocator, policy: Policy) !normalized.Child {
    return normalized.fromCapacity(a, policy.native, policy.exported, policy.recursive_key, policy.recursive_key_id, policy.recursive_schedule);
}
pub fn verify(a: std.mem.Allocator, bytes: []const u8, policy: Policy) !@import("blake3_native_parent_verifier.zig").Verified {
    const checked = try @import("block_v5_capacity_recursive_leaf_v1.zig").verify(a, bytes, policy.recursive_key, policy.recursive_key_id, policy.recursive_schedule, policy.native, policy.exported);
    return checked.equation;
}
