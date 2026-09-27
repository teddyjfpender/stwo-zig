//! Genuine Parent verification with only independently pinned compact public.
const std = @import("std");
const Bus = @import("block_v5_ram_range_forest_summary_bus_v1.zig");
const Protocol = @import("block_v5_ram_range_forest_summary_protocol_v1.zig");
const Raw = @import("block_v5_wide_public_windows_receiver_impl_v1.zig").ForModules(Bus, Protocol, Bus);
pub const Fresh = Raw.Fresh;
pub const Policy = struct { public: Bus.Policy, public_limits: Bus.Limits = .{}, max_proof_bytes: usize = 512 << 20 };
pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
    try policy.public.validate();
    const spec = policy.public.specs[policy.public.index];
    const key = try Protocol.Key.fromGeometry(spec.geometry, &.{});
    return Raw.verify(a, .{ .public = policy.public, .key = key, .expected_id = spec.expected_id, .schedule = &.{}, .public_limits = policy.public_limits, .max_proof_bytes = policy.max_proof_bytes }, bytes);
}
pub fn verifyRoot(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
    const root = policy.public.forest.geometry.root orelse return error.AbsentRamRangeForestRoot;
    if (policy.public.index != root) return error.UntrustedRamRangeForestRoot;
    return verify(a, policy, bytes);
}
