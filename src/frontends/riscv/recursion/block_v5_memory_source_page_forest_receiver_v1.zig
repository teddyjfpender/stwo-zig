//! Genuine fresh recursive PAGE aggregate receiver; all node keys/schedules
//! derive independently from original child rows and typed source setup.
const std = @import("std");
const Bus = @import("block_v5_memory_source_page_forest_bus_v1.zig");
const Protocol = @import("block_v5_memory_source_page_forest_protocol_v1.zig");
const Raw = @import("block_v5_wide_public_windows_receiver_impl_v1.zig").ForModules(Bus, Protocol, Bus);
pub const Fresh = Raw.Fresh;
pub const Policy = struct { public: Bus.Policy, public_limits: Bus.Limits = .{}, max_proof_bytes: usize = 512 << 20 };
pub fn admit(policy: Policy) !Raw.Policy {
    try policy.public.validate();
    const spec = policy.public.specs[policy.public.index];
    const key = try Protocol.Key.fromGeometry(spec.geometry, spec.schedule);
    if (!std.meta.eql(try key.identity(), spec.expected_id)) return error.UntrustedPageForestNode;
    return .{ .public = policy.public, .key = key, .expected_id = spec.expected_id, .schedule = spec.schedule, .public_limits = policy.public_limits, .max_proof_bytes = policy.max_proof_bytes };
}
pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
    return Raw.verify(a, try admit(policy), bytes);
}
pub fn verifyRoot(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
    try policy.public.validate();
    const root = policy.public.forest.geometry.root orelse return error.AbsentPageForestRoot;
    if (policy.public.index != root) return error.UntrustedPageForestRoot;
    return verify(a, policy, bytes);
}
