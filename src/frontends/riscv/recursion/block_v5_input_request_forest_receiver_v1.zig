//! Fresh node verification uses independently reconstructed exact geometry,
//! schedule and job statement. No manifest key or sibling receipt is authority.
const std = @import("std");
const Layout = @import("block_v5_input_request_forest_public_v1.zig");
const Protocol = @import("block_v5_input_request_forest_protocol_v1.zig");
const Raw = @import("block_v5_wide_public_windows_receiver_impl_v1.zig").ForModules(@import("block_v5_input_request_forest_bus_v1.zig"), Protocol, @import("block_v5_input_request_forest_bus_v1.zig"));
pub const Fresh = Raw.Fresh;
pub const Policy = struct { public: Layout.Policy, public_limits: Layout.Limits = .{}, max_proof_bytes: usize = 512 << 20 };
pub fn admit(policy: Policy) !Raw.Policy {
    try policy.public.validate();
    const spec = policy.public.specs[policy.public.index];
    const key = try Protocol.Key.fromGeometry(spec.geometry, spec.schedule);
    if (!std.meta.eql(try key.identity(), spec.expected_id)) return error.UntrustedInputRequestNode;
    return .{ .public = policy.public, .key = key, .expected_id = spec.expected_id, .schedule = spec.schedule, .public_limits = policy.public_limits, .max_proof_bytes = policy.max_proof_bytes };
}
pub fn verify(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
    return Raw.verify(a, try admit(policy), bytes);
}
/// Root-only entrypoint; an interior proof cannot masquerade as complete input
/// request coverage. Original source/global/provider completeness stays OPEN.
pub fn verifyRoot(a: std.mem.Allocator, policy: Policy, bytes: []const u8) !*Fresh {
    try policy.public.validate();
    if (policy.public.index != policy.public.forest.geometry.root) return error.UntrustedInputRequestForestRoot;
    return verify(a, policy, bytes);
}
