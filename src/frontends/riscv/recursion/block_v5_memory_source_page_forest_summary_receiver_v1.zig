//! Genuine fresh closed PAGE Parent verification from an independent compact
//! statement and exact expected key. Descendant leaf buffers are not retained.
const std = @import("std");
const Bus = @import("block_v5_memory_source_page_forest_summary_bus_v1.zig");
const Protocol = @import("block_v5_memory_source_page_forest_summary_protocol_v1.zig");
const OriginalReceiver = @import("block_v5_memory_source_page_forest_receiver_v1.zig");
const Raw = @import("block_v5_wide_public_windows_receiver_impl_v1.zig").ForModules(Bus, Protocol, Bus);
pub const Policy = OriginalReceiver.Policy;
pub const Fresh = Raw.Fresh;
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
