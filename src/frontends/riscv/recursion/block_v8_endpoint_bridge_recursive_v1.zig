//! Conditional recursive late bridge. The final DAG must bind this exact
//! endpoint-root roster to local execution roots and close the aggregate with
//! the global provider root. This module alone grants no RAM/execution closure.
const Self = @This();
const core = @import("stwo_core");
pub const Original = @import("../prover/block_v8_endpoint_global_bridge_proof_v1.zig");
pub const Statement = @import("block_v8_endpoint_bridge_statement_v1.zig");
pub const Profile = @import("block_v8_endpoint_bridge_profile_v1.zig");
pub const Composition = @import("air/block_v8_endpoint_bridge_composition_v1.zig");
pub const Transcript = @import("air/block_v8_endpoint_bridge_transcript_v1.zig");
pub const Ledger = struct {
    pub const Claims = []const core.fields.qm31.QM31;
    pub const Summary = struct {
        transition: core.fields.qm31.QM31,
        epoch: [32]u8,
        batch_first: u32,
        batch_count: u32,
        roster_count: u32,
        scope: enum { conditional_endpoint_root_rebinding } = .conditional_endpoint_root_rebinding,
    };
};
pub const PcsProfile = @import("block_v8_endpoint_recursive_pcs_profile_v1.zig").With(Self);
pub const Pcs = @import("block_v8_endpoint_recursive_pcs_preparation_v1.zig").With(Self);
pub const Public = @import("block_v8_endpoint_recursive_public_v1.zig").With(Self);
pub const Preparation = @import("block_v8_endpoint_recursive_preparation_v1.zig").With(Self);
pub const Fixed = @import("block_v8_endpoint_recursive_fixed_roster_v1.zig").With(Self);
pub const Protocol = @import("block_v8_endpoint_recursive_protocol_v1.zig").With(Self);
pub const Receiver = @import("block_v8_endpoint_recursive_receiver_v1.zig").With(Self);
pub const Pipeline = @import("block_v8_endpoint_recursive_pipeline_v1.zig").With(Self);
pub const IDENTITY_TAG: u32 = 0x42384249;
pub const SCHEDULE_TAG: u32 = 0x42384253;
pub const VALUES_TAG: u32 = 0x42384256;
pub const ROSTER_TAG: u32 = 0x42384252;
pub const tags: @import("block_v6_direct_batch_protocol_v1.zig").Domains = .{ .key = 0x4238424b, .public_input = 0x42384249, .proof = 0x42384250, .claims = 0x42384243 };
pub fn firstRoots(p: *const Profile.Owned) usize {
    return 1 + p.scope.sources.len;
}
pub fn rootsShape(count: usize) bool {
    return count >= 2 and count <= 128;
}
pub fn epoch(p: *const Profile.Owned) @import("../prover/block_v7_execution_epoch_v1.zig").Epoch {
    return p.scope.epoch;
}
pub fn summary(p: *const Profile.Owned) !Ledger.Summary {
    var sum = core.fields.qm31.QM31.zero();
    for (p.claims) |claim| sum = sum.add(claim);
    return .{ .transition = sum, .epoch = p.scope.epoch.digest, .batch_first = p.scope.batch_start, .batch_count = @intCast(p.scope.sources.len), .roster_count = p.scope.roster_count };
}
pub const production_active = false;
pub const global_ram_closed = false;
