//! Conditional recursive late bridge. The final DAG must bind this exact
//! endpoint-root roster to local execution roots and close the aggregate with
//! the global provider root. This module alone grants no RAM/execution closure.
const Self = @This();
const core = @import("stwo_core");
pub const Original = @import("../prover/block_v8_compact_ram_proof_v1.zig");
pub const Statement = @import("block_v8_compact_ram_statement_v1.zig");
pub const Profile = @import("block_v8_compact_ram_profile_v1.zig");
pub const Composition = @import("air/block_v8_compact_ram_composition_v1.zig");
pub const Transcript = @import("air/block_v8_compact_ram_transcript_v1.zig");
pub const Ledger = struct {
    pub const Claims = Original.Claims;
    pub const Summary = Original.Open;
};
pub const PcsProfile = @import("block_v8_endpoint_recursive_pcs_profile_v1.zig").With(Self);
pub const Pcs = @import("block_v8_endpoint_recursive_pcs_preparation_v1.zig").With(Self);
pub const Public = @import("block_v8_endpoint_recursive_public_v1.zig").With(Self);
pub const Preparation = @import("block_v8_endpoint_recursive_preparation_v1.zig").With(Self);
pub const Fixed = @import("block_v8_endpoint_recursive_fixed_roster_v1.zig").With(Self);
pub const Protocol = @import("block_v8_endpoint_recursive_protocol_v1.zig").With(Self);
pub const Receiver = @import("block_v8_endpoint_recursive_receiver_v1.zig").With(Self);
pub const Pipeline = @import("block_v8_endpoint_recursive_pipeline_v1.zig").With(Self);
pub const IDENTITY_TAG: u32 = 0x42384349;
pub const SCHEDULE_TAG: u32 = 0x42384353;
pub const VALUES_TAG: u32 = 0x42384356;
pub const ROSTER_TAG: u32 = 0x42384352;
pub const tags: @import("block_v6_direct_batch_protocol_v1.zig").Domains = .{ .key = 0x4238434b, .public_input = 0x42384349, .proof = 0x42384350, .claims = 0x42384343 };
pub fn firstRoots(p: *const Profile.Owned) usize {
    _ = p;
    return 4;
}
pub fn rootsShape(count: usize) bool {
    return count == 4;
}
pub fn epoch(p: *const Profile.Owned) @import("../prover/block_v7_execution_epoch_v1.zig").Epoch {
    return p.statement.input.epoch;
}
pub fn summary(p: *const Profile.Owned) !Ledger.Summary {
    return .{ .transition = p.claims.ram[0], .event_count = p.scope.event_count };
}
pub const production_active = false;
pub const global_ram_closed = false;
