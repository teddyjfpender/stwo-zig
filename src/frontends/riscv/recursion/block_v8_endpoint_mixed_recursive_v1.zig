//! One native Mixed original -> conditional recursive source root. All native
//! member residuals and shared providers close in-circuit. Global RAM remains
//! OPEN until a join binds every exported endpoint root to bridge/global roots.
const Self = @This();
pub const Original = @import("../prover/block_v8_endpoint_mixed_proof_v1.zig");
pub const Statement = @import("../prover/block_v8_endpoint_mixed_statement_v1.zig");
pub const Profile = @import("block_v8_endpoint_mixed_profile_v1.zig");
pub const Composition = @import("air/block_v8_endpoint_mixed_composition_v1.zig");
pub const Transcript = @import("air/block_v8_endpoint_mixed_transcript_v1.zig");
pub const Ledger = @import("../prover/block_v8_endpoint_mixed_ledger_v1.zig");
pub const PcsProfile = @import("block_v8_endpoint_recursive_pcs_profile_v1.zig").With(Self);
pub const Pcs = @import("block_v8_endpoint_recursive_pcs_preparation_v1.zig").With(Self);
pub const Public = @import("block_v8_endpoint_recursive_public_v1.zig").With(Self);
pub const Preparation = @import("block_v8_endpoint_recursive_preparation_v1.zig").With(Self);
pub const Fixed = @import("block_v8_endpoint_recursive_fixed_roster_v1.zig").With(Self);
pub const Protocol = @import("block_v8_endpoint_recursive_protocol_v1.zig").With(Self);
pub const Receiver = @import("block_v8_endpoint_recursive_receiver_v1.zig").With(Self);
pub const Pipeline = @import("block_v8_endpoint_recursive_pipeline_v1.zig").With(Self);
pub const IDENTITY_TAG: u32 = 0x42384d49;
pub const SCHEDULE_TAG: u32 = 0x42384d53;
pub const VALUES_TAG: u32 = 0x42384d56;
pub const ROSTER_TAG: u32 = 0x42384d52;
pub const tags: @import("block_v6_direct_batch_protocol_v1.zig").Domains = .{ .key = 0x42384d4b, .public_input = 0x42384d49, .proof = 0x42384d50, .claims = 0x42384d43 };
pub const production_active = false;
pub const global_ram_closed = false;
pub fn firstRoots(_: *const Profile.Owned) usize {
    return 7;
}
pub fn rootsShape(count: usize) bool {
    return count == 7;
}
pub fn epoch(p: *const Profile.Owned) @import("../prover/block_v7_execution_epoch_v1.zig").Epoch {
    return p.scope.epoch;
}
pub fn summary(p: *const Profile.Owned) !Ledger.Summary {
    return p.context.close();
}
