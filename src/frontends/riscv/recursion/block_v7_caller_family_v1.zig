//! Type-level policy selection for one caller verifier implementation. Full
//! and finite active families use distinct admissions and transcript domains.
pub fn For(comptime selected: bool) type {
    return struct {
        const Self = @This();
        pub const active = selected;
        pub const Source = if (selected) @import("../prover/block_v7_caller_active_source_v1.zig") else @import("../prover/block_v7_caller_joint_source_v1.zig");
        pub const Proof = if (selected) @import("../prover/block_v7_caller_active_proof_v1.zig") else @import("../prover/block_v7_caller_joint_proof_v1.zig");
        pub const Assembly = if (selected) @import("../prover/block_v7_caller_active_assembly_v1.zig").Assembly else @import("../prover/blake3_ethereum_sha_profile.zig").Assembly;
        pub const public_circuit: u32 = if (selected) 4_200_061 else 4_200_041;
        pub const identity_tag: u32 = if (selected) 0x42375a49 else 0x42374b49;
        pub const schedule_tag: u32 = if (selected) 0x42375a57 else 0x42374b57;
        pub const values_tag: u32 = if (selected) 0x42375a56 else 0x42374b56;
        pub const roster_tag: u32 = if (selected) 0x42375a52 else 0x42374b52;
        pub const tags: @import("block_v6_direct_batch_protocol_v1.zig").Domains = if (selected) .{ .key = 0x42375a4b, .public_input = 0x42375a49, .proof = 0x42375a50, .claims = 0x42375a43 } else .{ .key = 0x42374b4b, .public_input = 0x42374b49, .proof = 0x42374b50, .claims = 0x42374b43 };
        pub const Admission = @import("../prover/block_v7_caller_recursive_admission_v1.zig").For(Self);
        pub const Capture = @import("../prover/block_v7_caller_recursive_capture_v1.zig").For(Self);
        pub const Shape = @import("block_v7_caller_recursive_pcs_shape_v1.zig").For(Self);
        pub const Composition = @import("air/block_v7_caller_recursive_composition_v1.zig").For(Self);
        pub const Statement = @import("air/block_v7_caller_recursive_statement_v1.zig").For(Self);
        pub const Transcript = @import("air/block_v7_caller_recursive_transcript_v1.zig").For(Self);
        pub const Public = @import("block_v7_caller_recursive_public_v1.zig").For(Self);
        pub const FixedProfile = @import("block_v7_caller_recursive_fixed_profile_v1.zig").For(Self);
        pub const Fixed = @import("block_v7_caller_recursive_fixed_v1.zig").For(Self);
        pub const FixedTranscript = @import("block_v7_caller_recursive_fixed_transcript_v1.zig").For(Self);
        pub const FixedRoster = @import("block_v7_caller_recursive_fixed_roster_v1.zig").For(Self);
        pub const Preparation = @import("block_v7_caller_recursive_preparation_v1.zig").For(Self);
        pub const ParentProtocol = @import("block_v7_caller_recursive_parent_protocol_v1.zig").For(Self);
        pub const Receiver = @import("block_v7_caller_recursive_receiver_v1.zig").For(Self);
        pub const Capsule = @import("block_v7_caller_recursive_compiler_capsule_v1.zig").For(Self);
    };
}
pub const Full = For(false);
pub const Active = For(true);
