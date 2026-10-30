//! Explicit joint-family binding for shared original four-tree plumbing.
const D = @This();
pub const Profile = @import("block_v7_memory_joint_fixed_profile_v1.zig");
pub const Equation = @import("air/block_v7_memory_joint_composition_v1.zig");
pub const Inputs = @import("air/block_v7_memory_joint_inputs_v1.zig");
pub const Capture = @import("../prover/block_v7_memory_joint_proof_v1.zig");
pub const Statement = @import("air/block_v7_memory_joint_statement_v1.zig");
pub const Transcript = @import("air/block_v7_memory_joint_transcript_v1.zig");
pub const Public = @import("block_v7_memory_joint_public_v1.zig");
pub const Protocol = @import("block_v7_memory_joint_parent_protocol_v1.zig");
pub const Fixed = @import("block_v7_word_family_fixed_v1.zig").For(D);
pub const FixedTranscript = @import("block_v7_word_family_fixed_transcript_v1.zig").For(D);
pub const Preparation = @import("block_v7_word_family_preparation_v1.zig").For(D);
pub const FixedRoster = @import("block_v7_word_family_fixed_roster_v1.zig").For(D);
