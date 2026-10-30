//! Explicit nonterminal memory verifier. The snapshot-delta equations and
//! transcript are independently reconstructed, including both physical sums.
//! Shared four-tree plumbing never relabels a terminal memory proof.
const D = @This();
pub const Profile = @import("block_v7_memory_joint_fixed_profile_v1.zig").ForMode(true);
pub const Equation = @import("air/block_v7_memory_joint_composition_v1.zig").ForMode(true);
pub const Inputs = @import("air/block_v7_memory_joint_inputs_v1.zig").ForMode(true);
pub const Capture = @import("../prover/block_v7_window_memory_joint_v1.zig");
pub const Statement = @import("air/block_v7_memory_joint_statement_v1.zig").ForMode(true);
pub const Transcript = @import("air/block_v7_memory_joint_transcript_v1.zig").ForMode(true);
pub const Public = @import("block_v7_memory_joint_public_v1.zig").ForMode(true);
pub const Protocol = @import("block_v7_memory_joint_parent_protocol_v1.zig").ForMode(true);
pub const Fixed = @import("block_v7_word_family_fixed_v1.zig").For(D);
pub const FixedTranscript = @import("block_v7_word_family_fixed_transcript_v1.zig").For(D);
pub const Preparation = @import("block_v7_word_family_preparation_v1.zig").For(D);
pub const FixedRoster = @import("block_v7_word_family_fixed_roster_v1.zig").For(D);
