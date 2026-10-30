//! Public statement routing from the exact original B6CJ1 encoders. Offsets are
//! rebuilt from admitted metadata and proposed claims, never decoded authority.
const std = @import("std");
const Admission = @import("../../prover/block_v6_caller_joint_admission_v1.zig");
const Joint = @import("../../prover/block_v6_caller_joint_proof_v1.zig");
const Protocol = @import("../../prover/block_v5_precompile_protocol_v1.zig");
const Profile = @import("../../prover/blake3_ethereum_sha_profile.zig");
const Fused = @import("../../prover/block_v5_caller_fused_proof_v1.zig");
const Frames = @import("block_v5_recursive_statement_frames_v1.zig");
pub const PUBLIC_CIRCUIT: u32 = 4_200_021;
pub const Statement = Frames.Statement;
pub fn init(a: std.mem.Allocator, admitted: *const Admission.Prepared, arithmetic: *const Profile.ExtensionClaim, relations: *const Fused.ClaimFrames) !Statement {
    var b = Frames.Builder{ .allocator = a, .max_felts = admitted.limits.max_claims };
    defer b.deinit();
    const sealed = try b.digestWords(admitted.arithmetic.sealed.digest);
    var roots: [3]u32 = undefined;
    roots[0] = try b.digestWords(admitted.arithmetic.roots[0]);
    roots[1] = try b.digestWords(admitted.arithmetic.roots[1]);
    roots[2] = try b.digestWords(admitted.relations.witness_root);
    Protocol.mixPcsBinding(&b, admitted.arithmetic.binding);
    try Joint.mixAfterChallenges(&b, admitted.policy(), &admitted.relations.schedule, arithmetic, relations);
    try b.check();
    const claims = try b.steps.toOwnedSlice(a);
    errdefer a.free(claims);
    const words = try b.data.toOwnedSlice(a);
    errdefer a.free(words);
    const felts = try b.fields.toOwnedSlice(a);
    return .{ .allocator = a, .words = words, .felts = felts, .first = &.{}, .claims = claims, .sealed_offset = sealed, .roots_offset = roots };
}
