//! Per-proof native OM31 PCS offload. No process-global callback or fallback.
//! The caller keeps coefficient/point owners live for this synchronous boundary.
const std = @import("std");
const core = @import("stwo_core");
pub const O = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const Channel = core.channel.raw_mod_m31.Om31Channel;
pub const P = core.pcs.ForField(O);
pub const Point = core.circle.CirclePoint(O);
pub const Column = struct { log_size: u32, coefficients: []const M };
pub const Tree = struct { root: H.Hash, columns: []const Column };
pub const Scope = struct { statement: [32]u8, fixed: [32]u8, main: [32]u8, ordinal: u32 };
pub const Request = struct {
    scope: ?Scope = null,
    config: core.pcs.PcsConfig,
    lifting_log_size: u32,
    trees: []const Tree,
    points: core.pcs.TreeVec([][]Point),
};
pub const Stage = struct {
    context: *anyopaque,
    /// Returns owned native containers. Updates only the supplied channel copy;
    /// an error is terminal and must never silently execute the CPU path.
    prove: *const fn (*anyopaque, std.mem.Allocator, Request, *Channel) anyerror!P.ExtendedCommitmentSchemeProof(H),
};
