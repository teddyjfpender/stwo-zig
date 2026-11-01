//! One physical protocol authority for CPU and truth workers. Immutable M31
//! setup is shared by identity; each request/channel/manifest/claim vector is
//! bound independently. This is the new explicit OM profile, not legacy Q.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Manifest = @import("manifest.zig");
pub const O = core.fields.om31.OM31;
pub const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const Channel = core.channel.raw_mod_m31.Om31Channel;
pub const MC = struct {
    pub fn mixRoot(ch: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&ch.inner, root);
    }
};
pub const Prover = engine.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Channel);
pub const Scheme = Prover.Scheme;
pub const PcsConfig = core.pcs.ForField(O).PcsConfig;
pub const Proof = core.proof.ForField(O).StarkProof(H);
pub const Wire = @import("stwo_proof_wire").ForField(O);
pub fn digest(ch: *Channel, value: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*w, i| w.* = std.mem.readInt(u32, value[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
pub fn begin(config: PcsConfig, expected: Manifest.ExpectedWorker) Channel {
    var ch = Channel.init();
    config.mixInto(&ch);
    ch.mixU32s(&.{ 0x57474b4f, 1, 8, @intFromEnum(expected.kind), expected.ordinal });
    var profile: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(Manifest.PROFILE, &profile, .{});
    digest(&ch, profile);
    digest(&ch, expected.statement);
    return ch;
}
pub fn appendFixed(a: std.mem.Allocator, key: *const @import("../../keccak/shared/key.zig").Key, expected: [32]u8, scheme: *Scheme, ch: *Channel) !void {
    if (!std.mem.eql(u8, &key.root, &expected) or scheme.trees.items.len != 0 or scheme.pending_commit != null or scheme.config.fri_config.log_blowup_factor != key.suite.pcs.fri_config.log_blowup_factor) return error.WideWorkerFixedAuthorityMismatch;
    var tree = key.tree.retainShared();
    errdefer tree.deinit(key.allocator);
    try scheme.appendCommittedTree(a, tree, ch);
}
pub fn mixManifestAndClaims(ch: *Channel, manifest: [32]u8, claims: []const O) void {
    ch.mixU32s(&.{ 0x57474b32, 1, @intCast(claims.len) });
    digest(ch, manifest);
    ch.mixFelts(claims);
}
pub fn encodePhysical(a: std.mem.Allocator, proof: Proof) ![]u8 {
    return Wire.encodeProofBytesBinary(a, proof);
}
pub fn decodePhysical(a: std.mem.Allocator, bytes: []const u8) !Proof {
    return Wire.decodeProofBytesBinary(a, bytes);
}
