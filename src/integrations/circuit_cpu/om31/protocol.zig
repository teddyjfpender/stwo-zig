//! Concrete native OM31 circuit proof family; independent of legacy V2 proofs.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
pub const O = core.fields.om31.OM31;
pub const Q = core.fields.qm31.QM31;
pub const M = core.fields.m31.M31;
pub const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
pub const Channel = core.channel.raw_mod_m31.Om31Channel;
pub const MC = struct {
    pub fn mixRoot(ch: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&ch.inner, root);
    }
};
pub const Engine = prover.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Channel);
pub const Scheme = Engine.Scheme;
pub const Proof = core.proof.ForField(O).StarkProof(H);
pub const PcsConfig = core.pcs.ForField(O).PcsConfig;
pub const domain = "stwo/circuit/native-om31/q108-p20-fold4/lens-v1";
pub fn targetConfig() !PcsConfig {
    var fri = try core.fri.ForField(O).FriConfig.init(0, 1, 108);
    fri.fold_step = 4;
    return .{ .pow_bits = 20, .fri_config = fri };
}
pub fn validateConfig(config: PcsConfig) !void {
    if (!std.meta.eql(config, try targetConfig())) return error.UnsupportedOm31CircuitProfile;
}
pub fn mixProfile(ch: *Channel) void {
    ch.mixU32s(&.{ 0x434f4d38, 1, 8 });
    var words: [8]u32 = undefined;
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(domain, &identity, .{});
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, identity[4 * i ..][0..4], .little);
    ch.mixU32s(&words);
}
test "om31 outer profile is exact and separate from legacy" {
    const config = try targetConfig();
    try validateConfig(config);
    var bad = config;
    bad.fri_config.n_queries = 70;
    try std.testing.expectError(error.UnsupportedOm31CircuitProfile, validateConfig(bad));
    var original = Channel.init();
    const before = original.digestBytes();
    mixProfile(&original);
    try std.testing.expect(!std.mem.eql(u8, &before, &original.digestBytes()));
}
