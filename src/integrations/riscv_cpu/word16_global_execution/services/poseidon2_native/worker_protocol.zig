//! Receiver-owned mixed suite: P2v2 physical PCS/FS, raw-Blake local GKR/manifest.
//! No numeric PCS inference and no reuse of the raw-Blake default aliases.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
pub const Profile = enum {
    fixture_b4_q54_p0_fold4,
    pub fn config(_: Profile) core.pcs.PcsConfig {
        var fri = core.fri.FriConfig.init(0, 2, 54) catch unreachable;
        fri.fold_step = 4;
        return .{ .pow_bits = 0, .fri_config = fri };
    }
    pub fn identity(self: Profile) [32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64-native/p2v2-physical-rawblake-localgkr-manifest/FIXTURE-P0-v1\x00");
        h.update(@tagName(self));
        h.update(&Suite.identity());
        h.update("OM31/b4/q54/P0/fold4/old-localGKR64/no-security-certificate");
        return h.finalResult();
    }
};
pub const Suite = core.vcs_lifted.poseidon2_profile.Om31V2;
pub const W = ForSuite(Suite);
pub fn ForSuite(comptime MC_: type) type {
    if (MC_ != Suite) @compileError("define a distinct receiver-owned profile before selecting another native crypto suite");
    return struct {
        pub const O = core.fields.om31.OM31;
        pub const H = MC_.MerkleHasher;
        pub const Channel = MC_.Channel;
        pub const MC = MC_;
        pub const Prover = engine.engine.ForField(O).ProverEngine(@import("stwo_cpu_backend").CpuBackend, H, MC, Channel);
        pub const Scheme = Prover.Scheme;
        pub const Proof = core.proof.ForField(O).StarkProof(H);
        pub const Wire = @import("stwo_proof_wire").ForHasher(O, H);
        pub fn digest(channel: *Channel, value: [32]u8) void {
            var words: [8]u32 = undefined;
            for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, value[4 * i ..][0..4], .little);
            channel.mixU32s(&words);
        }
        pub fn begin(profile: Profile, expected: anytype, fixed_id: [32]u8, fixed_root: H.Hash) Channel {
            var channel = Channel.init();
            profile.config().mixInto(&channel);
            channel.mixU32s(&.{ 0x50324350, 2, 8, @intFromEnum(expected.kind), expected.ordinal });
            digest(&channel, profile.identity());
            digest(&channel, expected.statement);
            digest(&channel, expected.fixed);
            digest(&channel, fixed_id);
            channel.mixRoot(fixed_root);
            return channel;
        }
        pub fn mixManifestAndClaims(channel: *Channel, manifest: [32]u8, claims: []const O) void {
            channel.mixU32s(&.{ 0x50324d43, 2, @intCast(claims.len) });
            digest(channel, manifest);
            channel.mixFelts(claims);
        }
    };
}
/// Injective full-root framing into the explicitly raw-Blake local protocol.
/// This is a new mixed-suite commitment, never a truncated P2 root.
pub fn scopeRoot(profile: Profile, kind: enum(u32) { fixed = 0, main = 1 }, root: W.H.Hash) [32]u8 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update("rv64-p2v2/raw-local-scope-root/v1\x00");
    h.update(&profile.identity());
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, @intFromEnum(kind), .little);
    h.update(&bytes);
    h.update(&root);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}
