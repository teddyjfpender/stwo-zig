//! Explicit experimental M7 Poseidon commitment/channel suites.
//! Source callers must also bind PCS geometry, AIR roster and field security.
//! The final on-chain wrapper has a separate Blake/Keccak protocol identity.
const std = @import("std");
const S = @import("../crypto/poseidon2_m31_sponge.zig");
pub const Qm31 = ForField(@import("../fields/qm31.zig").QM31);
pub const Om31 = ForField(@import("../fields/om31.zig").OM31);
pub fn ForField(comptime Secure: type) type {
    return struct {
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        pub const Channel = @import("../channel/poseidon2_m31.zig").ForField(Secure);
        pub const MerkleHasher = @import("../vcs/poseidon2_m31_merkle.zig").Poseidon2M31MerkleHasher;
        pub const protocol_name = if (DEGREE == 8) "M7-P2M31-W24-R12-C12-D9-OM31-v1" else "M7-P2M31-W24-R12-C12-D9-QM31-v1";
        pub const protocol_revision = @import("../protocol_revision.zig").Revision.stwo_7b211ed;
        pub fn mixRoot(channel: *Channel, root: MerkleHasher.Hash) void {
            channel.mixRoot(root);
        }
        pub fn identity() [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(protocol_name);
            hash.update(&S.identity());
            hash.update("fs:degree-in-iv/indexed-u64-draw/first8-canonical/scalar-per-felt/pow-natural-u64-max30-v1");
            return hash.finalResult();
        }
    };
}
test "Poseidon suite identity and transcript bind secure field degree" {
    try std.testing.expect(!std.mem.eql(u8, &Qm31.identity(), &Om31.identity()));
    var q = Qm31.Channel.init();
    var o = Om31.Channel.init();
    try std.testing.expect(!std.mem.eql(u8, &q.digestBytes(), &o.digestBytes()));
    const root = MerkleRoot();
    Qm31.mixRoot(&q, root);
    Om31.mixRoot(&o, root);
    try std.testing.expect(!std.mem.eql(u8, &q.digestBytes(), &o.digestBytes()));
}
fn MerkleRoot() S.Digest {
    return Qm31.MerkleHasher.hashNode(null, &.{});
}
