//! Explicit experimental M7 Poseidon commitment/channel suites.
//! Source callers must also bind PCS geometry, AIR roster and field security.
//! The final on-chain wrapper has a separate Blake/Keccak protocol identity.
const std = @import("std");
const S = @import("../crypto/poseidon2_m31_sponge.zig");
pub const Qm31 = ForField(@import("../fields/qm31.zig").QM31);
pub const Om31 = ForField(@import("../fields/om31.zig").OM31);
pub const Qm31V2 = ForFieldV2(@import("../fields/qm31.zig").QM31);
pub const Om31V2 = ForFieldV2(@import("../fields/om31.zig").OM31);
pub fn ForField(comptime Secure: type) type {
    return ForVersion(Secure, 1);
}
pub fn ForFieldV2(comptime Secure: type) type {
    return ForVersion(Secure, 2);
}
fn ForVersion(comptime Secure: type, comptime version: u8) type {
    if (Secure != @import("../fields/qm31.zig").QM31 and Secure != @import("../fields/om31.zig").OM31)
        @compileError("Poseidon profile supports only source-qualified QM31 and OM31 suites");
    return struct {
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        const C = @import("../channel/poseidon2_m31.zig");
        const H = @import("../vcs/poseidon2_m31_merkle.zig");
        pub const Channel = if (version == 1) C.ForField(Secure) else C.ForFieldV2(Secure);
        pub const MerkleHasher = if (version == 1) H.Poseidon2M31MerkleHasher else H.Poseidon2M31MerkleHasherV2;
        pub const protocol_name = if (version == 1)
            (if (DEGREE == 8) "M7-P2M31-W24-R12-C12-D9-OM31-v1" else "M7-P2M31-W24-R12-C12-D9-QM31-v1")
        else
            (if (DEGREE == 8) "M7-P2M31-W24-R12-C12-D9-OM31-v2" else "M7-P2M31-W24-R12-C12-D9-QM31-v2");
        pub const protocol_revision = @import("../protocol_revision.zig").Revision.stwo_7b211ed;
        pub fn mixRoot(channel: *Channel, root: MerkleHasher.Hash) void {
            channel.mixRoot(root);
        }
        pub fn identity() [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(protocol_name);
            hash.update(&S.identity());
            hash.update(if (version == 1)
                "fs:degree-in-iv/indexed-u64-draw/first8-canonical/scalar-per-felt/pow-natural-u64-max30-v1"
            else
                "fs:degree-version2-in-iv/indexed-u32-draw/first8-canonical/scalar-per-felt/pow-natural-u64-max30-v2");
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
