//! Candidate source-tree profile, distinct from production plain trees and
//! the personalized FRI line trees. No production selector uses this profile.
const std = @import("std");
const builtin = @import("builtin");
const backend = @import("../crypto/blake2s_backend.zig");
const m31 = @import("../fields/m31.zig");

const M31 = m31.M31;
pub const profile_id = "S31SOURCE2";
pub const leaf_context: [8]u8 = "S31S2LEF".*;
pub const parent_context: [8]u8 = "S31S2PAR".*;
pub const Digest32 = backend.Blake2sHash;

/// Leaf bytes are canonical M31 words in column-roster order. Parent input
/// remains exactly 64 bytes and uses one BLAKE2s compression. Distinct full
/// personalization strings separate the source leaf/parent roles from each
/// other and from the line-tree roles; theorem applicability is still open.
pub const SourceMerkleHasherV2 = struct {
    inner: backend.Blake2sHasher,

    pub const Hash = Digest32;
    pub const Children = struct { left: Hash, right: Hash };

    pub fn defaultWithInitialState() SourceMerkleHasherV2 {
        return .{ .inner = backend.Blake2sHasher.initWithContext(leaf_context) };
    }

    pub fn updateLeaf(self: *SourceMerkleHasherV2, values: []const M31) void {
        if (builtin.cpu.arch.endian() == .little) {
            self.inner.update(std.mem.sliceAsBytes(values));
            return;
        }
        for (values) |value| {
            const bytes = value.toBytesLe();
            self.inner.update(&bytes);
        }
    }

    pub fn finalize(self: *SourceMerkleHasherV2) Hash {
        return self.inner.finalize();
    }

    pub fn hashChildren(children: Children) Hash {
        var payload: [64]u8 = undefined;
        @memcpy(payload[0..32], &children.left);
        @memcpy(payload[32..64], &children.right);
        return backend.Blake2sHasher.hashFixed64WithContext(parent_context, &payload);
    }
};

comptime {
    @import("merkle_hasher.zig").assertMerkleHasherLifted(SourceMerkleHasherV2);
}

test "source roles differ from line and production plain Merkle hashes" {
    const line = @import("blake2s_personalized_line_v2.zig");
    const plain = @import("blake2_merkle.zig").Blake2sPlainMerkleHasher;
    const values = [_]M31{ M31.fromCanonical(0), M31.fromCanonical(1) };
    var source_hash = SourceMerkleHasherV2.defaultWithInitialState();
    source_hash.updateLeaf(&values);
    var line_hash = line.LineMerkleHasherV2.defaultWithInitialState();
    line_hash.updateLeaf(&values);
    var plain_hash = plain.defaultWithInitialState();
    plain_hash.updateLeaf(&values);
    const source_leaf = source_hash.finalize();
    try std.testing.expect(!std.mem.eql(u8, &source_leaf, &line_hash.finalize()));
    try std.testing.expect(!std.mem.eql(u8, &source_leaf, &plain_hash.finalize()));
    const zero = [_]u8{0} ** 32;
    const parent = SourceMerkleHasherV2.hashChildren(.{ .left = zero, .right = zero });
    try std.testing.expect(!std.mem.eql(u8, &source_leaf, &parent));
}

test "source leaf and one-block parent match independent Python BLAKE2s" {
    const values = [_]M31{ M31.fromCanonical(1), M31.fromCanonical(2) };
    var hasher = SourceMerkleHasherV2.defaultWithInitialState();
    hasher.updateLeaf(&values);
    var expected: Digest32 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "41e7764fec8c6cf462c663c29273d9a0c380cc3b5ae7b34a038cce3938cb2467");
    try std.testing.expectEqualDeep(expected, hasher.finalize());
    const zero = [_]u8{0} ** 32;
    _ = try std.fmt.hexToBytes(&expected, "83ec7b8799a9634f552167295bd0622babcfae1a27adbe4515a64c781bcb3b82");
    try std.testing.expectEqualDeep(expected, SourceMerkleHasherV2.hashChildren(.{ .left = zero, .right = zero }));
}
