const std = @import("std");
const m31_mod = @import("../fields/m31.zig");
const qm31_mod = @import("../fields/qm31.zig");

const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;

pub const blake2_merkle = @import("blake2_merkle.zig");
pub const blake3_merkle = @import("blake3_merkle.zig");
pub const channel_profile = @import("channel_profile.zig");
pub const lifted_height_vectors = @import("lifted_height_vectors.zig");
pub const merkle_hasher = @import("merkle_hasher.zig");
pub const test_utils = @import("test_utils.zig");
pub const verifier = @import("verifier.zig");

/// Number of QM31 values packed into a single Merkle leaf when fold_step > 1.
pub const LOG_PACKED_LEAF_SIZE: u32 = 2;

/// 1 << LOG_PACKED_LEAF_SIZE = 4 QM31 values per packed leaf.
pub const PACKED_LEAF_SIZE: usize = 1 << LOG_PACKED_LEAF_SIZE;

/// Pack `PACKED_LEAF_SIZE` (4) adjacent QM31 values into a single Merkle leaf hash.
///
/// Each QM31 is decomposed into 4 M31 coordinates, each written as a 4-byte
/// little-endian u32, yielding 4 * 4 * 4 = 64 bytes that are fed into the
/// lifted Merkle hasher (with its standard leaf-domain prefix).
///
/// This packing is used when fold_step > 1, where the Merkle verifier decommits
/// groups of QM31s rather than individual values.
pub fn packLeaf(comptime H: type, values: [PACKED_LEAF_SIZE]QM31) H.Hash {
    comptime merkle_hasher.assertMerkleHasherLifted(H);

    // Serialize all QM31 values into a flat byte buffer.
    const n_m31 = PACKED_LEAF_SIZE * 4; // 4 QM31 * 4 M31 coords each = 16
    var m31_values: [n_m31]M31 = undefined;
    for (values, 0..) |qm31, i| {
        const coords = qm31.toM31Array();
        for (coords, 0..) |m31_val, j| {
            m31_values[i * 4 + j] = m31_val;
        }
    }

    var hasher = H.defaultWithInitialState();
    hasher.updateLeaf(&m31_values);
    return hasher.finalize();
}

test "vcs_lifted: packed leaf constants" {
    try std.testing.expectEqual(@as(u32, 2), LOG_PACKED_LEAF_SIZE);
    try std.testing.expectEqual(@as(usize, 4), PACKED_LEAF_SIZE);
}

test "vcs_lifted: packLeaf produces deterministic output" {
    const Hasher = blake2_merkle.Blake2sMerkleHasher;
    const values = [PACKED_LEAF_SIZE]QM31{
        QM31.fromM31(M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4)),
        QM31.fromM31(M31.fromCanonical(5), M31.fromCanonical(6), M31.fromCanonical(7), M31.fromCanonical(8)),
        QM31.fromM31(M31.fromCanonical(9), M31.fromCanonical(10), M31.fromCanonical(11), M31.fromCanonical(12)),
        QM31.fromM31(M31.fromCanonical(13), M31.fromCanonical(14), M31.fromCanonical(15), M31.fromCanonical(16)),
    };
    const h1 = packLeaf(Hasher, values);
    const h2 = packLeaf(Hasher, values);
    try std.testing.expectEqualSlices(u8, h1[0..], h2[0..]);
}

test "vcs_lifted: packLeaf changes with different values" {
    const Hasher = blake2_merkle.Blake2sMerkleHasher;
    const values_a = [PACKED_LEAF_SIZE]QM31{
        QM31.fromM31(M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4)),
        QM31.fromM31(M31.fromCanonical(5), M31.fromCanonical(6), M31.fromCanonical(7), M31.fromCanonical(8)),
        QM31.fromM31(M31.fromCanonical(9), M31.fromCanonical(10), M31.fromCanonical(11), M31.fromCanonical(12)),
        QM31.fromM31(M31.fromCanonical(13), M31.fromCanonical(14), M31.fromCanonical(15), M31.fromCanonical(16)),
    };
    const values_b = [PACKED_LEAF_SIZE]QM31{
        QM31.fromM31(M31.fromCanonical(100), M31.fromCanonical(200), M31.fromCanonical(300), M31.fromCanonical(400)),
        QM31.fromM31(M31.fromCanonical(5), M31.fromCanonical(6), M31.fromCanonical(7), M31.fromCanonical(8)),
        QM31.fromM31(M31.fromCanonical(9), M31.fromCanonical(10), M31.fromCanonical(11), M31.fromCanonical(12)),
        QM31.fromM31(M31.fromCanonical(13), M31.fromCanonical(14), M31.fromCanonical(15), M31.fromCanonical(16)),
    };
    const ha = packLeaf(Hasher, values_a);
    const hb = packLeaf(Hasher, values_b);
    try std.testing.expect(!std.mem.eql(u8, ha[0..], hb[0..]));
}
