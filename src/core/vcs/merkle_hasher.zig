const m31 = @import("../fields/m31.zig");
const hash_mod = @import("hash.zig");

const M31 = m31.M31;

/// Compile-time contract for core VCS Merkle hashers.
///
/// Required declarations:
/// - `Hash` value type.
/// - `hashNode(children_hashes, column_values) -> Hash`.
pub fn assertMerkleHasher(comptime H: type) void {
    comptime {
        if (!@hasDecl(H, "Hash")) {
            @compileError("Merkle hasher must declare `pub const Hash`.");
        }
        hash_mod.assertHashType(H.Hash);
        if (!@hasDecl(H, "hashNode")) {
            @compileError("Merkle hasher must declare `pub fn hashNode(...)`.");
        }
    }
}

pub fn hashNode(
    comptime H: type,
    children_hashes: ?struct { left: H.Hash, right: H.Hash },
    column_values: []const M31,
) H.Hash {
    comptime assertMerkleHasher(H);
    return H.hashNode(children_hashes, column_values);
}

test "merkle_hasher: blake2 merkle satisfies contract" {
    const Hasher = @import("blake2_merkle.zig").Blake2sMerkleHasher;
    comptime assertMerkleHasher(Hasher);
}
