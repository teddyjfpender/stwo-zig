const m31 = @import("../fields/m31.zig");
const vcs_hash = @import("../vcs/hash.zig");

const M31 = m31.M31;

/// Compile-time contract for lifted VCS Merkle hashers.
///
/// Required declarations:
/// - `Hash` value type.
/// - `defaultWithInitialState()`.
/// - `hashChildren(children_hashes) -> Hash`.
/// - `updateLeaf(self, column_values)`.
/// - `finalize(self) -> Hash`.
pub fn assertMerkleHasherLifted(comptime H: type) void {
    comptime {
        if (!@hasDecl(H, "Hash")) {
            @compileError("Lifted Merkle hasher must declare `pub const Hash`.");
        }
        vcs_hash.assertHashType(H.Hash);
        if (!@hasDecl(H, "defaultWithInitialState")) {
            @compileError("Lifted Merkle hasher must declare `defaultWithInitialState`.");
        }
        if (!@hasDecl(H, "hashChildren")) {
            @compileError("Lifted Merkle hasher must declare `hashChildren`.");
        }
        if (!@hasDecl(H, "updateLeaf")) {
            @compileError("Lifted Merkle hasher must declare `updateLeaf`.");
        }
        if (!@hasDecl(H, "finalize")) {
            @compileError("Lifted Merkle hasher must declare `finalize`.");
        }
    }
}

pub fn hashChildren(
    comptime H: type,
    children_hashes: struct { left: H.Hash, right: H.Hash },
) H.Hash {
    comptime assertMerkleHasherLifted(H);
    return H.hashChildren(children_hashes);
}

pub fn updateLeaf(
    comptime H: type,
    hasher: *H,
    column_values: []const M31,
) void {
    comptime assertMerkleHasherLifted(H);
    hasher.updateLeaf(column_values);
}

test "lifted merkle_hasher: blake2 merkle satisfies contract" {
    const Hasher = @import("blake2_merkle.zig").Blake2sMerkleHasher;
    comptime assertMerkleHasherLifted(Hasher);
}
