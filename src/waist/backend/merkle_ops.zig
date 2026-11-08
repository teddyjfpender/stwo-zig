//! Merkle tree operation contracts for prover backends.
//!
//! A backend owns the concrete tree representation and constructs it from
//! committed columns. The generic prover depends only on the typed tree API.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;

const M31 = m31.M31;

/// Validates that backend `B` declares the required Merkle operations
/// for hash function `H`.
///
/// Required declarations:
/// - `MerkleTree(comptime H: type) type`
/// - `commitMerkle(comptime H: type, allocator, columns) !MerkleTree(H)`
///
/// The associated tree must expose ownership, root access, selective reads,
/// and backend-neutral decommitment traversal.
pub fn assertMerkleOps(comptime B: type, comptime H: type) void {
    comptime {
        if (!@hasDecl(B, "MerkleTree")) {
            @compileError("Backend must declare `MerkleTree(comptime H: type) type`.");
        }
        if (!@hasDecl(B, "commitMerkle")) {
            @compileError("Backend must declare `commitMerkle`.");
        }

        const Tree = B.MerkleTree(H);
        if (!@hasDecl(Tree, "root")) {
            @compileError("Backend Merkle tree must declare `root`.");
        }
        if (!@hasDecl(Tree, "deinit")) {
            @compileError("Backend Merkle tree must declare `deinit`.");
        }
        if (!@hasDecl(Tree, "decommit")) {
            @compileError("Backend Merkle tree must declare `decommit`.");
        }
        if (!@hasDecl(Tree, "maxLogSize")) {
            @compileError("Backend Merkle tree must declare `maxLogSize`.");
        }
        if (!@hasDecl(Tree, "readHashes")) {
            @compileError("Backend Merkle tree must declare `readHashes`.");
        }

        const CommitResult = @TypeOf(B.commitMerkle(
            H,
            @as(std.mem.Allocator, undefined),
            @as([]const []const M31, undefined),
        ));
        const commit_info = @typeInfo(CommitResult);
        if (commit_info != .error_union or commit_info.error_union.payload != Tree) {
            @compileError("`commitMerkle` must return an error union containing `MerkleTree(H)`.");
        }
    }
}
