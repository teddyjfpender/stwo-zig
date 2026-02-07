const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const lifted_merkle_hasher = @import("../../core/vcs_lifted/merkle_hasher.zig");

const M31 = m31.M31;

/// Compile-time contract for backend lifted Merkle operations.
pub fn assertMerkleOpsLifted(comptime B: type, comptime H: type) void {
    comptime {
        lifted_merkle_hasher.assertMerkleHasherLifted(H);
        if (!@hasDecl(B, "buildLeaves")) {
            @compileError("Lifted Merkle ops backend must declare `buildLeaves`.");
        }
        if (!@hasDecl(B, "buildNextLayer")) {
            @compileError("Lifted Merkle ops backend must declare `buildNextLayer`.");
        }
    }
}

pub fn buildLeaves(
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    columns: []const []const M31,
) ![]H.Hash {
    comptime assertMerkleOpsLifted(B, H);
    return B.buildLeaves(allocator, columns);
}

pub fn buildNextLayer(
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    prev_layer: []const H.Hash,
) ![]H.Hash {
    comptime assertMerkleOpsLifted(B, H);
    return B.buildNextLayer(allocator, prev_layer);
}

test "vcs lifted ops: dummy backend satisfies contract" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const DummyBackend = struct {
        pub fn buildLeaves(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) ![]Hasher.Hash {
            _ = columns;
            const out = try allocator.alloc(Hasher.Hash, 1);
            out[0] = [_]u8{0} ** 32;
            return out;
        }

        pub fn buildNextLayer(
            allocator: std.mem.Allocator,
            prev_layer: []const Hasher.Hash,
        ) ![]Hasher.Hash {
            _ = prev_layer;
            const out = try allocator.alloc(Hasher.Hash, 1);
            out[0] = [_]u8{1} ** 32;
            return out;
        }
    };
    comptime assertMerkleOpsLifted(DummyBackend, Hasher);
}
