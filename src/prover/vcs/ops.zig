const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const vcs_merkle_hasher = @import("../../core/vcs/merkle_hasher.zig");

const M31 = m31.M31;

/// Compile-time contract for backend Merkle operations on mixed-degree VCS trees.
pub fn assertMerkleOps(comptime B: type, comptime H: type) void {
    comptime {
        vcs_merkle_hasher.assertMerkleHasher(H);
        if (!@hasDecl(B, "commitOnLayer")) {
            @compileError("Merkle ops backend must declare `commitOnLayer`.");
        }
    }
}

pub fn commitOnLayer(
    comptime B: type,
    comptime H: type,
    allocator: std.mem.Allocator,
    log_size: u32,
    prev_layer: ?[]const H.Hash,
    columns: []const []const M31,
) ![]H.Hash {
    comptime assertMerkleOps(B, H);
    return B.commitOnLayer(allocator, log_size, prev_layer, columns);
}

test "vcs ops: dummy backend satisfies contract" {
    const Hasher = @import("../../core/vcs/blake2_merkle.zig").Blake2sMerkleHasher;
    const DummyBackend = struct {
        pub fn commitOnLayer(
            allocator: std.mem.Allocator,
            log_size: u32,
            prev_layer: ?[]const Hasher.Hash,
            columns: []const []const M31,
        ) ![]Hasher.Hash {
            _ = prev_layer;
            _ = columns;
            const out = try allocator.alloc(Hasher.Hash, @as(usize, 1) << @intCast(log_size));
            @memset(out, [_]u8{0} ** 32);
            return out;
        }
    };
    comptime assertMerkleOps(DummyBackend, Hasher);
}
