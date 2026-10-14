//! Candidate S31NAT9F line-tree Merkle profile; no selected proof uses it.
//!
//! Fixed BLAKE2s personalization separates leaf and parent roles without
//! adding a message block. A parent hashes exactly `left[32] || right[32]`.
//! The full tree descriptor, shape and column roster must instead be bound
//! in the verifier-owned statement and root event. These functions alone do
//! not prove that binding or a random-oracle reduction for BLAKE2s parameters.
const std = @import("std");
const builtin = @import("builtin");
const backend = @import("../crypto/blake2s_backend.zig");
const m31 = @import("../fields/m31.zig");

const M31 = m31.M31;
pub const Digest32 = backend.Blake2sHash;
pub const profile_id = "S31LINE2";
pub const leaf_context: [8]u8 = "S31P2LEF".*;
pub const parent_context: [8]u8 = "S31P2PAR".*;
pub const Error = error{ InvalidPathShape, NonCanonicalRow };

pub const LineMerkleHasherV2 = struct {
    inner: backend.Blake2sHasher,

    const Self = @This();
    pub const Hash = backend.Blake2sHash;
    pub const Children = struct { left: Hash, right: Hash };
    pub const NodeSeed = enum { leaf, parent };

    pub fn defaultWithInitialState() Self {
        return .{ .inner = backend.Blake2sHasher.initWithContext(leaf_context) };
    }

    pub fn nodeSeed() NodeSeed {
        return .parent;
    }

    pub fn leafSeed() NodeSeed {
        return .leaf;
    }

    pub fn updateLeaf(self: *Self, values: []const M31) void {
        if (builtin.cpu.arch.endian() == .little) {
            self.inner.update(std.mem.sliceAsBytes(values));
            return;
        }
        for (values) |value| {
            const bytes = value.toBytesLe();
            self.inner.update(&bytes);
        }
    }

    /// Trusted packed rows; proof-owned bytes must pass canonical decoding
    /// before reaching this lower-level builder method.
    pub fn updateLeafPackedBytes(self: *Self, bytes: []const u8) void {
        std.debug.assert(bytes.len % 4 == 0);
        self.inner.update(bytes);
    }

    pub fn finalize(self: *Self) Hash {
        return self.inner.finalize();
    }

    pub fn hashChildren(children: Children) Hash {
        var payload: [64]u8 = undefined;
        @memcpy(payload[0..32], &children.left);
        @memcpy(payload[32..64], &children.right);
        return backend.Blake2sHasher.hashFixed64WithContext(parent_context, &payload);
    }

    pub fn hashChildrenWithSeed(seed: NodeSeed, children: Children) Hash {
        if (seed != .parent) @panic("line parent hash requires parent seed");
        return hashChildren(children);
    }

    pub fn hashChildrenWithSeed4(seed: NodeSeed, children: *const [8]Hash) [4]Hash {
        if (seed != .parent) @panic("line parent hash requires parent seed");
        var payloads: [4][64]u8 = undefined;
        for (&payloads, 0..) |*payload, lane| {
            @memcpy(payload[0..32], &children[2 * lane]);
            @memcpy(payload[32..64], &children[2 * lane + 1]);
        }
        return backend.Blake2sHasher.hashFixed64WithContext4(parent_context, &payloads);
    }

    pub fn hashPackedLeavesWithSeed4(seed: NodeSeed, messages: *const [4][]const u8) [4]Hash {
        if (seed != .leaf) @panic("line leaf hash requires leaf seed");
        var out: [4]Hash = undefined;
        for (&out, messages) |*digest, message| {
            var hasher = defaultWithInitialState();
            hasher.updateLeafPackedBytes(message);
            digest.* = hasher.finalize();
        }
        return out;
    }

    pub fn hashDirectM31LeavesWithSeed4(
        seed: NodeSeed,
        columns: anytype,
        position: usize,
    ) [4]Hash {
        if (seed != .leaf) @panic("line leaf hash requires leaf seed");
        var hashers = [_]Self{defaultWithInitialState()} ** 4;
        for (columns) |column| {
            for (&hashers, 0..) |*hasher, lane| {
                hasher.updateLeaf(column.values[position + lane .. position + lane + 1]);
            }
        }
        var out: [4]Hash = undefined;
        for (&out, &hashers) |*digest, *hasher| digest.* = hasher.finalize();
        return out;
    }
};

comptime {
    @import("merkle_hasher.zig").assertMerkleHasherLifted(LineMerkleHasherV2);
}

/// A strict verifier-side leaf encoder for proof-owned canonical M31 words.
pub fn hashCanonicalRow(row: []const u32) Error!Digest32 {
    var hasher = backend.Blake2sHasher.initWithContext(leaf_context);
    for (row) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalRow;
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        hasher.update(&bytes);
    }
    return hasher.finalize();
}

/// Verify a binary path only after the caller has checked the tree's full
/// descriptor against the statement and mapped `root` to its named event.
pub fn verifyPath(
    root: Digest32,
    row: []const u32,
    leaf_index: u64,
    depth: u32,
    siblings: []const Digest32,
) Error!bool {
    if (depth >= 64 or siblings.len != depth or leaf_index >= (@as(u64, 1) << @intCast(depth)))
        return error.InvalidPathShape;
    var node = try hashCanonicalRow(row);
    for (siblings, 0..) |sibling, level| {
        node = if ((leaf_index >> @intCast(level)) & 1 == 0)
            LineMerkleHasherV2.hashChildren(.{ .left = node, .right = sibling })
        else
            LineMerkleHasherV2.hashChildren(.{ .left = sibling, .right = node });
    }
    return std.mem.eql(u8, &node, &root);
}

fn expectHex(expected_hex: []const u8, actual: Digest32) !void {
    var bytes: [32]u8 = undefined;
    const expected = try std.fmt.hexToBytes(&bytes, expected_hex);
    try std.testing.expectEqualSlices(u8, expected, &actual);
}

test "personalized line leaf and one-block parent match independent Python" {
    const row = [_]M31{
        M31.fromCanonical(0), M31.fromCanonical(1),
        M31.fromCanonical(2), M31.fromCanonical(3),
    };
    var leaf = LineMerkleHasherV2.defaultWithInitialState();
    leaf.updateLeaf(&row);
    const leaf_hash = leaf.finalize();
    try expectHex("919bd474fd82ce68440dafb9fd23ed809ea2c5343cd5edb1adc0f510ac7836c8", leaf_hash);
    try std.testing.expectEqualDeep(leaf_hash, try hashCanonicalRow(&.{ 0, 1, 2, 3 }));

    var left: Digest32 = undefined;
    var right: Digest32 = undefined;
    for (&left, 0..) |*byte, i| byte.* = @intCast(i);
    for (&right, 0..) |*byte, i| byte.* = @intCast(i + 32);
    const parent = LineMerkleHasherV2.hashChildren(.{ .left = left, .right = right });
    try expectHex("1e5f78bdef8aa652c03d287f2ed33b3411460789251d8d2ddbf2510e7a44b737", parent);
    const swapped = LineMerkleHasherV2.hashChildren(.{ .left = right, .right = left });
    try expectHex("315c09be593d1e4b25bdb7495f8d667a700f749743042f7f24ab419df2c22b86", swapped);
    try std.testing.expect(!std.mem.eql(u8, &parent, &swapped));

    const Oracle = std.crypto.hash.blake2.Blake2s256;
    var oracle_parent: Digest32 = undefined;
    var payload: [64]u8 = undefined;
    @memcpy(payload[0..32], &left);
    @memcpy(payload[32..64], &right);
    Oracle.hash(&payload, &oracle_parent, .{ .context = parent_context });
    try std.testing.expectEqualDeep(parent, oracle_parent);
    var leaf_domain: Digest32 = undefined;
    Oracle.hash(&payload, &leaf_domain, .{ .context = leaf_context });
    try std.testing.expect(!std.mem.eql(u8, &parent, &leaf_domain));
}

test "four-way personalized parent hashes match scalar in both backends" {
    var children: [8]Digest32 = undefined;
    for (&children, 0..) |*child, i| @memset(child, @intCast(i + 1));
    const four = LineMerkleHasherV2.hashChildrenWithSeed4(.parent, &children);
    for (four, 0..) |actual, lane| {
        const scalar = LineMerkleHasherV2.hashChildren(.{
            .left = children[2 * lane],
            .right = children[2 * lane + 1],
        });
        try std.testing.expectEqualDeep(scalar, actual);
    }
    var payloads: [4][64]u8 = undefined;
    for (&payloads, 0..) |*payload, lane| {
        @memcpy(payload[0..32], &children[2 * lane]);
        @memcpy(payload[32..64], &children[2 * lane + 1]);
    }
    const scalar_four = backend.Blake2sHasher.hashFixed64WithModeAndContext4(.scalar, parent_context, &payloads);
    try std.testing.expectEqualDeep(four, scalar_four);
}

test "personalized path verifies exact shape and canonical row" {
    const leaves = [_]Digest32{
        try hashCanonicalRow(&.{0}), try hashCanonicalRow(&.{1}),
        try hashCanonicalRow(&.{2}), try hashCanonicalRow(&.{3}),
    };
    const left = LineMerkleHasherV2.hashChildren(.{ .left = leaves[0], .right = leaves[1] });
    const right = LineMerkleHasherV2.hashChildren(.{ .left = leaves[2], .right = leaves[3] });
    const root = LineMerkleHasherV2.hashChildren(.{ .left = left, .right = right });
    try std.testing.expect(try verifyPath(root, &.{2}, 2, 2, &.{ leaves[3], left }));
    try std.testing.expect(!(try verifyPath(root, &.{2}, 2, 2, &.{ leaves[0], left })));
    try std.testing.expectError(error.InvalidPathShape, verifyPath(root, &.{2}, 4, 2, &.{ leaves[3], left }));
    try std.testing.expectError(error.InvalidPathShape, verifyPath(root, &.{2}, 2, 2, &.{leaves[3]}));
    try std.testing.expectError(error.NonCanonicalRow, verifyPath(root, &.{m31.Modulus}, 2, 2, &.{ leaves[3], left }));
}

test "four direct canonical M31 leaves match scalar row hashes" {
    const Column = struct { values: []const M31 };
    const first = [_]M31{
        M31.fromCanonical(0), M31.fromCanonical(1),
        M31.fromCanonical(2), M31.fromCanonical(3),
    };
    const second = [_]M31{
        M31.fromCanonical(4), M31.fromCanonical(5),
        M31.fromCanonical(6), M31.fromCanonical(7),
    };
    const columns = [_]Column{ .{ .values = &first }, .{ .values = &second } };
    const direct = LineMerkleHasherV2.hashDirectM31LeavesWithSeed4(.leaf, &columns, 0);
    for (direct, 0..) |digest, lane| {
        const expected = try hashCanonicalRow(&.{ @intCast(lane), @intCast(lane + 4) });
        try std.testing.expectEqualDeep(expected, digest);
    }
}
