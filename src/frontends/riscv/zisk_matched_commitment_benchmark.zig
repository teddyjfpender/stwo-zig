// Research-only peer-protocol adapter; production transcript framing is unchanged.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Digest = [32]u8;
const H = struct {
    pub const Hash = [32]u8;
    pub const NodeSeed = void;
    pub fn nodeSeed() NodeSeed {}
    pub fn hashChildrenWithSeed(_: NodeSeed, c: struct { left: Hash, right: Hash }) Hash {
        return hashChildren(.{ .left = c.left, .right = c.right });
    }
    pub fn defaultWithInitialState() @This() {
        return .{};
    }
    pub fn updateLeaf(_: *@This(), _: []const core.fields.m31.M31) void {
        unreachable;
    }
    pub fn finalize(_: *const @This()) Hash {
        unreachable;
    }
    pub fn digest(bytes: []const u8) Hash {
        var out = core.vcs.blake3_hash.Blake3Hasher.hash(bytes);
        inline for (0..4) |i| {
            const x = std.mem.readInt(u64, out[i * 8 ..][0..8], .little);
            std.mem.writeInt(u64, out[i * 8 ..][0..8], x % 0xffffffff00000001, .little);
        }
        return out;
    }
    pub fn hashChildren(c: struct { left: Hash, right: Hash }) Hash {
        return digest(&(c.left ++ c.right));
    }
};
export fn matched_hash(input: [*]const u8, len: usize, out: *Digest) void {
    out.* = H.digest(input[0..len]);
}
// Input is canonical little-endian GL64 row words. Each row contains width words.
// Output is every node, bottom-up, followed by 70 paths. Allocation and
// deallocation are included in caller wall time; qualification copying is optional.
export fn matched_commit(log: u32, width: u32, input: [*]const u8, nodes: ?[*]Digest, paths: [*]Digest, root: *Digest) u32 {
    const a = std.heap.page_allocator;
    const n = @as(usize, 1) << @intCast(log);
    const leaves = a.alloc(Digest, n) catch return 1;
    for (leaves, 0..) |*leaf, i| leaf.* = H.digest(input[i * width * 8 ..][0 .. width * 8]);
    var tree = engine.vcs_lifted.prover.MerkleProverLifted(H).fromOwnedLeaves(a, a, leaves) catch return 2;
    defer tree.deinit(a);
    root.* = tree.root();
    if (nodes) |out| {
        var off: usize = 0;
        var level: usize = tree.layers.len;
        while (level > 0) {
            level -= 1;
            const layer = tree.layers[level];
            @memcpy(out[off..][0..layer.len], layer);
            off += layer.len;
        }
    }
    for (0..70) |q| {
        var idx = (q * 7919 + 17) % n;
        for (0..log) |level| {
            paths[q * log + level] = tree.layers[log - level][idx ^ 1];
            idx >>= 1;
        }
    }
    return 0;
}

export fn matched_verify(log: u32, width: u32, input: [*]const u8, paths: [*]const Digest, root: *const Digest) u32 {
    const n = @as(usize, 1) << @intCast(log);
    for (0..70) |q| {
        var idx = (q * 7919 + 17) % n;
        var hash = H.digest(input[idx * width * 8 ..][0 .. width * 8]);
        for (0..log) |level| {
            const sibling = paths[q * log + level];
            hash = if (idx & 1 == 0) H.hashChildren(.{ .left = hash, .right = sibling }) else H.hashChildren(.{ .left = sibling, .right = hash });
            idx >>= 1;
        }
        if (!std.mem.eql(u8, &hash, root)) return 1;
    }
    return 0;
}
