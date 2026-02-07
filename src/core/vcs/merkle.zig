const std = @import("std");
const hash256 = @import("core/crypto/hash256.zig");

pub const Hash = hash256.Digest32;

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

pub const MerkleTree = struct {
    allocator: std.mem.Allocator,
    leaf_count: usize,
    leaf_capacity: usize,
    /// 1-based binary heap storage. `nodes[0]` is unused.
    nodes: []Hash,

    pub const Error = error{
        IndexOutOfRange,
        EmptyTree,
    };

    pub fn init(allocator: std.mem.Allocator, leaves: []const []const u8) !MerkleTree {
        if (leaves.len == 0) return Error.EmptyTree;

        const leaf_count = leaves.len;
        const leaf_capacity = nextPow2(leaf_count);

        // 1-based: total length = 2*leaf_capacity
        const nodes = try allocator.alloc(Hash, 2 * leaf_capacity);

        // Fill leaves.
        var i: usize = 0;
        while (i < leaf_capacity) : (i += 1) {
            if (i < leaf_count) {
                nodes[leaf_capacity + i] = hashLeaf(leaves[i]);
            } else {
                nodes[leaf_capacity + i] = hashLeaf("");
            }
        }

        // Build internal nodes.
        var idx: usize = leaf_capacity;
        while (idx > 1) {
            idx -= 1;
            nodes[idx] = hashNode(&nodes[idx * 2], &nodes[idx * 2 + 1]);
        }

        return .{
            .allocator = allocator,
            .leaf_count = leaf_count,
            .leaf_capacity = leaf_capacity,
            .nodes = nodes,
        };
    }

    pub fn deinit(self: *MerkleTree) void {
        self.allocator.free(self.nodes);
        self.* = undefined;
    }

    pub fn root(self: MerkleTree) Hash {
        return self.nodes[1];
    }

    pub fn open(self: MerkleTree, allocator: std.mem.Allocator, index: usize) !Proof {
        if (index >= self.leaf_count) return Error.IndexOutOfRange;

        const depth = log2Pow2(self.leaf_capacity);
        const siblings = try allocator.alloc(Hash, depth);

        var idx: usize = self.leaf_capacity + index;
        var d: usize = 0;
        while (d < depth) : (d += 1) {
            const sib = idx ^ 1;
            siblings[d] = self.nodes[sib];
            idx >>= 1;
        }

        return .{
            .leaf_count = self.leaf_count,
            .index = index,
            .siblings = siblings,
        };
    }
};

pub const Proof = struct {
    leaf_count: usize,
    index: usize,
    siblings: []Hash,

    pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
        allocator.free(self.siblings);
        self.* = undefined;
    }

    pub fn verify(self: Proof, leaf_data: []const u8, root: Hash) bool {
        if (self.leaf_count == 0) return false;
        if (self.index >= self.leaf_count) return false;

        const cap = nextPow2(self.leaf_count);
        const depth = log2Pow2(cap);
        if (self.siblings.len != depth) return false;

        var h = hashLeaf(leaf_data);
        var idx: usize = cap + self.index;

        for (self.siblings) |sib| {
            if ((idx & 1) == 0) {
                h = hashNode(&h, &sib);
            } else {
                h = hashNode(&sib, &h);
            }
            idx >>= 1;
        }

        return std.mem.eql(u8, h[0..], root[0..]);
    }
};

fn hashLeaf(data: []const u8) Hash {
    return hash256.hashPrefix1(LEAF_PREFIX, data);
}

fn hashNode(left: *const Hash, right: *const Hash) Hash {
    return hash256.hashPrefix2(NODE_PREFIX, left, right);
}

fn nextPow2(n: usize) usize {
    var p: usize = 1;
    while (p < n) : (p <<= 1) {}
    return p;
}

fn log2Pow2(n: usize) usize {
    std.debug.assert(n != 0 and (n & (n - 1)) == 0);
    var d: usize = 0;
    var t: usize = n;
    while (t > 1) : (t >>= 1) {
        d += 1;
    }
    return d;
}

test "merkle: proofs verify" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const alloc = arena.allocator();

    const leaves = [_][]const u8{ "a", "b", "c" };
    var tree = try MerkleTree.init(alloc, leaves[0..]);
    defer tree.deinit();

    const root = tree.root();

    var i: usize = 0;
    while (i < leaves.len) : (i += 1) {
        var proof = try tree.open(alloc, i);
        defer proof.deinit(alloc);

        try std.testing.expect(proof.verify(leaves[i], root));

        // Wrong leaf must not verify.
        try std.testing.expect(!proof.verify("not-the-leaf", root));
    }
}

test "merkle: corrupted path fails" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const alloc = arena.allocator();

    const leaves = [_][]const u8{ "a", "b", "c", "d" };
    var tree = try MerkleTree.init(alloc, leaves[0..]);
    defer tree.deinit();

    const root = tree.root();

    var proof = try tree.open(alloc, 2);
    defer proof.deinit(alloc);

    try std.testing.expect(proof.verify(leaves[2], root));

    // Flip one bit in the first sibling.
    proof.siblings[0][0] ^= 0x01;
    try std.testing.expect(!proof.verify(leaves[2], root));
}
