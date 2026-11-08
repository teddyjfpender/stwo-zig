//! Corpus v4 compress hooks that already apply to TODAY's verifier (stream profiles, M6 prep for M7).
//! rv64-m7-compress-profiles.md sec. 2(3): the core lifted Merkle decommitment is already a batched
//! multiproof; its wire set must be canonical (exactly the siblings not on a path, in verifier order).
//! These tests build a real tree, the canonical witness, and check every non-canonical variant is refused.
const std = @import("std");
const core = @import("stwo_core");
const V = core.vcs_lifted.verifier;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const M31 = core.fields.m31.M31;
const Hash = H.Hash;

const LOG: u32 = 6; // 64 leaves
const N: usize = 1 << LOG;
const COLS: usize = 2;

fn leafValue(col: usize, row: usize) M31 {
    return M31.fromCanonical(@intCast(1000 * col + 7 * row + 1));
}
fn leafHash(row: usize) Hash {
    var s = H.defaultWithInitialState();
    var vals: [COLS]M31 = undefined;
    for (0..COLS) |c| vals[c] = leafValue(c, row);
    s.updateLeaf(vals[0..]);
    return s.finalize();
}
const Tree = struct {
    levels: [LOG + 1][]Hash, // levels[0] = leaves, levels[LOG] = root
    fn init(a: std.mem.Allocator) !Tree {
        var t: Tree = undefined;
        t.levels[0] = try a.alloc(Hash, N);
        for (0..N) |i| t.levels[0][i] = leafHash(i);
        for (1..LOG + 1) |l| {
            const below = t.levels[l - 1];
            t.levels[l] = try a.alloc(Hash, below.len / 2);
            for (t.levels[l], 0..) |*h, i| h.* = H.hashChildren(.{ .left = below[2 * i], .right = below[2 * i + 1] });
        }
        return t;
    }
    fn deinit(self: *Tree, a: std.mem.Allocator) void {
        for (self.levels) |l| a.free(l);
    }
    /// Canonical witness in the verifier's order: bottom-up, per layer ascending node index, one hash for every
    /// path node whose sibling is not itself on a path (vcs_lifted verifier.zig, layer loop).
    fn witness(self: Tree, a: std.mem.Allocator, positions: []const usize) ![]Hash {
        var out = std.ArrayList(Hash).empty;
        errdefer out.deinit(a);
        var layer = std.ArrayList(usize).empty;
        defer layer.deinit(a);
        for (positions) |p| if (std.mem.indexOfScalar(usize, layer.items, p) == null) try layer.append(a, p);
        std.mem.sort(usize, layer.items, {}, std.sort.asc(usize));
        for (0..LOG) |l| {
            var next = std.ArrayList(usize).empty;
            defer next.deinit(a);
            var i: usize = 0;
            while (i < layer.items.len) {
                const idx = layer.items[i];
                if (i + 1 < layer.items.len and layer.items[i + 1] == idx ^ 1) {
                    i += 2;
                } else {
                    try out.append(a, self.levels[l][idx ^ 1]);
                    i += 1;
                }
                if (next.items.len == 0 or next.items[next.items.len - 1] != idx >> 1) try next.append(a, idx >> 1);
            }
            layer.clearRetainingCapacity();
            try layer.appendSlice(a, next.items);
        }
        return out.toOwnedSlice(a);
    }
};
fn values(a: std.mem.Allocator, positions: []const usize) ![][]M31 {
    const cols = try a.alloc([]M31, COLS);
    for (cols, 0..) |*col, c| {
        col.* = try a.alloc(M31, positions.len);
        for (positions, 0..) |p, q| col.*[q] = leafValue(c, p);
    }
    return cols;
}
fn freeValues(a: std.mem.Allocator, cols: [][]M31) void {
    for (cols) |c| a.free(c);
    a.free(cols);
}
fn check(a: std.mem.Allocator, root: Hash, positions: []const usize, cols: []const []const M31, wit: []const Hash) !void {
    var verifier = try V.MerkleVerifierLifted(H).init(a, root, &[_]u32{ LOG, LOG });
    defer verifier.deinit(a);
    var d = V.MerkleDecommitmentLifted(H){ .hash_witness = try a.dupe(Hash, wit) };
    defer d.deinit(a);
    try verifier.verify(a, positions, cols, d);
}

const POSITIONS = [_]usize{ 3, 9, 10, 11, 40, 63 };

test "corpus CP01 multiproof: canonical witness verifies; extra, dropped, reordered or duplicated sibling is refused" {
    const a = std.testing.allocator;
    var tree = try Tree.init(a);
    defer tree.deinit(a);
    const root = tree.levels[LOG][0];
    const cols = try values(a, &POSITIONS);
    defer freeValues(a, cols);
    const wit = try tree.witness(a, &POSITIONS);
    defer a.free(wit);
    // Batched decommitment sends fewer hashes than independent paths (6 x 6 = 36).
    try std.testing.expect(wit.len < POSITIONS.len * LOG);
    try check(a, root, &POSITIONS, cols, wit);

    // Extra sibling appended (any value, including a correct hash): WitnessTooLong.
    {
        const longer = try a.alloc(Hash, wit.len + 1);
        defer a.free(longer);
        @memcpy(longer[0..wit.len], wit);
        longer[wit.len] = tree.levels[1][0];
        try std.testing.expectError(error.WitnessTooLong, check(a, root, &POSITIONS, cols, longer));
    }
    // Last sibling dropped: WitnessTooShort.
    try std.testing.expectError(error.WitnessTooShort, check(a, root, &POSITIONS, cols, wit[0 .. wit.len - 1]));
    // Two siblings swapped (reordered set, same multiset): root mismatch.
    {
        const swapped = try a.dupe(Hash, wit);
        defer a.free(swapped);
        std.mem.swap(Hash, &swapped[0], &swapped[1]);
        try std.testing.expect(!std.mem.eql(u8, std.mem.asBytes(&swapped[0]), std.mem.asBytes(&swapped[1])));
        try std.testing.expectError(error.RootMismatch, check(a, root, &POSITIONS, cols, swapped));
    }
    // One sibling replaced by a duplicate of another: root mismatch.
    {
        const dup = try a.dupe(Hash, wit);
        defer a.free(dup);
        dup[2] = dup[0];
        try std.testing.expectError(error.RootMismatch, check(a, root, &POSITIONS, cols, dup));
    }
    // A sibling that IS on a path (derivable) sent in place of the canonical one: root mismatch / length.
    {
        const bad = try a.dupe(Hash, wit);
        defer a.free(bad);
        bad[0] = tree.levels[0][POSITIONS[0]];
        try std.testing.expectError(error.RootMismatch, check(a, root, &POSITIONS, cols, bad));
    }
}
test "corpus CP02 multiproof: a changed upper node (cap-level substitution) or opened value is refused" {
    const a = std.testing.allocator;
    var tree = try Tree.init(a);
    defer tree.deinit(a);
    const root = tree.levels[LOG][0];
    const cols = try values(a, &POSITIONS);
    defer freeValues(a, cols);
    const wit = try tree.witness(a, &POSITIONS);
    defer a.free(wit);
    // The topmost witness hash is a level >= LOG-2 node (a 4-node "cap" level): flip one byte.
    const top = try a.dupe(Hash, wit);
    defer a.free(top);
    top[top.len - 1][0] ^= 1;
    try std.testing.expectError(error.RootMismatch, check(a, root, &POSITIONS, cols, top));
    // An opened value changed with the witness kept.
    cols[1][3] = cols[1][3].add(M31.one());
    try std.testing.expectError(error.RootMismatch, check(a, root, &POSITIONS, cols, wit));
}
test "multiproof sibling count matches the M7 size model's rule (exact, rv64_m7_compress_model.multiproof_siblings)" {
    const a = std.testing.allocator;
    var tree = try Tree.init(a);
    defer tree.deinit(a);
    const wit = try tree.witness(a, &POSITIONS);
    defer a.free(wit);
    // Hand count for {3,9,10,11,40,63} in a 64-leaf tree (python model gives the same, see the note):
    // L0: 3->2, 9->8, 10/11 pair, 40->41, 63->62  = 4; L1: {1,4,5,20,31}: 1->0, 4/5 pair, 20->21, 31->30 = 3;
    // L2: {0,2,10,15}: 0->1, 2->3, 10->11, 15->14 = 4; L3: {0,1,5,7}: 0/1 pair, 5->4, 7->6 = 2;
    // L4: {0,2,3}: 0->1, 2/3 pair = 1; L5: {0,1}: pair = 0. Total 14.
    try std.testing.expectEqual(@as(usize, 14), wit.len);
}
