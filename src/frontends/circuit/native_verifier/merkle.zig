//! In-circuit decommitment of the native lifted Merkle trees: port of
//! `MerkleVerifierLifted.verifyImpl` in `core/vcs_lifted/verifier.zig` for
//! one query at a time, with the per-tree query positions of
//! `prepareTreeQueryPositions` in `core/pcs/utils.zig`.
//!
//! Hashes are the domain-prefixed ones of `core/vcs_lifted/blake2_merkle.zig`
//! (`blake_chain.zig`): a leaf is `Blake2s(LEAF_PREFIX || column values)`
//! and a node `Blake2s(NODE_PREFIX || left || right)`.
//!
//! Leaf layout. The native verifier sorts the tree's columns by log size
//! (`std.sort.heap` with `lessByLogSize`, which breaks ties by column index,
//! so the result is the stable sort by log size) and hashes, at each query
//! position, one M31 per column in that order. The value a smaller column
//! contributes at leaf position `p` of a tree of height `H` is its entry at
//! `((p >> (H - log + 1)) << 1) | (p & 1)` (`hashLiftedM31Columns4` in
//! `core/crypto/blake2s_backend.zig`); the proof's queried values already
//! hold exactly that entry, one per column per query, so the circuit only
//! orders them. Trees are as tall as their largest column (`stwo_7b211ed`,
//! `MerkleVerifierLifted.init`); a tree without columns is not checked at
//! all, as natively (`verifyImpl` returns before comparing the root).
//!
//! Query positions. A query drawn in the lifting domain of log size `L`
//! addresses leaf `((p >> (L - H + 1)) << 1) | (p & 1)` of a tree of height
//! `H <= L`: bit 0 of `p`, then bits `L - H + 1 ..< L`, so the tree's path
//! bits are a fixed selection of the query bits.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const blake_chain = @import("blake_chain.zig");

const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const blake = builder.blake;
const wrappers = builder.wrappers;
const U32Wrapper = wrappers.U32Wrapper;
const M31Wrapper = wrappers.M31Wrapper;
const HashValue = blake.HashValue;

pub const DecommitError = Error || error{
    /// A tree's authentication paths are not `height` nodes long, or a
    /// tree is taller than the lifting domain.
    ShapeMismatch,
};

/// The leaf hash of `words`: `Blake2s(LEAF_PREFIX || words)`.
pub fn hashLeafWords(comptime V: type, ctx: *Context(V), words: []const U32Wrapper(Var)) Error!HashValue(Var) {
    return blake_chain.blake2sU32sFrom(V, ctx, blake_chain.leaf_chaining, blake_chain.PREFIX_BYTES, words, 4 * words.len);
}

/// `H.defaultWithInitialState(); updateLeaf(values); finalize()`: each M31 is
/// one little-endian word.
pub fn hashLeafM31s(comptime V: type, ctx: *Context(V), values: []const M31Wrapper(Var)) Error!HashValue(Var) {
    const words = try ctx.scratch().alloc(U32Wrapper(Var), values.len);
    for (words, values) |*word, value| word.* = try blake.m31ToU32(V, ctx, value.get());
    return hashLeafWords(V, ctx, words);
}

/// A leaf of QM31 values (the FRI layers): each value is its four limbs,
/// value-major (`fri/merkle_queries.zig` `build`).
pub fn hashLeafQm31s(comptime V: type, ctx: *Context(V), values: []const Var) Error!HashValue(Var) {
    const words = try blake.unpackQm31sToU32Words(V, ctx, values);
    return hashLeafWords(V, ctx, words);
}

/// `H.hashChildren`: `Blake2s(NODE_PREFIX || left || right)`.
pub fn hashNode(comptime V: type, ctx: *Context(V), left: HashValue(Var), right: HashValue(Var)) Error!HashValue(Var) {
    var words: [16]U32Wrapper(Var) = undefined;
    @memcpy(words[0..8], &left.words);
    @memcpy(words[8..], &right.words);
    return blake_chain.blake2sU32sFrom(V, ctx, blake_chain.node_chaining, blake_chain.PREFIX_BYTES, &words, 64);
}

/// The parent of `node` and `sibling`, `node` on the right when `bit` is 1.
pub fn merkleNode(comptime V: type, ctx: *Context(V), node: HashValue(Var), sibling: HashValue(Var), bit: Var) Error!HashValue(Var) {
    var left: HashValue(Var) = undefined;
    var right: HashValue(Var) = undefined;
    for (node.words, sibling.words, &left.words, &right.words) |a, b, *l, *r| {
        const flipped = try builder.ops.condFlipU32(V, ctx, bit, a, b);
        l.* = flipped[0];
        r.* = flipped[1];
    }
    return hashNode(V, ctx, left, right);
}

/// Recomputes the root from `leaf` along `siblings` (the leaf's sibling
/// first; `bits` are the leaf position's bits, LSB first) and requires it
/// equal to `root`, word for word.
pub fn verifyPath(
    comptime V: type,
    ctx: *Context(V),
    leaf: HashValue(Var),
    bits: []const Var,
    siblings: []const HashValue(Var),
    root: HashValue(Var),
) Error!void {
    std.debug.assert(bits.len == siblings.len);
    var node = leaf;
    for (bits, siblings) |bit, sibling| node = try merkleNode(V, ctx, node, sibling, bit);
    for (node.words, root.words) |recomputed, expected| try ctx.eq(recomputed.get(), expected.get());
}

// ---------------------------------------------------------------------------
// Merkle cap (M6 diet-wire, rv64-m6-diet-wire.md section 5). A cap of log `c`
// is the 2^c nodes c levels below the root, in index order. The circuit
// hashes the cap up to the root once (2^c - 1 node hashes) and stops every
// query's path c levels early, where the path's node must equal the cap
// entry its top c position bits select. Same binding as a full path (the
// root is a hash of the cap and each path ends in the cap), c fewer node
// hashes per query. The cap entries are guessed witness, never constants.

/// `bit ? b : a`, word by word.
fn selectHashBit(comptime V: type, ctx: *Context(V), bit: Var, a: HashValue(Var), b: HashValue(Var)) Error!HashValue(Var) {
    var out: HashValue(Var) = undefined;
    for (a.words, b.words, &out.words) |x, y, *o| o.* = (try builder.ops.condFlipU32(V, ctx, bit, x, y))[0];
    return out;
}

/// `nodes[index]` where `index = sum bits[k] << k` (LSB first); `nodes.len == 2^bits.len`.
pub fn selectHash(comptime V: type, ctx: *Context(V), nodes: []const HashValue(Var), bits: []const Var) Error!HashValue(Var) {
    std.debug.assert(nodes.len == @as(usize, 1) << @intCast(bits.len));
    const layer = try ctx.scratch().dupe(HashValue(Var), nodes);
    var n = layer.len;
    for (bits) |bit| {
        n /= 2;
        for (0..n) |i| layer[i] = try selectHashBit(V, ctx, bit, layer[2 * i], layer[2 * i + 1]);
    }
    return layer[0];
}

/// The root above a cap (`cap.len` a power of two >= 1).
pub fn capRoot(comptime V: type, ctx: *Context(V), cap: []const HashValue(Var)) Error!HashValue(Var) {
    std.debug.assert(cap.len >= 1 and std.math.isPowerOfTwo(cap.len));
    const layer = try ctx.scratch().dupe(HashValue(Var), cap);
    var n = layer.len;
    while (n > 1) {
        n /= 2;
        for (0..n) |i| layer[i] = try hashNode(V, ctx, layer[2 * i], layer[2 * i + 1]);
    }
    return layer[0];
}

/// Requires `root == capRoot(cap)`, word for word.
pub fn verifyCap(comptime V: type, ctx: *Context(V), cap: []const HashValue(Var), root: HashValue(Var)) Error!void {
    const recomputed = try capRoot(V, ctx, cap);
    for (recomputed.words, root.words) |a, b| try ctx.eq(a.get(), b.get());
}

/// `verifyPath` that stops `log2(cap.len)` levels below the root: walks
/// `siblings` (leaf sibling first; `siblings.len = bits.len - log2(cap.len)`)
/// and requires the reached node to equal the cap entry selected by the
/// remaining (top) position bits. The caller checks the cap once per tree
/// (`verifyCap`).
pub fn verifyPathToCap(
    comptime V: type,
    ctx: *Context(V),
    leaf: HashValue(Var),
    bits: []const Var,
    siblings: []const HashValue(Var),
    cap: []const HashValue(Var),
) Error!void {
    const cap_log = std.math.log2_int(usize, cap.len);
    std.debug.assert(std.math.isPowerOfTwo(cap.len) and bits.len == siblings.len + cap_log);
    var node = leaf;
    for (bits[0..siblings.len], siblings) |bit, sibling| node = try merkleNode(V, ctx, node, sibling, bit);
    const expected = try selectHash(V, ctx, cap, bits[siblings.len..]);
    for (node.words, expected.words) |a, b| try ctx.eq(a.get(), b.get());
}

/// The cap log a tree of `height` uses under a requested cap log `c`: trees
/// no taller than the cap keep their full path (no cap).
pub fn capLogFor(height: u32, cap_log: u32) u32 {
    return if (height > cap_log) cap_log else 0;
}

/// `decommitTrees` with a Merkle cap per tree: `caps[t]` holds
/// `2^capLogFor(height_t, cap_log)` guessed nodes and `auth_paths[t][q]` the
/// `height_t - capLogFor(..)` lowest siblings. A tree with an empty cap is
/// checked with full paths, exactly as `decommitTrees`.
pub fn decommitTreesCapped(
    comptime V: type,
    ctx: *Context(V),
    log_sizes: []const []const u32,
    lifting_log: u32,
    queried_values: []const []const []const M31Wrapper(Var),
    auth_paths: []const []const []const HashValue(Var),
    query_bits: []const []const Var,
    roots: []const HashValue(Var),
    caps: []const []const HashValue(Var),
    cap_log: u32,
) DecommitError!void {
    if (log_sizes.len != roots.len or queried_values.len != roots.len or auth_paths.len != roots.len or caps.len != roots.len) return error.ShapeMismatch;
    if (query_bits.len != lifting_log) return error.ShapeMismatch;
    const n_queries = if (query_bits.len == 0) 0 else query_bits[0].len;
    const scratch = ctx.scratch();
    const bits_for_query = try scratch.alloc(Var, lifting_log);
    for (log_sizes, queried_values, auth_paths, roots, caps) |tree_logs, tree_values, tree_paths, root, cap| {
        if (tree_logs.len == 0) {
            if (cap.len != 0) return error.ShapeMismatch;
            continue;
        }
        if (tree_values.len != tree_logs.len or tree_paths.len != n_queries) return error.ShapeMismatch;
        const height = treeHeight(tree_logs);
        const cl = capLogFor(height, cap_log);
        if (cap.len != (if (cl == 0) @as(usize, 0) else @as(usize, 1) << @intCast(cl))) return error.ShapeMismatch;
        if (cl != 0) try verifyCap(V, ctx, cap, root);
        const order = try columnPermutation(scratch, tree_logs);
        for (tree_values) |column| {
            if (column.len != n_queries) return error.ShapeMismatch;
        }
        for (0..n_queries) |q| {
            const leaf = try hashLeafRow(V, ctx, tree_values, order, q);
            for (bits_for_query, query_bits) |*bit, column_bits| bit.* = column_bits[q];
            const position_bits = try treePositionBits(scratch, bits_for_query, height, lifting_log);
            if (tree_paths[q].len != height - cl) return error.ShapeMismatch;
            if (cl == 0) {
                try verifyPath(V, ctx, leaf, position_bits, tree_paths[q], root);
            } else {
                try verifyPathToCap(V, ctx, leaf, position_bits, tree_paths[q], cap);
            }
        }
    }
}

/// Host side: the 2^cap_log cap of one tree from captured query paths.
/// `leaves[q]` is query q's leaf hash at tree position `positions[q]`,
/// `paths[q]` its full authentication path (leaf sibling first, `height`
/// long). Node j at the cap level is either some query's own node there or
/// some query's sibling; it is derivable whenever a query lies under j or
/// under j ^ 1. Returns `error.MerkleCapUncovered` otherwise (completeness:
/// 2^(c-1) (1 - 2^-(c-1))^queries per tree, 1.4e-13 for c = 3 and 108
/// queries) and `error.MerkleCapMismatch` when two queries disagree or the
/// cap does not hash to `root` (an invalid proof, never accepted upstream).
pub fn hostCap(comptime H: type, out: []H.Hash, positions: []const usize, leaves: []const H.Hash, paths: []const []const H.Hash, height: u32, root: H.Hash) error{ MerkleCapUncovered, MerkleCapMismatch, ShapeMismatch }!void {
    if (!std.math.isPowerOfTwo(out.len) or out.len < 2 or out.len > 64) return error.ShapeMismatch;
    const cap_log: u32 = std.math.log2_int(usize, out.len);
    if (cap_log >= height or positions.len != leaves.len or paths.len != leaves.len) return error.ShapeMismatch;
    var known: [64]bool = @splat(false);
    const walk = height - cap_log;
    for (positions, leaves, paths) |position, leaf, path| {
        if (path.len != height) return error.ShapeMismatch;
        var node = leaf;
        for (path[0..walk], 0..) |sibling, level| {
            node = if ((position >> @intCast(level)) & 1 == 1) H.hashChildren(.{ .left = sibling, .right = node }) else H.hashChildren(.{ .left = node, .right = sibling });
        }
        const at = position >> @intCast(walk);
        if (at >= out.len) return error.ShapeMismatch;
        const indices = [2]usize{ at, at ^ 1 };
        const hashes = [2]H.Hash{ node, path[walk] };
        for (indices, hashes) |index, hash| {
            if (known[index]) {
                if (!std.mem.eql(u8, std.mem.asBytes(&out[index]), std.mem.asBytes(&hash))) return error.MerkleCapMismatch;
            } else {
                out[index] = hash;
                known[index] = true;
            }
        }
    }
    for (known[0..out.len]) |k| if (!k) return error.MerkleCapUncovered;
    var layer: [64]H.Hash = undefined;
    @memcpy(layer[0..out.len], out);
    var n = out.len;
    while (n > 1) {
        n /= 2;
        for (0..n) |i| layer[i] = H.hashChildren(.{ .left = layer[2 * i], .right = layer[2 * i + 1] });
    }
    if (!std.mem.eql(u8, std.mem.asBytes(&layer[0]), std.mem.asBytes(&root))) return error.MerkleCapMismatch;
}

/// The committed column order of a tree: column indices sorted by log size,
/// ties by index (the order `lessByLogSize` under `std.sort.heap` yields).
pub fn columnPermutation(allocator: std.mem.Allocator, log_sizes: []const u32) std.mem.Allocator.Error![]usize {
    const order = try allocator.alloc(usize, log_sizes.len);
    for (order, 0..) |*index, i| index.* = i;
    std.sort.insertion(usize, order, log_sizes, lessByLogSize);
    return order;
}

fn lessByLogSize(log_sizes: []const u32, lhs: usize, rhs: usize) bool {
    if (log_sizes[lhs] == log_sizes[rhs]) return lhs < rhs;
    return log_sizes[lhs] < log_sizes[rhs];
}

/// The height of a tree: its largest column's (extended) log size.
pub fn treeHeight(log_sizes: []const u32) u32 {
    var height: u32 = 0;
    for (log_sizes) |log_size| height = @max(height, log_size);
    return height;
}

/// `prepareTreeQueryPositions` as a bit selection: the path bits of a tree
/// of height `tree_log` for a query of `lifting_log` bits (scratch-owned).
pub fn treePositionBits(allocator: std.mem.Allocator, query_bits: []const Var, tree_log: u32, lifting_log: u32) DecommitError![]Var {
    if (tree_log > lifting_log or query_bits.len != lifting_log) return error.ShapeMismatch;
    const out = try allocator.alloc(Var, tree_log);
    if (tree_log == 0) return out;
    out[0] = query_bits[0];
    const skipped = lifting_log - tree_log;
    for (out[1..], 1..) |*bit, i| bit.* = query_bits[i + skipped];
    return out;
}

/// `prepareTreeQueryPositions` on the host, for one position.
pub fn treePosition(position: usize, tree_log: u32, lifting_log: u32) usize {
    std.debug.assert(tree_log <= lifting_log);
    if (tree_log == 0) return 0;
    return ((position >> @intCast(lifting_log - tree_log + 1)) << 1) + (position & 1);
}

/// The leaf of query `q`: the tree's values at that query in committed
/// column order (`order`, from `columnPermutation`), hashed as a leaf.
pub fn hashLeafRow(
    comptime V: type,
    ctx: *Context(V),
    tree_values: []const []const M31Wrapper(Var),
    order: []const usize,
    q: usize,
) Error!HashValue(Var) {
    const row = try ctx.scratch().alloc(M31Wrapper(Var), order.len);
    for (row, order) |*value, column| value.* = tree_values[column][q];
    return hashLeafM31s(V, ctx, row);
}

/// Decommits every tree at every query. `log_sizes[t]` are tree `t`'s
/// column log sizes (committed order, extended by the blowup);
/// `queried_values[t][c][q]`, `auth_paths[t][q]` (leaf sibling first) and
/// `query_bits[i][q]` (bit `i` of query `q` in the lifting domain). A tree
/// without columns is skipped, as natively.
pub fn decommitTrees(
    comptime V: type,
    ctx: *Context(V),
    log_sizes: []const []const u32,
    lifting_log: u32,
    queried_values: []const []const []const M31Wrapper(Var),
    auth_paths: []const []const []const HashValue(Var),
    query_bits: []const []const Var,
    roots: []const HashValue(Var),
) DecommitError!void {
    if (log_sizes.len != roots.len or queried_values.len != roots.len or auth_paths.len != roots.len) return error.ShapeMismatch;
    if (query_bits.len != lifting_log) return error.ShapeMismatch;
    const n_queries = if (query_bits.len == 0) 0 else query_bits[0].len;
    const scratch = ctx.scratch();
    const bits_for_query = try scratch.alloc(Var, lifting_log);

    for (log_sizes, queried_values, auth_paths, roots) |tree_logs, tree_values, tree_paths, root| {
        if (tree_logs.len == 0) continue;
        if (tree_values.len != tree_logs.len or tree_paths.len != n_queries) return error.ShapeMismatch;
        const height = treeHeight(tree_logs);
        const order = try columnPermutation(scratch, tree_logs);
        for (tree_values) |column| {
            if (column.len != n_queries) return error.ShapeMismatch;
        }
        for (0..n_queries) |q| {
            const leaf = try hashLeafRow(V, ctx, tree_values, order, q);
            for (bits_for_query, query_bits) |*bit, column_bits| bit.* = column_bits[q];
            const position_bits = try treePositionBits(scratch, bits_for_query, height, lifting_log);
            if (tree_paths[q].len != height) return error.ShapeMismatch;
            try verifyPath(V, ctx, leaf, position_bits, tree_paths[q], root);
        }
    }
}

test {
    _ = @import("merkle_test.zig");
}

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;

test "merkle: tree positions agree with prepareTreeQueryPositions on a whole domain" {
    const lifting_log: u32 = 6;
    var positions: [64]usize = undefined;
    for (&positions, 0..) |*position, i| position.* = i;
    for ([_]u32{ 6, 4, 2, 1 }) |tree_log| {
        const expected = try core.pcs.utils.prepareTreeQueryPositions(std.testing.allocator, &positions, lifting_log, tree_log);
        defer std.testing.allocator.free(expected);
        for (positions, expected) |position, want| try std.testing.expectEqual(want, treePosition(position, tree_log, lifting_log));
    }
}

test "merkle: verifyPath accepts the native path and rejects a flipped bit or sibling" {
    const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Case = enum { valid, wrong_bit, wrong_sibling };
    for ([_]Case{ .valid, .wrong_bit, .wrong_sibling }) |case| {
        var ctx = try Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const values = [_]M31{ M31.fromCanonical(3), M31.fromCanonical(5) };
        var leaf_hasher = Hasher.defaultWithInitialState();
        leaf_hasher.updateLeaf(&values);
        var node = leaf_hasher.finalize();
        var siblings: [3]Hasher.Hash = undefined;
        // Position 0b101: right, left, right.
        const bit_values = [3]u32{ 1, 0, 1 };
        for (&siblings, bit_values, 0..) |*sibling, bit, level| {
            for (sibling, 0..) |*byte, i| byte.* = @intCast((level + 1) * 17 + i);
            node = if (bit == 1) Hasher.hashChildren(.{ .left = sibling.*, .right = node }) else Hasher.hashChildren(.{ .left = node, .right = sibling.* });
        }
        var wires: [values.len]M31Wrapper(Var) = undefined;
        for (&wires, values) |*wire, value| wire.* = try wrappers.guessM31(QM31, &ctx, wrappers.m31Value(QM31, value));
        const leaf = try hashLeafM31s(QM31, &ctx, &wires);
        var bits: [3]Var = undefined;
        for (&bits, bit_values, 0..) |*bit, value, level| {
            const used = if (case == .wrong_bit and level == 1) 1 - value else value;
            bit.* = try ctx.guess(builder.ivalue.qm31FromU32s(used, 0, 0, 0));
        }
        var path: [3]HashValue(Var) = undefined;
        for (&path, siblings, 0..) |*wire, sibling, level| {
            var digest = sibling;
            if (case == .wrong_sibling and level == 2) digest[0] ^= 1;
            wire.* = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, digest));
        }
        const root = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, node));
        try verifyPath(QM31, &ctx, leaf, &bits, &path, root);
        try ctx.finalize(false);
        try std.testing.expectEqual(case == .valid, try ctx.isCircuitValid());
    }
}

test "merkle cap: hostCap recovers the level-c nodes, capped paths accept, tampering rejects" {
    const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const height: u32 = 6;
    const cap_log: u32 = 3;
    var levels: [height + 1][64]Hasher.Hash = undefined;
    for (&levels[0], 0..) |*leaf, i| {
        for (leaf, 0..) |*byte, j| byte.* = @truncate(i * 31 + j * 7 + 1);
    }
    var width: usize = 64;
    for (1..height + 1) |l| {
        width /= 2;
        for (0..width) |i| levels[l][i] = Hasher.hashChildren(.{ .left = levels[l - 1][2 * i], .right = levels[l - 1][2 * i + 1] });
    }
    const root = levels[height][0];
    const positions = [_]usize{ 3, 9, 17, 22, 40, 41, 55, 63 };
    var leaves: [positions.len]Hasher.Hash = undefined;
    var path_store: [positions.len][height]Hasher.Hash = undefined;
    var paths: [positions.len][]const Hasher.Hash = undefined;
    for (positions, &leaves, &path_store, &paths) |p, *leaf, *store, *path| {
        leaf.* = levels[0][p];
        for (store, 0..) |*sibling, l| sibling.* = levels[l][(p >> @intCast(l)) ^ 1];
        path.* = store;
    }
    var cap: [8]Hasher.Hash = undefined;
    try hostCap(Hasher, &cap, &positions, &leaves, &paths, height, root);
    for (cap, 0..) |node, j| try std.testing.expectEqualSlices(u8, &levels[height - cap_log][j], &node);
    // A wrong root and an uncovered cap are refused on the host.
    var bad_root = root;
    bad_root[0] ^= 1;
    try std.testing.expectError(error.MerkleCapMismatch, hostCap(Hasher, &cap, &positions, &leaves, &paths, height, bad_root));
    try std.testing.expectError(error.MerkleCapUncovered, hostCap(Hasher, &cap, positions[0..1], leaves[0..1], paths[0..1], height, root));

    const Case = enum { valid, cap_node, sibling, bit };
    for ([_]Case{ .valid, .cap_node, .sibling, .bit }) |case| {
        var ctx = try Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        var cap_wires: [8]HashValue(Var) = undefined;
        for (&cap_wires, cap, 0..) |*wire, node, j| {
            var digest = node;
            if (case == .cap_node and j == 5) digest[7] ^= 1;
            wire.* = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, digest));
        }
        const root_wire = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, root));
        try verifyCap(QM31, &ctx, &cap_wires, root_wire);
        for (positions, leaves, path_store, 0..) |p, leaf, store, qi| {
            const leaf_wire = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, leaf));
            var bits: [height]Var = undefined;
            for (&bits, 0..) |*bit, l| {
                var value: u32 = @intCast((p >> @intCast(l)) & 1);
                if (case == .bit and qi == 2 and l == height - 1) value ^= 1;
                bit.* = try ctx.guess(builder.ivalue.qm31FromU32s(value, 0, 0, 0));
            }
            var siblings: [height - cap_log]HashValue(Var) = undefined;
            for (&siblings, store[0 .. height - cap_log], 0..) |*wire, sibling, l| {
                var digest = sibling;
                if (case == .sibling and qi == 4 and l == 1) digest[0] ^= 1;
                wire.* = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, digest));
            }
            try verifyPathToCap(QM31, &ctx, leaf_wire, &bits, &siblings, &cap_wires);
        }
        try ctx.finalize(false);
        try std.testing.expectEqual(case == .valid, try ctx.isCircuitValid());
    }
}
