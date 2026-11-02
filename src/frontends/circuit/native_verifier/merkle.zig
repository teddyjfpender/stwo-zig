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
