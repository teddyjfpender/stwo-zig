//! Dedicated P2 lifted-tree verifier. Column ordering and index projection
//! reuse the native geometry; commitment operations never call Blake.
const std = @import("std");
const core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const Old = @import("stwo_circuit_frontend").native_verifier.merkle;
const C = @import("common.zig");
const G = @import("../../poseidon2_outer/merkle.zig").ForContext(C.PoseidonContext);
const Var = B.Var;
const M31Wrapper = B.wrappers.M31Wrapper;
pub const columnPermutation = Old.columnPermutation;
pub const treeHeight = Old.treeHeight;
pub const treePositionBits = Old.treePositionBits;
pub const capLogFor = Old.capLogFor;
fn assertAlgebra(comptime V: type) void {
    if (V != C.Q) @compileError("P2 circuit algebra is QM31");
}
pub fn hashLeafM31s(comptime V: type, ctx: *C.Context, values: []const M31Wrapper(Var)) !C.Hash {
    assertAlgebra(V);
    const wires = try ctx.scratch().alloc(Var, values.len);
    for (wires, values) |*wire, value| wire.* = value.get();
    return G.leaf(try C.sidecar(ctx), wires);
}
pub fn hashLeafQm31s(comptime V: type, ctx: *C.Context, values: []const Var) !C.Hash {
    assertAlgebra(V);
    const wires = try ctx.scratch().alloc(Var, 4 * values.len);
    const lanes = B.simd.Simd.fromPacked(values, 4 * values.len);
    for (wires, 0..) |*wire, i| wire.* = try B.simd.unpackIdx(V, ctx, lanes, i);
    return G.leaf(try C.sidecar(ctx), wires);
}
pub fn hashNode(comptime V: type, ctx: *C.Context, left: C.Hash, right: C.Hash) !C.Hash {
    assertAlgebra(V);
    return G.children(try C.sidecar(ctx), left, right);
}
fn selectBit(ctx: *C.Context, bit: Var, left: C.Hash, right: C.Hash) !C.Hash {
    try ctx.eq(try ctx.mul(bit, bit), bit);
    var out: C.Hash = undefined;
    for (&out, left, right) |*wire, x, y| wire.* = try ctx.add(x, try ctx.mul(bit, try ctx.sub(y, x)));
    return out;
}
pub fn merkleNode(comptime V: type, ctx: *C.Context, node: C.Hash, sibling: C.Hash, bit: Var) !C.Hash {
    return hashNode(V, ctx, try selectBit(ctx, bit, node, sibling), try selectBit(ctx, bit, sibling, node));
}
pub fn verifyPath(comptime V: type, ctx: *C.Context, leaf: C.Hash, bits: []const Var, siblings: []const C.Hash, root: C.Hash) !void {
    assertAlgebra(V);
    return G.verifyPath(try C.sidecar(ctx), leaf, bits, siblings, root);
}
pub fn selectHash(comptime V: type, ctx: *C.Context, nodes: []const C.Hash, bits: []const Var) !C.Hash {
    assertAlgebra(V);
    if (bits.len > 5 or nodes.len != @as(usize, 1) << @intCast(bits.len)) return error.ShapeMismatch;
    const layer = try ctx.scratch().dupe(C.Hash, nodes);
    var n = layer.len;
    for (bits) |bit| {
        n /= 2;
        for (0..n) |i| layer[i] = try selectBit(ctx, bit, layer[2 * i], layer[2 * i + 1]);
    }
    return layer[0];
}
pub fn capRoot(comptime V: type, ctx: *C.Context, cap: []const C.Hash) !C.Hash {
    assertAlgebra(V);
    if (cap.len == 0 or cap.len > 32 or !std.math.isPowerOfTwo(cap.len)) return error.ShapeMismatch;
    const layer = try ctx.scratch().dupe(C.Hash, cap);
    var n = layer.len;
    while (n > 1) {
        n /= 2;
        for (0..n) |i| layer[i] = try hashNode(V, ctx, layer[2 * i], layer[2 * i + 1]);
    }
    return layer[0];
}
pub fn verifyCap(comptime V: type, ctx: *C.Context, cap: []const C.Hash, root: C.Hash) !void {
    const actual = try capRoot(V, ctx, cap);
    for (actual, root) |x, y| try ctx.eq(x, y);
}
pub fn verifyPathToCap(comptime V: type, ctx: *C.Context, leaf: C.Hash, bits: []const Var, siblings: []const C.Hash, cap: []const C.Hash) !void {
    if (cap.len == 0 or cap.len > 32 or !std.math.isPowerOfTwo(cap.len)) return error.ShapeMismatch;
    const log = std.math.log2_int(usize, cap.len);
    if (bits.len != siblings.len + log) return error.ShapeMismatch;
    var node = leaf;
    for (bits[0..siblings.len], siblings) |bit, sibling| node = try merkleNode(V, ctx, node, sibling, bit);
    const expected = try selectHash(V, ctx, cap, bits[siblings.len..]);
    for (node, expected) |x, y| try ctx.eq(x, y);
}
pub fn decommitTreesCapped(
    comptime V: type,
    ctx: *C.Context,
    log_sizes: []const []const u32,
    lifting_log: u32,
    queried_values: []const []const []const M31Wrapper(Var),
    auth_paths: []const []const []const C.Hash,
    query_bits: []const []const Var,
    roots: []const C.Hash,
    caps: []const []const C.Hash,
    cap_log: u32,
) anyerror!void {
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

pub fn hashLeafRow(
    comptime V: type,
    ctx: *C.Context,
    tree_values: []const []const M31Wrapper(Var),
    order: []const usize,
    q: usize,
) anyerror!C.Hash {
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
    ctx: *C.Context,
    log_sizes: []const []const u32,
    lifting_log: u32,
    queried_values: []const []const []const M31Wrapper(Var),
    auth_paths: []const []const []const C.Hash,
    query_bits: []const []const Var,
    roots: []const C.Hash,
) anyerror!void {
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
