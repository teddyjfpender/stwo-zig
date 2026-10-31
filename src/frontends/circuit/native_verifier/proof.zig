//! The fixed-width witness of a native proof, its guess order, and its
//! construction from a natively verified `core.proof.StarkProof(H)` plus the
//! verifier's `VerifiedProofCapture(H)` (`core/pcs/verifier.zig`).
//!
//! The native proof deduplicates query openings (`MerkleDecommitmentLifted`
//! multiproofs, FRI witnesses of the missing coset values only). The capture
//! re-expands them per raw transcript query: `queried_values` tree-major,
//! then column, then raw query (`expandQueriedColumns`); `trace_paths[t]`
//! one full path per raw query (`MerklePathCapture.path`, leaf sibling
//! first); `fri.layers[k]` per raw query the full `2^fold_step` coset
//! (`FriLayerQueryCapture.queryValues`, position order) and the path above
//! the coset's subtree (`queryPath`). A tree without columns has no paths
//! and is never checked natively; its capture slot is not read.
//!
//! Guess order (`guess`): commitments (tree order, eight words each),
//! sampled values (tree, column, sample), queried values (tree, column,
//! query), authentication paths (tree, query, leaf side first), the proof of
//! work nonce (low word, high word), then per FRI layer its commitment, the
//! cosets (query, position) and the paths (query, leaf side first), and the
//! last layer coefficients. Every value is a guess; nothing is a constant.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const fri = @import("fri.zig");
const shape_mod = @import("shape.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const blake = builder.blake;
const wrappers = builder.wrappers;
const HashValue = blake.HashValue;
const U32Wrapper = wrappers.U32Wrapper;
const M31Wrapper = wrappers.M31Wrapper;

pub const ConvertError = std.mem.Allocator.Error || error{
    /// The proof or capture disagrees with the shape (tree, column, sample,
    /// query or layer counts).
    ShapeMismatch,
};

/// `Proof(QM31)` holds values, `Proof(NoValue)` placeholders, `Proof(Var)`
/// the guessed wires.
pub fn Proof(comptime T: type) type {
    return struct {
        /// One root per tree.
        commitments: []const HashValue(T),
        /// `[tree][column][sample]`.
        sampled_values: []const []const []const T,
        /// `[tree][column][raw query]`.
        queried_values: []const []const []const M31Wrapper(T),
        /// `[tree][raw query][level]`, leaf sibling first; empty per query
        /// for a tree without columns.
        auth_paths: []const []const []const HashValue(T),
        /// The proof of work nonce as `(low, high)` words.
        pow_nonce: [2]U32Wrapper(T),
        fri: fri.FriProof(T),

        /// Checks the counts against `shape` (sample and layer counts).
        pub fn validateStructure(self: *const @This(), shape: *const shape_mod.Shape) ConvertError!void {
            const n_trees = shape.nTrees();
            const n_queries = shape.nQueries();
            if (self.commitments.len != n_trees or self.sampled_values.len != n_trees) return error.ShapeMismatch;
            if (self.queried_values.len != n_trees or self.auth_paths.len != n_trees) return error.ShapeMismatch;
            for (0..n_trees) |tree| {
                const n_columns = shape.nColumns(tree);
                if (self.sampled_values[tree].len != n_columns or self.queried_values[tree].len != n_columns) return error.ShapeMismatch;
                for (0..n_columns) |column| {
                    if (self.sampled_values[tree][column].len != shape.sampleCount(tree, column)) return error.ShapeMismatch;
                    if (self.queried_values[tree][column].len != n_queries) return error.ShapeMismatch;
                }
                if (n_columns == 0) continue;
                if (self.auth_paths[tree].len != n_queries) return error.ShapeMismatch;
                for (self.auth_paths[tree]) |path| {
                    if (path.len != shape.treeHeight(tree)) return error.ShapeMismatch;
                }
            }
            var steps_buffer: [64]u32 = undefined;
            const steps = shape.foldSteps(&steps_buffer);
            if (self.fri.layers.len != steps.len) return error.ShapeMismatch;
            var log_size = shape.liftingLogSize();
            for (self.fri.layers, steps) |layer, step| {
                if (layer.cosets.len != n_queries or layer.auth_paths.len != n_queries) return error.ShapeMismatch;
                for (layer.cosets, layer.auth_paths) |coset, path| {
                    if (coset.len != @as(usize, 1) << @intCast(step) or path.len != log_size - step) return error.ShapeMismatch;
                }
                log_size -= step;
            }
            if (self.fri.last_layer_coefs.len != shape.nLastLayerCoefficients()) return error.ShapeMismatch;
        }
    };
}

/// Guesses every value of `proof`, in the documented order (scratch-owned
/// wires).
pub fn guess(comptime V: type, ctx: *Context(V), proof: *const Proof(V)) Error!Proof(Var) {
    const scratch = ctx.scratch();
    const commitments = try scratch.alloc(HashValue(Var), proof.commitments.len);
    for (commitments, proof.commitments) |*wire, root| wire.* = try blake.guessHash(V, ctx, root);

    const sampled = try scratch.alloc([]const []const Var, proof.sampled_values.len);
    for (sampled, proof.sampled_values) |*tree_wires, tree| {
        const columns = try scratch.alloc([]const Var, tree.len);
        for (columns, tree) |*column_wires, column| column_wires.* = try guessValues(V, ctx, column);
        tree_wires.* = columns;
    }

    const queried = try scratch.alloc([]const []const M31Wrapper(Var), proof.queried_values.len);
    for (queried, proof.queried_values) |*tree_wires, tree| {
        const columns = try scratch.alloc([]const M31Wrapper(Var), tree.len);
        for (columns, tree) |*column_wires, column| {
            const wires = try scratch.alloc(M31Wrapper(Var), column.len);
            for (wires, column) |*wire, value| wire.* = try wrappers.guessM31(V, ctx, value);
            column_wires.* = wires;
        }
        tree_wires.* = columns;
    }

    const paths = try scratch.alloc([]const []const HashValue(Var), proof.auth_paths.len);
    for (paths, proof.auth_paths) |*tree_wires, tree| tree_wires.* = try guessPaths(V, ctx, tree);

    const nonce = [2]U32Wrapper(Var){
        try wrappers.guessU32(V, ctx, proof.pow_nonce[0]),
        try wrappers.guessU32(V, ctx, proof.pow_nonce[1]),
    };

    const layers = try scratch.alloc(fri.Layer(Var), proof.fri.layers.len);
    for (layers, proof.fri.layers) |*wire, layer| {
        const commitment = try blake.guessHash(V, ctx, layer.commitment);
        const cosets = try scratch.alloc([]const Var, layer.cosets.len);
        for (cosets, layer.cosets) |*coset_wires, coset| coset_wires.* = try guessValues(V, ctx, coset);
        wire.* = .{ .commitment = commitment, .cosets = cosets, .auth_paths = try guessPaths(V, ctx, layer.auth_paths) };
    }
    const last_layer = try guessValues(V, ctx, proof.fri.last_layer_coefs);

    return .{
        .commitments = commitments,
        .sampled_values = sampled,
        .queried_values = queried,
        .auth_paths = paths,
        .pow_nonce = nonce,
        .fri = .{ .layers = layers, .last_layer_coefs = last_layer },
    };
}

fn guessValues(comptime V: type, ctx: *Context(V), values: []const V) Error![]Var {
    const wires = try ctx.scratch().alloc(Var, values.len);
    for (wires, values) |*wire, value| wire.* = try ctx.guess(value);
    return wires;
}

fn guessPaths(comptime V: type, ctx: *Context(V), paths: []const []const HashValue(V)) Error![]const []const HashValue(Var) {
    const scratch = ctx.scratch();
    const out = try scratch.alloc([]const HashValue(Var), paths.len);
    for (out, paths) |*path_wires, path| {
        const nodes = try scratch.alloc(HashValue(Var), path.len);
        for (nodes, path) |*node, sibling| node.* = try blake.guessHash(V, ctx, sibling);
        path_wires.* = nodes;
    }
    return out;
}

/// Converts a natively verified proof and its capture into the fixed-width
/// value proof. `allocator` should be an arena: the result is one nested
/// allocation set with no `deinit`.
pub fn fromNative(
    allocator: std.mem.Allocator,
    comptime H: type,
    proof: *const core.proof.StarkProof(H),
    capture: *const core.pcs.verifier.VerifiedProofCapture(H),
    shape: *const shape_mod.Shape,
) ConvertError!Proof(QM31) {
    const pcs_proof = &proof.commitment_scheme_proof;
    const n_trees = shape.nTrees();
    const n_queries = capture.queries.raw.len;
    if (n_queries != shape.nQueries()) return error.ShapeMismatch;
    if (pcs_proof.commitments.items.len != n_trees or pcs_proof.sampled_values.items.len != n_trees) return error.ShapeMismatch;
    if (capture.column_log_sizes.len != n_trees or capture.trace_paths.len != n_trees) return error.ShapeMismatch;

    const commitments = try allocator.alloc(HashValue(QM31), n_trees);
    for (commitments, pcs_proof.commitments.items) |*out, root| out.* = blake.hashValueFromDigest(QM31, root);

    const sampled = try allocator.alloc([]const []const QM31, n_trees);
    for (sampled, pcs_proof.sampled_values.items, 0..) |*tree_out, tree, t| {
        if (tree.len != shape.nColumns(t)) return error.ShapeMismatch;
        const columns = try allocator.alloc([]const QM31, tree.len);
        for (columns, tree, 0..) |*column_out, column, c| {
            if (column.len != shape.sampleCount(t, c)) return error.ShapeMismatch;
            column_out.* = try allocator.dupe(QM31, column);
        }
        tree_out.* = columns;
    }

    const queried = try allocator.alloc([]const []const M31Wrapper(QM31), n_trees);
    const paths = try allocator.alloc([]const []const HashValue(QM31), n_trees);
    var flat: usize = 0;
    for (0..n_trees) |t| {
        const n_columns = shape.nColumns(t);
        if (capture.column_log_sizes[t].len != n_columns) return error.ShapeMismatch;
        const columns = try allocator.alloc([]const M31Wrapper(QM31), n_columns);
        for (columns, 0..) |*column_out, c| {
            if (capture.column_log_sizes[t][c] != shape.extendedLogSize(t, c)) return error.ShapeMismatch;
            if (flat + n_queries > capture.queried_values.len) return error.ShapeMismatch;
            const values = try allocator.alloc(M31Wrapper(QM31), n_queries);
            for (values, capture.queried_values[flat..][0..n_queries]) |*out, value| out.* = wrappers.m31Value(QM31, value);
            flat += n_queries;
            column_out.* = values;
        }
        queried[t] = columns;
        if (n_columns == 0) {
            paths[t] = &.{};
            continue;
        }
        const trace_paths = &capture.trace_paths[t];
        if (trace_paths.positions.len != n_queries or trace_paths.path_depth != shape.treeHeight(t)) return error.ShapeMismatch;
        paths[t] = try convertPaths(allocator, H, n_queries, trace_paths.path_depth, trace_paths.siblings);
    }
    if (flat != capture.queried_values.len) return error.ShapeMismatch;

    const layers = try allocator.alloc(fri.Layer(QM31), capture.fri.layers.len);
    for (layers, capture.fri.layers) |*out, layer| {
        if (layer.query_count != n_queries or layer.values.len != n_queries * layer.fold_width) return error.ShapeMismatch;
        const cosets = try allocator.alloc([]const QM31, n_queries);
        for (cosets, 0..) |*coset, q| coset.* = try allocator.dupe(QM31, layer.queryValues(q));
        out.* = .{
            .commitment = blake.hashValueFromDigest(QM31, layer.commitment),
            .cosets = cosets,
            .auth_paths = try convertPaths(allocator, H, n_queries, layer.path_depth, layer.siblings),
        };
    }

    const result: Proof(QM31) = .{
        .commitments = commitments,
        .sampled_values = sampled,
        .queried_values = queried,
        .auth_paths = paths,
        .pow_nonce = .{
            wrappers.u32Value(QM31, @truncate(capture.proof_of_work)),
            wrappers.u32Value(QM31, @truncate(capture.proof_of_work >> 32)),
        },
        .fri = .{ .layers = layers, .last_layer_coefs = try allocator.dupe(QM31, capture.last_layer_coefficients) },
    };
    try result.validateStructure(shape);
    return result;
}

fn convertPaths(allocator: std.mem.Allocator, comptime H: type, n_queries: usize, depth: u32, siblings: []const H.Hash) ConvertError![]const []const HashValue(QM31) {
    const path_depth: usize = @intCast(depth);
    if (siblings.len != n_queries * path_depth) return error.ShapeMismatch;
    const out = try allocator.alloc([]const HashValue(QM31), n_queries);
    for (out, 0..) |*path, q| {
        const nodes = try allocator.alloc(HashValue(QM31), path_depth);
        for (nodes, siblings[q * path_depth ..][0..path_depth]) |*node, sibling| node.* = blake.hashValueFromDigest(QM31, sibling);
        path.* = nodes;
    }
    return out;
}

/// The topology-mode proof of `shape`: placeholders in every slot
/// (allocate from an arena).
pub fn emptyProof(allocator: std.mem.Allocator, shape: *const shape_mod.Shape) std.mem.Allocator.Error!Proof(builder.NoValue) {
    const NoValue = builder.NoValue;
    const n_trees = shape.nTrees();
    const n_queries = shape.nQueries();
    const placeholder_hash = blake.hashValue(NoValue, @splat(0));
    const commitments = try allocator.alloc(HashValue(NoValue), n_trees);
    @memset(commitments, placeholder_hash);
    const sampled = try allocator.alloc([]const []const NoValue, n_trees);
    const queried = try allocator.alloc([]const []const M31Wrapper(NoValue), n_trees);
    const paths = try allocator.alloc([]const []const HashValue(NoValue), n_trees);
    for (0..n_trees) |tree| {
        const n_columns = shape.nColumns(tree);
        const samples = try allocator.alloc([]const NoValue, n_columns);
        const values = try allocator.alloc([]const M31Wrapper(NoValue), n_columns);
        for (samples, values, 0..) |*column_samples, *column_values, column| {
            column_samples.* = try allocator.alloc(NoValue, shape.sampleCount(tree, column));
            const wires = try allocator.alloc(M31Wrapper(NoValue), n_queries);
            @memset(wires, .newUnsafe(.{}));
            column_values.* = wires;
        }
        sampled[tree] = samples;
        queried[tree] = values;
        paths[tree] = if (n_columns == 0) &.{} else try emptyPaths(allocator, n_queries, shape.treeHeight(tree));
    }
    var steps_buffer: [64]u32 = undefined;
    const steps = shape.foldSteps(&steps_buffer);
    const layers = try allocator.alloc(fri.Layer(NoValue), steps.len);
    var log_size = shape.liftingLogSize();
    for (layers, steps) |*layer, step| {
        const cosets = try allocator.alloc([]const NoValue, n_queries);
        for (cosets) |*coset| coset.* = try allocator.alloc(NoValue, @as(usize, 1) << @intCast(step));
        log_size -= step;
        layer.* = .{ .commitment = placeholder_hash, .cosets = cosets, .auth_paths = try emptyPaths(allocator, n_queries, log_size) };
    }
    return .{
        .commitments = commitments,
        .sampled_values = sampled,
        .queried_values = queried,
        .auth_paths = paths,
        .pow_nonce = .{ .newUnsafe(.{}), .newUnsafe(.{}) },
        .fri = .{ .layers = layers, .last_layer_coefs = try allocator.alloc(NoValue, shape.nLastLayerCoefficients()) },
    };
}

fn emptyPaths(allocator: std.mem.Allocator, n_queries: usize, depth: u32) std.mem.Allocator.Error![]const []const HashValue(builder.NoValue) {
    const out = try allocator.alloc([]const HashValue(builder.NoValue), n_queries);
    for (out) |*path| {
        const nodes = try allocator.alloc(HashValue(builder.NoValue), depth);
        @memset(nodes, blake.hashValue(builder.NoValue, @splat(0)));
        path.* = nodes;
    }
    return out;
}

/// `sampled_values` flattened in the order `mixFelts` absorbs them: tree,
/// column, sample (scratch-owned).
pub fn flattenSampledValues(allocator: std.mem.Allocator, sampled_values: []const []const []const Var) std.mem.Allocator.Error![]Var {
    var total: usize = 0;
    for (sampled_values) |tree| for (tree) |column| {
        total += column.len;
    };
    const out = try allocator.alloc(Var, total);
    var at: usize = 0;
    for (sampled_values) |tree| for (tree) |column| {
        @memcpy(out[at..][0..column.len], column);
        at += column.len;
    };
    return out;
}

test "proof: guess order and counts of a tiny shape" {
    const NoValue = builder.NoValue;
    var ctx = try Context(NoValue).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const root = blake.hashValue(NoValue, @splat(0));
    const sample = [_]NoValue{.{}};
    const query_values = [_]M31Wrapper(NoValue){ .newUnsafe(.{}), .newUnsafe(.{}) };
    const path = [_]HashValue(NoValue){root} ** 3;
    const paths = [_][]const HashValue(NoValue){ &path, &path };
    const coset = [_]NoValue{ .{}, .{} };
    const fri_path = [_]HashValue(NoValue){root} ** 2;
    const value_proof: Proof(NoValue) = .{
        .commitments = &.{ root, root },
        .sampled_values = &.{ &.{&sample}, &.{&sample} },
        .queried_values = &.{ &.{&query_values}, &.{&query_values} },
        .auth_paths = &.{ &paths, &paths },
        .pow_nonce = .{ .newUnsafe(.{}), .newUnsafe(.{}) },
        .fri = .{
            .layers = &.{.{ .commitment = root, .cosets = &.{ &coset, &coset }, .auth_paths = &.{ &fri_path, &fri_path } }},
            .last_layer_coefs = &.{.{}},
        },
    };
    const wires = try guess(NoValue, &ctx, &value_proof);
    // 2 roots (16 u32 = 32 u16 guesses), 2 samples, 4 M31, 12 path nodes (192),
    // the nonce (4), one FRI root (16), 4 coset values, 4 path nodes (64), 1 coefficient.
    try std.testing.expectEqual(@as(usize, 32 + 2 + 4 + 192 + 4 + 16 + 4 + 64 + 1), ctx.stats.guess);
    try std.testing.expectEqual(@as(usize, 2), wires.fri.layers[0].cosets[1].len);
}
