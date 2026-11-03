//! Native verified-capture conversion and fixed-shape guessed OM31 proof wires.
//! Capture conversion is not acceptance. Callers own an arena for nested views.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const Shape = @import("shape.zig").Shape;
const F = C.F;
const O = C.O;
const Q = C.Q;
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const B = circuit.builder;
const Word = B.wrappers.U32Wrapper(C.Var);
const Base = B.wrappers.M31Wrapper(C.Var);
pub const NativeProof = core.proof.ForField(O).StarkProof(H);
pub const NativeCapture = core.pcs.ForField(O).verifier.VerifiedProofCapture(H);
pub const CapturedLayer = struct { commitment: H.Hash, cosets: []const []const O, auth_paths: []const []const H.Hash };
pub const Captured = struct {
    commitments: []const H.Hash,
    sampled_values: []const []const []const O,
    queried_values: []const []const []const M,
    auth_paths: []const []const []const H.Hash,
    pow_nonce: u64,
    layers: []const CapturedLayer,
    last_layer_coefs: []const O,
};
pub const Layer = struct { commitment: C.Hash, cosets: []const []const F, auth_paths: []const []const C.Hash };
pub const Proof = struct {
    commitments: []const C.Hash,
    sampled_values: []const []const []const F,
    queried_values: []const []const []const Base,
    auth_paths: []const []const []const C.Hash,
    pow_nonce: [2]Word,
    layers: []const Layer,
    last_layer_coefs: []const F,
    pub fn validate(self: *const Proof, shape: *const Shape) !void {
        try validateProof(self.*, shape);
    }
};
fn validateProof(proof: anytype, shape: *const Shape) !void {
    try shape.validate();
    if (proof.commitments.len != shape.nTrees() or proof.sampled_values.len != shape.nTrees() or
        proof.queried_values.len != shape.nTrees() or proof.auth_paths.len != shape.nTrees()) return error.ShapeMismatch;
    for (0..shape.nTrees()) |t| {
        if (proof.sampled_values[t].len != shape.nColumns(t) or proof.queried_values[t].len != shape.nColumns(t)) return error.ShapeMismatch;
        for (proof.sampled_values[t], proof.queried_values[t], 0..) |samples, queried, col| {
            if (samples.len != shape.sampleCount(t, col) or queried.len != shape.nQueries()) return error.ShapeMismatch;
        }
        if (shape.nColumns(t) == 0) {
            if (proof.auth_paths[t].len != 0) return error.ShapeMismatch;
        } else {
            if (proof.auth_paths[t].len != shape.nQueries()) return error.ShapeMismatch;
            for (proof.auth_paths[t]) |path| if (path.len != shape.treeHeight(t)) return error.ShapeMismatch;
        }
    }
    var buffer: [64]u32 = undefined;
    const steps = shape.foldSteps(&buffer);
    if (proof.layers.len != steps.len or proof.last_layer_coefs.len != shape.nLastLayerCoefficients()) return error.ShapeMismatch;
    var log = shape.liftingLogSize();
    for (proof.layers, steps) |layer, step| {
        if (layer.cosets.len != shape.nQueries() or layer.auth_paths.len != shape.nQueries()) return error.ShapeMismatch;
        log -= step;
        for (layer.cosets, layer.auth_paths) |coset, path| {
            if (coset.len != @as(usize, 1) << @intCast(step) or path.len != log) return error.ShapeMismatch;
        }
    }
}
fn paths(a: std.mem.Allocator, queries: usize, depth: usize, siblings: []const H.Hash) ![]const []const H.Hash {
    if (siblings.len != queries * depth) return error.ShapeMismatch;
    const result = try a.alloc([]const H.Hash, queries);
    for (result, 0..) |*path, q| path.* = try a.dupe(H.Hash, siblings[q * depth ..][0..depth]);
    return result;
}
pub fn fromNative(a: std.mem.Allocator, native: *const NativeProof, capture: *const NativeCapture, shape: *const Shape) !Captured {
    try shape.validate();
    const pcs = &native.commitment_scheme_proof;
    const nt = shape.nTrees();
    const nq = shape.nQueries();
    if (capture.queries.raw.len != nq or pcs.commitments.items.len != nt or pcs.sampled_values.items.len != nt or
        capture.column_log_sizes.len != nt or capture.trace_paths.len != nt) return error.ShapeMismatch;
    const sampled = try a.alloc([]const []const O, nt);
    const queried = try a.alloc([]const []const M, nt);
    const auth = try a.alloc([]const []const H.Hash, nt);
    var flat: usize = 0;
    for (0..nt) |t| {
        const nc = shape.nColumns(t);
        if (pcs.sampled_values.items[t].len != nc or capture.column_log_sizes[t].len != nc) return error.ShapeMismatch;
        const columns = try a.alloc([]const O, nc);
        const values = try a.alloc([]const M, nc);
        for (columns, values, 0..) |*samples, *base_values, col| {
            if (capture.column_log_sizes[t][col] != shape.extendedLogSize(t, col) or flat + nq > capture.queried_values.len) return error.ShapeMismatch;
            samples.* = try a.dupe(O, pcs.sampled_values.items[t][col]);
            base_values.* = try a.dupe(M, capture.queried_values[flat..][0..nq]);
            flat += nq;
        }
        sampled[t] = columns;
        queried[t] = values;
        if (nc == 0) {
            auth[t] = &.{};
            continue;
        }
        const trace = capture.trace_paths[t];
        if (trace.positions.len != nq or trace.path_depth != shape.treeHeight(t)) return error.ShapeMismatch;
        auth[t] = try paths(a, nq, trace.path_depth, trace.siblings);
    }
    if (flat != capture.queried_values.len) return error.ShapeMismatch;
    const layers = try a.alloc(CapturedLayer, capture.fri.layers.len);
    for (layers, capture.fri.layers) |*out, in| {
        if (in.query_count != nq or in.values.len != nq * in.fold_width) return error.ShapeMismatch;
        const cosets = try a.alloc([]const O, nq);
        for (cosets, 0..) |*coset, q| coset.* = try a.dupe(O, in.queryValues(q));
        out.* = .{ .commitment = in.commitment, .cosets = cosets, .auth_paths = try paths(a, nq, in.path_depth, in.siblings) };
    }
    const result: Captured = .{ .commitments = try a.dupe(H.Hash, pcs.commitments.items), .sampled_values = sampled, .queried_values = queried, .auth_paths = auth, .pow_nonce = capture.proof_of_work, .layers = layers, .last_layer_coefs = try a.dupe(O, capture.last_layer_coefficients) };
    try validateProof(result, shape);
    return result;
}
fn guessHash(ctx: *C.Context, value: H.Hash) !C.Hash {
    return B.blake.guessHash(Q, ctx, B.blake.hashValueFromDigest(Q, value));
}
fn guessPaths(ctx: *C.Context, source: []const []const H.Hash) ![]const []const C.Hash {
    const output = try ctx.scratch().alloc([]const C.Hash, source.len);
    for (output, source) |*out, in| {
        const nodes = try ctx.scratch().alloc(C.Hash, in.len);
        for (nodes, in) |*node, value| node.* = try guessHash(ctx, value);
        out.* = nodes;
    }
    return output;
}
fn guessValues(ctx: *C.Context, values: []const O) ![]const F {
    const result = try ctx.scratch().alloc(F, values.len);
    for (result, values) |*wire, value| wire.* = try F.guess(ctx, value);
    return result;
}
pub fn guess(ctx: *C.Context, source: *const Captured, shape: *const Shape) !Proof {
    try validateProof(source.*, shape);
    const a = ctx.scratch();
    const roots = try a.alloc(C.Hash, source.commitments.len);
    for (roots, source.commitments) |*root, value| root.* = try guessHash(ctx, value);
    const sampled = try a.alloc([]const []const F, shape.nTrees());
    const queried = try a.alloc([]const []const Base, shape.nTrees());
    const auth = try a.alloc([]const []const C.Hash, shape.nTrees());
    for (0..shape.nTrees()) |t| {
        const columns = try a.alloc([]const F, shape.nColumns(t));
        const base_columns = try a.alloc([]const Base, shape.nColumns(t));
        for (columns, base_columns, source.sampled_values[t], source.queried_values[t]) |*samples, *base_values, src, bases| {
            samples.* = try guessValues(ctx, src);
            const b = try a.alloc(Base, bases.len);
            for (b, bases) |*wire, value| wire.* = try B.wrappers.guessM31(Q, ctx, B.wrappers.m31Value(Q, value));
            base_values.* = b;
        }
        sampled[t] = columns;
        queried[t] = base_columns;
        auth[t] = try guessPaths(ctx, source.auth_paths[t]);
    }
    const layers = try a.alloc(Layer, source.layers.len);
    for (layers, source.layers) |*out, in| {
        const cosets = try a.alloc([]const F, in.cosets.len);
        for (cosets, in.cosets) |*c, values| c.* = try guessValues(ctx, values);
        out.* = .{ .commitment = try guessHash(ctx, in.commitment), .cosets = cosets, .auth_paths = try guessPaths(ctx, in.auth_paths) };
    }
    return .{ .commitments = roots, .sampled_values = sampled, .queried_values = queried, .auth_paths = auth, .pow_nonce = .{ try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, @truncate(source.pow_nonce))), try B.wrappers.guessU32(Q, ctx, B.wrappers.u32Value(Q, @truncate(source.pow_nonce >> 32))) }, .layers = layers, .last_layer_coefs = try guessValues(ctx, source.last_layer_coefs) };
}
