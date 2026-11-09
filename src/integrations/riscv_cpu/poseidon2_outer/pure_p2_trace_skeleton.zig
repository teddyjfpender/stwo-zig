//! Shape-only guessed wires for immutable trace construction. Zero values are
//! advice placeholders, never a proof or an accepted native transcript.
const std = @import("std");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const O = V.common.O;
const M = @import("stwo_core").fields.m31.M31;
const Hash = @import("pure_p2_worker_protocol.zig").W.H.Hash;
fn zeros(comptime T: type, a: std.mem.Allocator, n: usize, value: T) ![]T {
    const out = try a.alloc(T, n);
    @memset(out, value);
    return out;
}
pub fn init(a: std.mem.Allocator, shape: *const V.Shape) !V.Captured {
    try shape.validate();
    const sampled = try a.alloc([]const []const O, shape.nTrees());
    const queried = try a.alloc([]const []const M, shape.nTrees());
    const paths = try a.alloc([]const []const Hash, shape.nTrees());
    for (0..shape.nTrees()) |t| {
        const samples = try a.alloc([]const O, shape.nColumns(t));
        const queries = try a.alloc([]const M, shape.nColumns(t));
        for (samples, queries, 0..) |*s, *q, c| {
            s.* = try zeros(O, a, shape.sampleCount(t, c), O.zero());
            q.* = try zeros(M, a, shape.nQueries(), M.zero());
        }
        sampled[t] = samples;
        queried[t] = queries;
        const treepaths = try a.alloc([]const Hash, if (shape.nColumns(t) == 0) 0 else shape.nQueries());
        for (treepaths) |*path| path.* = try zeros(Hash, a, shape.treeHeight(t), @splat(0));
        paths[t] = treepaths;
    }
    var buffer: [64]u32 = undefined;
    const steps = shape.foldSteps(&buffer);
    const layers = try a.alloc(V.proof.CapturedLayer, steps.len);
    var log = shape.liftingLogSize();
    for (layers, steps) |*layer, step| {
        log -= step;
        const cosets = try a.alloc([]const O, shape.nQueries());
        const auth = try a.alloc([]const Hash, shape.nQueries());
        for (cosets, auth) |*coset, *path| {
            coset.* = try zeros(O, a, @as(usize, 1) << @intCast(step), O.zero());
            path.* = try zeros(Hash, a, log, @splat(0));
        }
        layer.* = .{ .commitment = @splat(0), .cosets = cosets, .auth_paths = auth };
    }
    return .{ .commitments = try zeros(Hash, a, shape.nTrees(), @splat(0)), .sampled_values = sampled, .queried_values = queried, .auth_paths = paths, .pow_nonce = 0, .layers = layers, .last_layer_coefs = try zeros(O, a, shape.nLastLayerCoefficients(), O.zero()) };
}
