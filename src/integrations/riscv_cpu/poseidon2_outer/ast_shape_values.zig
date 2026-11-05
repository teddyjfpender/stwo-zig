//! Zero ASSIGNMENT PLACEHOLDERS from receiver/source geometry, for AST census
//! only. This is not a native proof/capture and must never verify numerically.
const std = @import("std");
const Core = @import("stwo_core");
const V = @import("../rv64_recursion/om31_poseidon/mod.zig");
const O = Core.fields.om31.OM31;
const M = Core.fields.m31.M31;
const H = Core.vcs_lifted.poseidon2_profile.Om31V2.MerkleHasher.Hash;
fn paths(a: std.mem.Allocator, n: usize, depth: usize) ![]const []const H {
    const out = try a.alloc([]const H, n);
    for (out) |*p| {
        const values = try a.alloc(H, depth);
        @memset(values, @splat(0));
        p.* = values;
    }
    return out;
}
pub fn fromSourceShape(a: std.mem.Allocator, shape: *const V.Shape) !V.Captured {
    try shape.validate();
    const nt = shape.nTrees();
    const nq = shape.nQueries();
    const roots = try a.alloc(H, nt);
    @memset(roots, @splat(0));
    const sampled = try a.alloc([]const []const O, nt);
    const queried = try a.alloc([]const []const M, nt);
    const auth = try a.alloc([]const []const H, nt);
    for (0..nt) |t| {
        const nc = shape.nColumns(t);
        const samples = try a.alloc([]const O, nc);
        const values = try a.alloc([]const M, nc);
        for (samples, values, 0..) |*s, *v, c| {
            const sc = try a.alloc(O, shape.sampleCount(t, c));
            @memset(sc, O.zero());
            s.* = sc;
            const q = try a.alloc(M, nq);
            @memset(q, M.zero());
            v.* = q;
        }
        sampled[t] = samples;
        queried[t] = values;
        auth[t] = try paths(a, if (nc == 0) 0 else nq, shape.treeHeight(t));
    }
    var buffer: [64]u32 = undefined;
    const steps = shape.foldSteps(&buffer);
    const layers = try a.alloc(V.proof.CapturedLayer, steps.len);
    var log = shape.liftingLogSize();
    for (layers, steps) |*layer, step| {
        log -= step;
        const cosets = try a.alloc([]const O, nq);
        for (cosets) |*c| {
            const values = try a.alloc(O, @as(usize, 1) << @intCast(step));
            @memset(values, O.zero());
            c.* = values;
        }
        layer.* = .{ .commitment = @splat(0), .cosets = cosets, .auth_paths = try paths(a, nq, log) };
    }
    const last = try a.alloc(O, shape.nLastLayerCoefficients());
    @memset(last, O.zero());
    return .{ .commitments = roots, .sampled_values = sampled, .queried_values = queried, .auth_paths = auth, .pow_nonce = 0, .layers = layers, .last_layer_coefs = last };
}
