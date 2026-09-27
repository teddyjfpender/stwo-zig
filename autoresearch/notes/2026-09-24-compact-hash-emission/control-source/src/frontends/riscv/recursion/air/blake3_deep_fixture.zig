//! Explicit standalone PCS fixture geometry, not production capture admission.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
pub const deep = @import("pcs_deep_circuit.zig");
const Capture = f.core.pcs.verifier.VerifiedProofCapture(f.Hasher);
pub const Prepared = struct {
    graph: deep.Circuit,
    evaluation: deep.Evaluation,
    exports: [34]@import("verifier_arithmetic_lowering.zig").Export,
    queried_nodes: [2][17]u32,
    pub fn deinit(self: *Prepared) void {
        self.evaluation.deinit();
        self.graph.deinit();
    }
};
pub fn prepare(a: std.mem.Allocator, capture: *const Capture) !Prepared {
    try std.testing.expectEqual(@as(usize, 1), capture.column_log_sizes.len);
    try std.testing.expectEqualSlices(u32, &.{ 6, 4 }, capture.column_log_sizes[0]);
    try std.testing.expectEqual(@as(usize, 17), capture.queries.raw.len);
    const point = try f.core.circle.secureFieldPointFromRandomSeedChecked(capture.oods_seed);
    try std.testing.expectEqual(@as(usize, 1), capture.sampled_points.len);
    try std.testing.expectEqual(@as(usize, 2), capture.sampled_points[0].len);
    for (capture.sampled_points[0]) |points| {
        try std.testing.expectEqual(@as(usize, 1), points.len);
        try std.testing.expect(points[0].eql(point));
    }
    var graph = try deep.build(a, .{ .trees = &.{.{ .column_log_sizes = &.{ 6, 4 } }}, .sample_layouts = &.{ .current, .current }, .lifting_log_size = 6, .log_blowup_factor = 1, .query_count = 17 });
    errdefer graph.deinit();
    const raw = try a.alloc(f.M31, capture.queries.raw.len);
    defer a.free(raw);
    for (capture.queries.raw, raw) |position, *value| {
        if (position >= 64) return error.InvalidFixtureQuery;
        value.* = f.M31.fromCanonical(@intCast(position));
    }
    const witness = deep.Witness{ .active = true, .sampled_values = capture.sampled_values, .queried_values = capture.queried_values, .oods_seed = capture.oods_seed, .deep_randomness = capture.deep_randomness, .raw_queries = raw, .answers = capture.deep_answers };
    var evaluation = try graph.evaluate(a, witness);
    errdefer evaluation.deinit();
    const samples = try a.dupe(f.QM31, capture.sampled_values);
    defer a.free(samples);
    samples[0] = samples[0].add(f.QM31.one());
    var wrong = witness;
    wrong.sampled_values = samples;
    try std.testing.expectError(error.UnsatisfiedCircuit, graph.evaluate(a, wrong));
    var exports: [34]@import("verifier_arithmetic_lowering.zig").Export = undefined;
    var queried_nodes: [2][17]u32 = @splat(@splat(std.math.maxInt(u32)));
    var cursor: usize = 0;
    for (graph.bindings) |binding| switch (binding.source) {
        .queried_value => |source| {
            if (source.tree != 0 or source.column >= 2 or source.query >= 17 or cursor >= exports.len) return error.InvalidTraceMapping;
            if (queried_nodes[source.column][source.query] != std.math.maxInt(u32)) return error.InvalidTraceMapping;
            queried_nodes[source.column][source.query] = binding.node_id;
            exports[cursor] = .{ .node_id = binding.node_id, .uses = 1 };
            cursor += 1;
        },
        else => {},
    };
    try std.testing.expectEqual(exports.len, cursor);
    return .{ .graph = graph, .evaluation = evaluation, .exports = exports, .queried_nodes = queried_nodes };
}
