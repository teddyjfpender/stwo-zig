//! Full-STARK PCS arithmetic from verifier-owned component geometry.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const deep = @import("pcs_deep_circuit.zig");
const fri = @import("fri_verifier_circuit.zig");
const adapter = @import("../pcs_arithmetic_capture.zig");
const layout = @import("../sample_point_layout.zig");
const Capture = f.core.verifier.ProofCapture(f.Hasher);
pub const Prepared = struct {
    deep_graph: deep.Circuit,
    deep_evaluation: deep.Evaluation,
    fri_graph: fri.Circuit,
    fri_evaluation: fri.Evaluation,
    pub fn deinit(self: *Prepared) void {
        self.fri_evaluation.deinit();
        self.fri_graph.deinit();
        self.deep_evaluation.deinit();
        self.deep_graph.deinit();
    }
};
pub fn prepare(a: std.mem.Allocator, capture: *const Capture, native: f.core.air.components.Components, config: f.core.pcs.PcsConfig) !Prepared {
    const fc = config.fri_config;
    const split = try native.compositionLogSplit();
    const mask_log = f.core.verifier_types.compositionMaskLogSize(native.compositionLogDegreeBound(), split) orelse return error.InvalidStarkPcsGeometry;
    const lifting = mask_log + fc.log_blowup_factor;
    var column_logs = try native.columnLogSizes(a);
    defer column_logs.deinitDeep(a);
    const composition_columns = f.core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidStarkPcsGeometry;
    var trees: [4]deep.TreeProfile = undefined;
    try std.testing.expectEqual(@as(usize, 3), column_logs.items.len);
    for (&trees, 0..) |*tree, i| {
        const count = if (i < 3) column_logs.items[i].len else composition_columns;
        const logs = try a.alloc(u32, count);
        for (logs, 0..) |*value, j| value.* = (if (i < 3) column_logs.items[i][j] else mask_log) + fc.log_blowup_factor;
        tree.* = .{ .column_log_sizes = logs };
    }
    const current = try f.core.circle.secureFieldPointFromRandomSeedChecked(capture.oods_seed);
    const step = f.core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
    const previous = current.sub(.{ .x = f.QM31.fromBase(step.x), .y = f.QM31.fromBase(step.y) });
    var masks = try native.maskPoints(a, current, mask_log, false);
    defer masks.deinitDeep(a);
    var layouts: std.ArrayList(deep.SamplePointLayout) = .empty;
    for (masks.items) |tree| for (tree) |points| try layouts.append(a, try layout.classifyColumn(points, current, previous));
    try layouts.appendNTimes(a, .current, composition_columns);
    const profile = deep.Profile{ .trees = &trees, .sample_layouts = layouts.items, .lifting_log_size = lifting, .log_blowup_factor = fc.log_blowup_factor, .query_count = @intCast(fc.n_queries) };
    var input = try adapter.Owned.init(a, profile, capture);
    defer input.deinit();
    // Neither sample order nor values are inferred from the proof's dimensions.
    const saved_layout = layouts.items[0];
    layouts.items[0] = .none;
    try std.testing.expectError(error.InvalidPcsArithmeticCapture, adapter.Owned.init(a, profile, capture));
    layouts.items[0] = saved_layout;
    var deep_graph = try deep.build(a, profile);
    errdefer deep_graph.deinit();
    var deep_evaluation = try deep_graph.evaluate(a, input.inputs);
    errdefer deep_evaluation.deinit();
    const changed = try a.dupe(f.QM31, input.inputs.sampled_values);
    changed[0] = changed[0].add(f.QM31.one());
    var wrong = input.inputs;
    wrong.sampled_values = changed;
    try std.testing.expectError(error.UnsatisfiedCircuit, deep_graph.evaluate(a, wrong));
    var widths: std.ArrayList(u32) = .empty;
    var remaining = lifting;
    const terminal = fc.log_blowup_factor + fc.log_last_layer_degree_bound;
    while (remaining > terminal) {
        const fold = @min(fc.fold_step, remaining - terminal);
        if (fold == 0) return error.InvalidStarkPcsGeometry;
        try widths.append(a, @as(u32, 1) << @intCast(fold));
        remaining -= fold;
    }
    const fri_profile = fri.Profile{ .lifting_log_size = lifting, .log_blowup_factor = fc.log_blowup_factor, .log_last_layer_degree_bound = fc.log_last_layer_degree_bound, .fold_widths = widths.items, .query_count = @intCast(fc.n_queries) };
    var fri_input = try @import("../fri_arithmetic_capture.zig").Owned.init(a, fri_profile, capture);
    defer fri_input.deinit();
    var fri_graph = try fri.build(a, fri_profile);
    errdefer fri_graph.deinit();
    var fri_evaluation = try fri_graph.evaluate(a, fri_input.inputs);
    errdefer fri_evaluation.deinit();
    return .{ .deep_graph = deep_graph, .deep_evaluation = deep_evaluation, .fri_graph = fri_graph, .fri_evaluation = fri_evaluation };
}
