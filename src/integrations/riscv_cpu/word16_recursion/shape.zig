//! Diagnostic metadata from real native component vtables. No circuit is built.
const std = @import("std");
const core = @import("stwo_core");
const NV = @import("stwo_circuit_frontend").native_verifier;
const Q = core.fields.qm31.QM31;
const Component = core.air.components.Component;
pub const Report = struct {
    component_constraints: []usize,
    global_log: u32,
    composition_split: u32,
    lifting_log: u32,
    fri_degree_log: u32,
    tree_logs: [][]u32,
    mask_offsets: [][][]i32,
    tree_heights: []u32,
    sampled_qm31: usize,
    deep_sample_entries: usize,
    deep_batches: []Batch,
    fold_steps: []u32,
    last_layer_coefficients: usize,
};
pub const Batch = struct { shift: usize, entries: usize };
pub fn describe(a: std.mem.Allocator, handles: []const Component, config: core.pcs.PcsConfig, proof: anytype) !Report {
    if (handles.len == 0 or handles.len > 64) return error.DiagnosticComponentLimit;
    const cc = core.air.components.Components{ .components = handles, .n_preprocessed_columns = proof.commitment_scheme_proof.sampled_values.items[0].len };
    const split = try cc.compositionLogSplit();
    const global = core.verifier_types.compositionMaskLogSize(cc.compositionLogDegreeBound(), split) orelse return error.InvalidDiagnosticGeometry;
    var logs = try cc.columnLogSizes(a);
    defer logs.deinitDeep(a);
    const probe = core.circle.secureFieldPointFromRandomSeed(Q.fromU32Unchecked(7, 11, 13, 17));
    var points = try cc.maskPoints(a, probe, global, false);
    defer points.deinitDeep(a);
    if (logs.items.len != 3 or points.items.len != 3) return error.InvalidDiagnosticTrees;
    const column_cap = 65536;
    var columns: usize = 0;
    for (logs.items) |tree| columns = try std.math.add(usize, columns, tree.len);
    if (columns > column_cap) return error.DiagnosticColumnLimit;
    const tree_logs = try a.alloc([]u32, 4);
    const offsets = try a.alloc([][]i32, 4);
    const step = core.poly.circle.canonic.CanonicCoset.new(global).coset().step;
    const lifted = core.circle.CirclePointQM31{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) };
    var candidates: [129]core.circle.CirclePointQM31 = undefined;
    for (&candidates, 0..) |*c, j| c.* = probe.add(lifted.mulSigned(@as(isize, @intCast(j)) - 64));
    var samples: usize = 0;
    for (logs.items, points.items, 0..) |tree, masks, t| {
        tree_logs[t] = try a.dupe(u32, tree);
        offsets[t] = try a.alloc([]i32, masks.len);
        for (masks, offsets[t]) |mask, *out| {
            if (mask.len > 8) return error.DiagnosticMaskLimit;
            out.* = try a.alloc(i32, mask.len);
            samples += mask.len;
            for (mask, out.*) |point, *offset| {
                offset.* = for (candidates, 0..) |candidate, j| {
                    if (point.eql(candidate)) break @as(i32, @intCast(j)) - 64;
                } else return error.UnknownDiagnosticMaskOffset;
            }
        }
    }
    const count = core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidDiagnosticGeometry;
    tree_logs[3] = try a.alloc(u32, count);
    @memset(tree_logs[3], global);
    offsets[3] = try a.alloc([]i32, count);
    for (offsets[3]) |*out| out.* = try a.dupe(i32, &.{0});
    samples += count;
    const shape = NV.Shape{ .tree_column_log_sizes = tree_logs, .mask_offsets = offsets, .global_log = global, .composition_log_split = split, .pcs = config };
    try shape.validate();
    const sampled = proof.commitment_scheme_proof.sampled_values.items;
    if (sampled.len != 4) return error.InvalidDiagnosticSamples;
    for (sampled, offsets) |tree, masks| {
        if (tree.len != masks.len) return error.InvalidDiagnosticSamples;
        for (tree, masks) |column, mask| if (column.len != mask.len) return error.InvalidDiagnosticSamples;
    }
    const plan = try NV.shape.SamplePlan.init(a, &shape);
    const batches = try a.alloc(Batch, plan.batches.len);
    for (batches, plan.batches) |*out, b| out.* = .{ .shift = b.shift.v, .entries = b.entries.len };
    const heights = try a.alloc(u32, 4);
    for (heights, 0..) |*h, t| h.* = shape.treeHeight(t);
    var buffer: [32]u32 = undefined;
    const constraints = try a.alloc(usize, handles.len);
    for (constraints, handles) |*n, h| n.* = h.nConstraints();
    return .{ .component_constraints = constraints, .global_log = global, .composition_split = split, .lifting_log = shape.liftingLogSize(), .fri_degree_log = shape.logDegreeBound(), .tree_logs = tree_logs, .mask_offsets = offsets, .tree_heights = heights, .sampled_qm31 = samples, .deep_sample_entries = plan.n_samples, .deep_batches = batches, .fold_steps = try a.dupe(u32, shape.foldSteps(&buffer)), .last_layer_coefficients = shape.nLastLayerCoefficients() };
}
