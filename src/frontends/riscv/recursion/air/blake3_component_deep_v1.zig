//! Component-owned DEEP geometry for three/four-trace PCS verifiers.
//! The independent component masks select every sample and degree; a received
//! capture supplies arithmetic values only. No missing trace is synthesized.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const deep = @import("pcs_deep_circuit.zig");
const layouts = @import("../sample_point_layout.zig");
const capture_mod = @import("../pcs_arithmetic_capture.zig");
pub const Prepared = @import("blake3_native_deep.zig").Prepared;
pub const MAX_TRACE_TREES: usize = 4;

pub fn prepareComponents(a: std.mem.Allocator, all: core.air.components.Components, column_logs: []const []const u32, config: core.pcs.PcsConfig, proof: anytype) !Prepared {
    if (column_logs.len < 3 or column_logs.len > MAX_TRACE_TREES) return error.InvalidComponentDeepGeometry;
    return prepareInternal(MAX_TRACE_TREES, a, all, column_logs, config, proof);
}
/// Statically selected complete PAGE geometry; received proof metadata cannot
/// select or expand the tree grammar of a legacy entrypoint.
pub fn prepareForTraceTrees(comptime count: usize, a: std.mem.Allocator, all: core.air.components.Components, column_logs: []const []const u32, config: core.pcs.PcsConfig, proof: anytype) !Prepared {
    comptime if (count != 9) @compileError("explicit PAGE DEEP route requires nine trace trees");
    if (column_logs.len != count) return error.InvalidComponentDeepGeometry;
    return prepareInternal(count, a, all, column_logs, config, proof);
}
fn prepareInternal(comptime max_trees: usize, a: std.mem.Allocator, all: core.air.components.Components, column_logs: []const []const u32, config: core.pcs.PcsConfig, proof: anytype) !Prepared {
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const temp = scratch.allocator();
    const split = try all.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(all.compositionLogDegreeBound(), split) orelse return error.InvalidComponentDeepGeometry;
    const current = core.circle.SECURE_FIELD_CIRCLE_GEN;
    const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
    const previous = current.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var masks = try all.maskPoints(temp, current, mask_log, false);
    defer masks.deinitDeep(temp);
    if (masks.items.len != column_logs.len or proof.column_log_sizes.len != column_logs.len + 1) return error.InvalidComponentDeepGeometry;
    var trees: [max_trees + 1]deep.TreeProfile = undefined;
    var ordered: std.ArrayList(deep.SamplePointLayout) = .empty;
    var mask_logs: std.ArrayList(u32) = .empty;
    var physical_pair = false;
    const blowup = config.fri_config.log_blowup_factor;
    var lifting: u32 = 0;
    for (column_logs, masks.items, trees[0..column_logs.len], 0..) |logs, columns, *tree, index| {
        if (logs.len != columns.len or logs.len != proof.column_log_sizes[index].len) return error.InvalidComponentDeepGeometry;
        const extended = try temp.alloc(u32, logs.len);
        for (logs, columns, extended, proof.column_log_sizes[index]) |log, points, *out, captured_log| {
            out.* = try std.math.add(u32, log, blowup);
            if (out.* != captured_log) return error.InvalidComponentDeepGeometry;
            if (points.len != 0) lifting = @max(lifting, out.*);
            const layout = layouts.classifyColumn(points, current, previous) catch blk: {
                // The only non-composition-step mask admitted by this generic
                // path is the original fused Keccak current/+27 pair.
                const physical_step = core.poly.circle.canonic.CanonicCoset.new(log).step();
                const physical_previous = current.sub(.{ .x = Q.fromBase(physical_step.x), .y = Q.fromBase(physical_step.y) });
                break :blk try layouts.classifyKeccakPair(points, current, physical_previous);
            };
            if (layout == .current_keccak_final) physical_pair = true;
            try ordered.append(temp, layout);
            try mask_logs.append(temp, if (layout == .current_keccak_final) log else mask_log);
        }
        tree.* = .{ .column_log_sizes = extended };
    }
    const composition_columns = core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidComponentDeepGeometry;
    const extended = try temp.alloc(u32, composition_columns);
    @memset(extended, try std.math.add(u32, mask_log, blowup));
    if (!std.mem.eql(u32, extended, proof.column_log_sizes[column_logs.len])) return error.InvalidComponentDeepGeometry;
    lifting = @max(lifting, extended[0]);
    for (extended) |_| {
        try ordered.append(temp, .current);
        try mask_logs.append(temp, mask_log);
    }
    trees[column_logs.len] = .{ .column_log_sizes = extended };
    const profile = deep.Profile{ .trees = trees[0 .. column_logs.len + 1], .sample_layouts = ordered.items, .mask_log_sizes = if (physical_pair) mask_logs.items else &.{}, .lifting_log_size = lifting, .log_blowup_factor = blowup, .query_count = std.math.cast(u32, config.fri_config.n_queries) orelse return error.InvalidComponentDeepGeometry };
    var inputs = try capture_mod.Owned.init(a, profile, proof);
    errdefer inputs.deinit();
    var graph = try deep.build(a, profile);
    errdefer graph.deinit();
    const evaluation = try graph.evaluate(a, inputs.inputs);
    return .{ .graph = graph, .inputs = inputs, .evaluation = evaluation };
}
