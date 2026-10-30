//! Capture-free PCS/DEEP/FRI geometry for the explicit compact lookup layout.
//! Shape only: no composition graph, transcript admission or recursive key is
//! claimed here. Original dense geometry remains an independent comparator.
const std = @import("std");
const core = @import("stwo_core");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
const Air = @import("../prover/block_v7_lookup_compact_air_v1.zig");
const Layout = @import("../prover/block_v7_lookup_compact_layout_v1.zig");
const Dense = @import("../prover/block_v5_native_lookup_assembly_v1.zig");
const Shared = @import("air/universal_provider_relations.zig");
const Q = core.fields.qm31.QM31;
pub const complete_key_authority = false;
pub fn compact(a: std.mem.Allocator, layout: Layout.Layout, config: core.pcs.PcsConfig, relations: Shared.SharedProviderRelations, limits: Shape.Limits) !Shape.Owned {
    try layout.validate();
    try relations.validate();
    const owner = try Air.Owner.init(a, layout, relations, @splat(Q.zero()));
    defer owner.deinit();
    var logs: [3][]const u32 = undefined;
    var ready: usize = 0;
    defer for (logs[0..ready]) |values| a.free(values);
    for (&logs, 0..) |*values, i| {
        values.* = try layout.logs(a, i);
        ready += 1;
    }
    return Shape.Owned.init(a, &logs, .{ .components = &owner.verifiers, .n_preprocessed_columns = layout.columns[0] }, config, limits);
}
pub fn originalDense(a: std.mem.Allocator, config: core.pcs.PcsConfig, relations: Shared.SharedProviderRelations, limits: Shape.Limits) !Shape.Owned {
    try relations.validate();
    const owner = try Dense.Owner.init(a, relations, @splat(Q.zero()));
    defer owner.destroy(a);
    var logs: [3][]const u32 = undefined;
    var ready: usize = 0;
    defer for (logs[0..ready]) |values| a.free(values);
    inline for (.{ Dense.Tree.fixed, Dense.Tree.main, Dense.Tree.interaction }, 0..) |tree, i| {
        logs[i] = try Dense.logs(a, tree);
        ready += 1;
    }
    return Shape.Owned.init(a, &logs, .{ .components = &owner.verifierHandles(), .n_preprocessed_columns = logs[0].len }, config, limits);
}
pub const Census = struct {
    trace_columns: usize,
    oods_secure_fields: usize,
    trace_query_fields_upper: usize,
    trace_path_edges_upper: usize,
    fri_rounds: usize,
    fri_openings_secure_upper: usize,
    lifting_log: u32,
    composition_log: u32,
    composition_split: u32,
    pub fn derive(shape: *const Shape.Owned) !Census {
        const queries = shape.config.fri_config.n_queries;
        var out = Census{ .trace_columns = 0, .oods_secure_fields = 0, .trace_query_fields_upper = 0, .trace_path_edges_upper = 0, .fri_rounds = shape.widths.len, .fri_openings_secure_upper = 0, .lifting_log = shape.lifting_log, .composition_log = shape.composition_log, .composition_split = shape.split };
        for (shape.columns) |columns| {
            var height: u32 = 0;
            for (columns) |log| height = @max(height, log);
            out.trace_columns = try std.math.add(usize, out.trace_columns, columns.len);
            out.trace_path_edges_upper = try std.math.add(usize, out.trace_path_edges_upper, try std.math.mul(usize, height, queries));
        }
        out.trace_query_fields_upper = try std.math.mul(usize, out.trace_columns, queries);
        for (shape.layouts) |layout| out.oods_secure_fields = try std.math.add(usize, out.oods_secure_fields, layout.sampleCount());
        for (shape.widths) |width| out.fri_openings_secure_upper = try std.math.add(usize, out.fri_openings_secure_upper, try std.math.mul(usize, width, queries));
        return out;
    }
};
