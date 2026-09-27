//! Canonical DEEP preparation from authenticated native V2 geometry.
const std = @import("std");
const core = @import("stwo_core");
const verifier = @import("../../prover/verifier.zig");
const suite = @import("../blake3_engine_protocol.zig");
const geometry_mod = @import("../vm_composition_base_geometry_v2.zig");
const capture_mod = @import("../pcs_arithmetic_capture.zig");
const deep = @import("pcs_deep_circuit.zig");
pub const Prepared = struct {
    graph: deep.Circuit,
    inputs: capture_mod.Owned,
    evaluation: deep.Evaluation,
    pub fn deinit(self: *Prepared) void {
        self.evaluation.deinit();
        self.inputs.deinit();
        self.graph.deinit();
        self.* = undefined;
    }
};
pub fn prepare(comptime Engine: type, a: std.mem.Allocator, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig) !Prepared {
    comptime {
        if (Engine.Hasher != suite.Hasher) @compileError("native DEEP adapter requires BLAKE3 capture");
    }
    try capture.validate();
    var geometry = try geometry_mod.GeometryV2.init(a, &capture.vm_air.profile);
    defer geometry.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const temp = scratch.allocator();
    var trees: [geometry_mod.TREE_COUNT]deep.TreeProfile = undefined;
    var layouts: std.ArrayList(deep.SamplePointLayout) = .empty;
    var lifting: u32 = 0;
    for (geometry.columns, &trees) |columns, *tree| {
        const logs = try temp.alloc(u32, columns.len);
        for (columns, logs) |column, *log| {
            log.* = try std.math.add(u32, column.log_size, config.fri_config.log_blowup_factor);
            lifting = @max(lifting, log.*);
            // GeometryV2 validates the exact current/previous order.
            try layouts.append(temp, if (column.sample_count == 2) .current_previous else .current);
        }
        tree.* = .{ .column_log_sizes = logs };
    }
    const profile = deep.Profile{ .trees = &trees, .sample_layouts = layouts.items, .lifting_log_size = lifting, .log_blowup_factor = config.fri_config.log_blowup_factor, .query_count = std.math.cast(u32, config.fri_config.n_queries) orelse return error.InvalidNativeDeepProfile };
    var inputs = try capture_mod.Owned.init(a, profile, &capture.proof);
    errdefer inputs.deinit();
    var graph = try deep.build(a, profile);
    errdefer graph.deinit();
    const evaluation = try graph.evaluate(a, inputs.inputs);
    return .{ .graph = graph, .inputs = inputs, .evaluation = evaluation };
}
