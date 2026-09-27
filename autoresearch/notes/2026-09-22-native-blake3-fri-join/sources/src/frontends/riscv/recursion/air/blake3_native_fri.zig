//! Native FRI arithmetic and explicit DEEP-answer scalar routes.
const std = @import("std");
const core = @import("stwo_core");
const verifier = @import("../../prover/verifier.zig");
const suite = @import("../blake3_engine_protocol.zig");
const native_deep = @import("blake3_native_deep.zig");
const capture_mod = @import("../fri_arithmetic_capture.zig");
const fri = @import("fri_verifier_circuit.zig");
const terminal = @import("blake3_terminal_links.zig");
const scalar = @import("scalar_wire_source.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M31 = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    graph: fri.Circuit,
    inputs: capture_mod.Owned,
    evaluation: fri.Evaluation,
    links: terminal.Prepared,
    sources: []scalar.Row,
    fixed_sources: []scalar.Row,
    destinations: []scalar.Row,
    fixed_destinations: []scalar.Row,
    pub fn deinit(self: *Prepared) void {
        self.links.deinit();
        self.evaluation.deinit();
        self.inputs.deinit();
        self.graph.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(comptime Engine: type, a: std.mem.Allocator, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, deep: *const native_deep.Prepared, deep_circuit: u32, fri_circuit: u32) !Prepared {
    comptime {
        if (Engine.Hasher != suite.Hasher) @compileError("native FRI adapter requires BLAKE3 capture");
    }
    try capture.validate();
    try deep.graph.validateEvaluation(&deep.evaluation);
    const dp = deep.graph.profile();
    const fc = config.fri_config;
    if (dp.log_blowup_factor != fc.log_blowup_factor or dp.query_count != fc.n_queries or fc.fold_step == 0 or fc.fold_step > fri.MAX_FOLD_STEP) return error.InvalidNativeFriProfile;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var widths: std.ArrayList(u32) = .empty;
    var remaining = dp.lifting_log_size;
    const last = try std.math.add(u32, fc.log_blowup_factor, fc.log_last_layer_degree_bound);
    while (remaining > last) {
        const step = @min(fc.fold_step, remaining - last);
        try widths.append(temp, @as(u32, 1) << @intCast(step));
        remaining -= step;
    }
    const profile = fri.Profile{ .lifting_log_size = dp.lifting_log_size, .log_blowup_factor = fc.log_blowup_factor, .log_last_layer_degree_bound = fc.log_last_layer_degree_bound, .fold_widths = widths.items, .query_count = dp.query_count };
    var inputs = try capture_mod.Owned.init(a, profile, &capture.proof);
    errdefer inputs.deinit();
    var graph = try fri.build(a, profile);
    errdefer graph.deinit();
    var evaluation = try graph.evaluate(a, inputs.inputs);
    errdefer evaluation.deinit();
    var links = try terminal.build(a, &deep.graph, &graph, dp.query_count, inputs.inputs.last_layer_coefficients.len);
    errdefer links.deinit();
    const deep_uses = try lower.computeUseCountsInto(deep.graph.graph(), try temp.alloc(u32, deep.graph.nodes.len));
    const fri_uses = try lower.computeUseCountsInto(graph.graph(), try temp.alloc(u32, graph.nodes.len));
    const sources = try temp.alloc(scalar.Row, links.answers.len);
    const fixed_sources = try temp.alloc(scalar.Row, links.answers.len);
    const destinations = try temp.alloc(scalar.Row, links.answers.len);
    const fixed_destinations = try temp.alloc(scalar.Row, links.answers.len);
    for (links.answers, sources, fixed_sources, destinations, fixed_destinations) |link, *source, *fixed_source, *destination, *fixed_destination| {
        const value = deep.evaluation.values[link.deep];
        const base = value.toM31Array()[0];
        if (!value.eql(Q.fromBase(base)) or !value.eql(evaluation.values[link.fri])) return error.InvalidNativeFriAnswer;
        const weight = try std.math.add(u32, deep_uses[link.deep], 1);
        source.* = try scalar.logicalRow(deep_circuit, link.deep, weight, base);
        fixed_source.* = try scalar.logicalRow(deep_circuit, link.deep, weight, M31.zero());
        destination.* = try scalar.routedRow(fri_circuit, link.fri, fri_uses[link.fri], deep_circuit, link.deep, base);
        fixed_destination.* = try scalar.routedRow(fri_circuit, link.fri, fri_uses[link.fri], deep_circuit, link.deep, M31.zero());
    }
    return .{ .arena = arena, .graph = graph, .inputs = inputs, .evaluation = evaluation, .links = links, .sources = sources, .fixed_sources = fixed_sources, .destinations = destinations, .fixed_destinations = fixed_destinations };
}
