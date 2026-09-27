//! Original public cells to actual shared arithmetic cohorts in the enclosing
//! parent. Graph constants/zero outputs use canonical boundary rows; input
//! multiplicities use the exact lowering plan and independent public supply.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const recorder = @import("composition_graph_recorder.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const storage = @import("blake3_parent_row_storage.zig");
const direct = @import("blake3_direct_cohort_columns_v1.zig");
const rebase = @import("blake3_parent_rebase.zig");
const join = @import("blake3_parent_join.zig");
const Bus = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Source = Bus.Wire;
pub const CIRCUIT: u32 = 4_200_018;
pub const Graph = struct {
    circuit: *const recorder.Circuit,
    inputs: []const Q,
    values: []const Q,
    sources: []const Source,
};
pub const Lowered = struct {
    rows: storage.Prepared,
    wires: []Bus.Wire,
    identity: [32]u8,
    pub fn deinit(self: *Lowered) void {
        self.rows.allocator.free(self.wires);
        self.rows.deinit();
        self.* = undefined;
    }
};
/// This is a public-coordinate audit, not authority for the graph's equations.
/// The caller must supply its independently derived pairing/aggregate graph.
pub fn materialize(a: std.mem.Allocator, graph: Graph, values: Bus.Values) !Lowered {
    try values.validate();
    return materializeAdmitted(a, graph, values);
}
/// Exact canonical lowering/audit body after the caller has independently
/// validated its process-local immutable setup and current source values.
pub fn materializeLocallyAdmitted(a: std.mem.Allocator, graph: Graph, values: Bus.Values) !Lowered {
    return materializeAdmitted(a, graph, values);
}
fn materializeAdmitted(a: std.mem.Allocator, graph: Graph, values: Bus.Values) !Lowered {
    return materializeLocallyAdmittedFor(a, graph, values);
}
/// Statically selected coordinate view for genuine separately admitted lazy
/// source protocols. Same graph/Wire/cohorts/identity body as the typed path.
/// Received proofs cannot select this type or its admission policy.
pub fn materializeLocallyAdmittedFor(a: std.mem.Allocator, graph: Graph, values: anytype) !Lowered {
    try graph.circuit.validate();
    if (graph.sources.len != graph.circuit.input_count or graph.inputs.len != graph.sources.len or graph.values.len != graph.circuit.nodes.len) return error.InvalidHeterogeneousGraphShape;
    const checked = try a.alloc(Q, graph.values.len);
    defer a.free(checked);
    for (graph.sources, graph.inputs) |source, value| {
        const coordinates = try values.at(source);
        for (coordinates) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.UntrustedHeterogeneousGraphInput;
        if (!value.eql(Q.fromM31Array(coordinates))) return error.UntrustedHeterogeneousGraphInput;
    }
    try graph.circuit.evaluateInto(graph.inputs, checked);
    for (checked, graph.values) |actual, expected| if (!actual.eql(expected)) return error.MutatedHeterogeneousGraphEvaluation;
    const lane = lower.Lane{ .circuit_id = CIRCUIT, .active_in = .segment, .circuit_identity = graph.circuit.identity_digest, .graph = graph.circuit.graph() };
    // The shared lowering contract admits both selectors. Like original native
    // preparation, use the identical authenticated graph for the inactive
    // binary schedule; only segment terms enter this parent public supply.
    var binary = lane;
    binary.circuit_id += 1;
    binary.active_in = .binary;
    const lanes = [_]lower.Lane{ lane, binary };
    const reference = try lower.Reference.seal(&lanes);
    var plan = try lower.Plan.init(a, reference);
    defer plan.deinit();
    const evaluation = lower.Evaluation{ .circuit_identity = graph.circuit.identity_digest, .values = graph.values };
    var fused = try @import("arithmetic_fusion_rows.zig").materializeColumns(a, &plan, reference, .{ .lanes = &.{ evaluation, evaluation } }, .segment_leaf);
    defer fused.deinit();
    var rows = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = graph.inputs.len };
    inline for (0..storage.Airs.len) |i| rows.fixed[i] = &.{};
    errdefer rows.deinit();
    inline for (storage.Airs, 0..) |Air, i| {
        var empty = try direct.ForAir(Air).init(a, 0);
        defer empty.deinit();
        const columns = try empty.take();
        rows.main[i] = columns.main;
        rows.fixed[i] = columns.fixed;
    }
    inline for (.{ 3, 4, 5 }, .{ &fused.multiply, &fused.inverse, &fused.linear }) |i, cohort| {
        const columns = try cohort.take();
        rows.releaseCohort(i);
        rows.main[i] = columns.main;
        rows.fixed[i] = columns.fixed;
    }
    var openings = try direct.ForAir(storage.Airs[18]).init(a, fused.opening.len);
    defer openings.deinit();
    for (fused.opening) |row| try openings.append(row);
    const opened = try openings.take();
    rows.releaseCohort(18);
    rows.main[18] = opened.main;
    rows.fixed[18] = opened.fixed;
    var boundary_count: usize = 0;
    for (plan.public_terms) |term| if (term.active_in == .segment) {
        boundary_count += 1;
    };
    var boundaries = try direct.ForAir(storage.Airs[2]).init(a, boundary_count);
    defer boundaries.deinit();
    for (plan.public_terms) |term| if (term.active_in == .segment) {
        if (term.role == .request) return error.InvalidHeterogeneousGraphBoundary;
        const weight = M.fromCanonical(term.multiplicity);
        try boundaries.append(try @import("blake3_boundary.zig").logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array()));
    };
    const anchored = try boundaries.take();
    rows.releaseCohort(2);
    rows.main[2] = anchored.main;
    rows.fixed[2] = anchored.fixed;
    const counts = try a.alloc(u32, graph.circuit.nodes.len);
    defer a.free(counts);
    const uses = try lower.computeLaneUseCountsInto(lane, counts);
    var wires: std.ArrayList(Bus.Wire) = .empty;
    errdefer wires.deinit(a);
    for (graph.sources, 0..) |source, node| if (uses[node] != 0) {
        var wire = source;
        wire.circuit = CIRCUIT;
        wire.wire = @intCast(node);
        wire.uses = uses[node];
        wire.negative = false;
        try wires.append(a, wire);
    };
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ 0x42355a45, 1, CIRCUIT }); // B5ZE compact scoped export equations.
    channel.mixRoot(graph.circuit.identity_digest);
    channel.mixRoot(reference.authority_digest);
    for (graph.sources) |source| channel.mixU32s(&.{ @intFromEnum(source.kind), source.child, source.coordinate, if (source.part) |part| part else 4 });
    return .{ .rows = rows, .wires = try wires.toOwnedSlice(a), .identity = channel.digestBytes() };
}
/// Adds genuinely constrained equations to the same parent rows and public
/// supply schedule. Callers mix the returned identity into setup context.
pub fn attach(a: std.mem.Allocator, parent: *@import("../blake3_execution_parent_preparation.zig").Prepared, wires: *std.ArrayList(Bus.Wire), graph: Graph, values: Bus.Values, next_namespace: *u32) ![32]u8 {
    try values.validate();
    var lowered = try materialize(a, graph, values);
    defer lowered.deinit();
    var namespace = try rebase.prepare(a, &lowered.rows, next_namespace.*);
    defer namespace.deinit();
    const end = try namespace.end();
    const namespace_id = try namespace.identity();
    for (lowered.wires) |*wire| wire.circuit = namespace.map(wire.circuit) orelse return error.MissingHeterogeneousGraphNamespace;
    // Reserve before the destructive row transfer. The caller tears down its
    // parent on every later error; no borrowed source is consumed by this API.
    try wires.ensureUnusedCapacity(a, lowered.wires.len);
    try rebase.apply(&lowered.rows, &namespace, namespace_id);
    const joined = try join.joinDraining(a, &parent.rows, &lowered.rows, .{ .{ .first = 1, .end = next_namespace.* }, .{ .first = next_namespace.*, .end = end } });
    parent.rows.deinit();
    lowered.rows.deinit();
    lowered.rows = .{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..storage.Airs.len) |i| lowered.rows.fixed[i] = &.{};
    parent.rows = joined;
    wires.appendSliceAssumeCapacity(lowered.wires);
    next_namespace.* = end;
    var channel = core.channel.blake3.Channel{};
    channel.mixRoot(lowered.identity);
    channel.mixRoot(namespace_id);
    return channel.digestBytes();
}

/// Pure lower-row parity view, never an admitted parent/proof source.
pub const testing = struct {
    pub const lowerGraph = materializeAdmitted;
};
