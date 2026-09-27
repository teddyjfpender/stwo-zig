//! Complete native child verifier row assembly. No implicit public input fallback.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const lower = @import("verifier_arithmetic_lowering.zig");
const Graph = @import("composition_circuit.zig").CircuitGraph;
const vm = @import("../vm_air_composition_circuit.zig");
const scalar = @import("scalar_wire_source.zig");
const boundary = @import("blake3_boundary.zig");
pub const selectors = @import("proof_kind.zig").ProofKind.segment_leaf.selectors();
pub const Airs = .{
    @import("blake3_g_call.zig"),                   @import("blake3_xor_call.zig"),      boundary,
    @import("qm31_mul_add_v1.zig"),                 @import("qm31_inv.zig"),             @import("linear_ops.zig"),
    @import("blake3_challenge_block.zig"),          @import("blake3_byte_route.zig"),    @import("blake3_query_mask.zig"),
    @import("blake3_private_word.zig"),             @import("blake3_field_bytes.zig"),   @import("qm31_pack_wire.zig"),
    scalar,                                         @import("blake3_path_select.zig"),   @import("blake3_retry_control.zig"),
    @import("blake3_counter_step.zig"),             @import("readonly_consistency.zig"), @import("readonly_input.zig"),
    @import("detached_opening_accumulate4_v1.zig"),
};
fn Tuple(comptime list: bool) type {
    var types: [Airs.len]type = undefined;
    for (Airs, &types) |Air, *T| T.* = if (list) std.ArrayList(Air.Row) else []Air.Row;
    return std.meta.Tuple(&types);
}
pub const Sources = struct {
    composition: *const vm.Prepared,
    transcript: *const @import("blake3_native_transcript.zig").Prepared,
    deep: *const @import("blake3_native_deep.zig").Prepared,
    fri: *const @import("blake3_native_fri.zig").Prepared,
    payloads: *const @import("blake3_native_payload_links.zig").Prepared,
    samples: *const @import("blake3_native_sample_links.zig").Prepared,
    challenges: *const @import("blake3_native_pcs_challenges.zig").Prepared,
    terminal: *const @import("blake3_native_terminal_encoding.zig").Prepared,
    queries: *const @import("blake3_native_queries.zig").Prepared,
    openings: *const @import("blake3_native_openings.zig").Prepared,
    roots: *const @import("blake3_native_root_nonce.zig").Prepared,
    public_boundary: *const @import("blake3_native_public_boundary.zig").Prepared,
    public_join: *const @import("blake3_native_public_links.zig").Prepared,
    public_inputs: *const @import("blake3_native_public_sources.zig").Prepared,
    paths: *const @import("blake3_stark_paths.zig").Prepared,
    fn graphs(self: Sources) [5]Graph {
        return .{ self.composition.circuit.graph(), self.deep.graph.graph(), self.fri.graph.graph(), self.public_boundary.graph.graph, self.public_join.graph.graph };
    }
    fn evaluations(self: Sources) [5][]const Q {
        return .{ self.composition.evaluation.values, self.deep.evaluation.values, self.fri.evaluation.values, self.public_boundary.evaluation.values, self.public_join.evaluation.values };
    }
};
/// Read-only census of the exact graph lanes used by this assembler.
pub fn fusionCensus(a: std.mem.Allocator, sources: Sources) !void {
    var removed: usize = 0;
    var original: usize = 0;
    for (sources.graphs(), 0..) |graph, i| {
        const lane = lower.Lane{ .circuit_id = @intCast(1500 + 2 * i), .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph };
        const census = try @import("arithmetic_fusion_census.zig").inspect(a, lane);
        original += census.multiply + census.linear + census.inverse;
        removed += census.removedRows();
        std.debug.print("BLAKE3_ARITHMETIC_CENSUS lane={d} nodes={d} multiply={d} linear={d} inverse={d} dot4={d} fma={d} removable_rows={d}\n", .{ lane.circuit_id, census.nodes, census.multiply, census.linear, census.inverse, census.dot4_matches, census.fma_matches, census.removedRows() });
    }
    const pcs_census = try @import("detached_pcs_opening_plan.zig").censusGraph(a, sources.deep.graph.graph(), sources.deep.graph.bindings, &.{});
    std.debug.print("BLAKE3_PCS_QUERY_FUSION_CENSUS nodes={d} query_inputs={d} single_use={d} shared={d} dot4={d} eligible={d} scope=arithmetic_graph_only native_routing_admitted=false\n", .{ pcs_census.graph_nodes, pcs_census.queried_inputs, pcs_census.single_use_queried_inputs, pcs_census.shared_queried_inputs, pcs_census.opening4_groups, pcs_census.eligible_groups });
    std.debug.print("BLAKE3_ARITHMETIC_CENSUS total_rows={d} removable_rows={d} removed_relation_events={d} scope=graph_match_census\n", .{ original, removed, 2 * removed });
}

pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: Tuple(false),
    fixed: Tuple(false),
    input_count: usize,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    rows: Tuple(true),
    fixed: Tuple(true),
    fn init(a: std.mem.Allocator) Builder {
        var self: Builder = .{ .a = a, .rows = undefined, .fixed = undefined };
        inline for (0..Airs.len) |i| {
            self.rows[i] = .empty;
            self.fixed[i] = .empty;
        }
        return self;
    }
    fn append(self: *Builder, comptime i: usize, rows: []const Airs[i].Row, fixed: []const Airs[i].Row) !void {
        if (rows.len != fixed.len) return error.InvalidNativeParentRows;
        for (rows, fixed) |live, trusted| for (live[Airs[i].PHYSICAL_MAIN_COLUMN_COUNT..], trusted[Airs[i].PHYSICAL_MAIN_COLUMN_COUNT..]) |actual, expected| {
            if (!actual.eql(expected)) return error.InvalidNativeParentRows;
        };
        try self.rows[i].appendSlice(self.a, rows);
        try self.fixed[i].appendSlice(self.a, fixed);
    }
};
pub fn prepare(a: std.mem.Allocator, source: Sources) !Prepared {
    try source.composition.validate();
    try source.deep.graph.validateEvaluation(&source.deep.evaluation);
    try source.fri.evaluation.validateAgainst(&source.fri.graph);
    try source.public_boundary.validate(a);
    try source.public_join.graph.validate();
    var aggregate = try source.public_join.evaluate(a, &source.public_join.inputs);
    defer aggregate.deinit();
    if (aggregate.values.len != source.public_join.evaluation.values.len) return error.InvalidNativeParentRows;
    for (aggregate.values, source.public_join.evaluation.values) |actual, expected| if (!actual.eql(expected)) return error.InvalidNativeParentRows;
    try source.transcript.plan.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var b = Builder.init(temp);
    const graphs = source.graphs();
    const values = source.evaluations();
    // Replacements are selected once, before constructing any row roster.
    const claim_words = source.public_join.claim_sources.len;
    if (source.samples.sources.len < claim_words) return error.InvalidNativeParentRows;
    try b.append(12, &source.public_join.composition.rows, &source.public_join.composition.fixed);
    try b.append(12, source.challenges.rows, source.challenges.fixed);
    try b.append(12, &source.public_join.challenge_rows, &source.public_join.fixed_challenges);
    try b.append(12, &source.public_join.claim_sources, &source.public_join.fixed_claims);
    try b.append(12, source.samples.sources[claim_words..], source.samples.fixed_sources[claim_words..]);
    try b.append(12, source.samples.destinations, source.samples.fixed_destinations);
    try b.append(12, source.fri.sources, source.fri.fixed_sources);
    try b.append(12, source.fri.destinations, source.fri.fixed_destinations);
    try b.append(12, source.queries.rows, source.queries.fixed);
    try b.append(12, source.openings.rows, source.openings.fixed);
    try b.append(12, &source.public_join.total_sources, &source.public_join.fixed_total_sources);
    try b.append(12, &source.public_join.destinations, &source.public_join.fixed_destinations);
    try b.append(12, &source.public_inputs.sums, &source.public_inputs.fixed_sums);
    try b.append(2, source.public_inputs.rows, source.public_inputs.fixed_rows);
    try b.append(2, &source.roots.key, &source.roots.key);
    try b.append(9, source.roots.words, source.roots.fixed_words);
    try b.append(11, source.payloads.packing, source.payloads.fixed_packing);
    try b.append(10, source.payloads.encoded, source.payloads.fixed_encoded);
    try b.append(10, source.queries.encoded, source.queries.fixed_encoded);
    try b.append(11, source.paths.inputs.packing, source.paths.inputs.fixed_packed);
    try b.append(10, source.paths.inputs.encoded, source.paths.inputs.fixed_encoded);
    try b.append(16, source.paths.inputs.readonly_rows, source.paths.inputs.fixed_readonly_rows);
    try b.append(17, source.paths.inputs.adapter_rows, source.paths.inputs.fixed_adapter_rows);
    for (source.terminal.rows) |row| {
        try b.append(12, &row.scalars, &row.fixed_scalars);
        try b.append(11, &.{row.packing}, &.{row.fixed_packing});
        try b.append(10, &.{row.encoded}, &.{row.fixed_encoded});
    }
    try b.append(0, source.transcript.live.g_rows, source.transcript.plan.fixed.g_rows);
    try b.append(1, source.transcript.live.xor_rows, source.transcript.plan.fixed.xor_rows);
    try b.append(2, source.transcript.live.boundary_rows, source.transcript.plan.fixed.boundary_rows);
    try b.append(6, source.transcript.live.challenge_rows, source.transcript.plan.fixed.challenge_rows);
    try b.append(7, source.transcript.live.route_rows, source.transcript.plan.fixed.route_rows);
    try b.append(8, source.transcript.live.query_rows, source.transcript.plan.fixed.query_rows);
    try b.append(14, source.transcript.live.control_rows, source.transcript.plan.fixed.control_rows);
    try b.append(15, source.transcript.live.counter_rows, source.transcript.plan.fixed.counter_rows);
    try b.append(0, source.paths.live.g_rows, source.paths.fixed.g_rows);
    try b.append(1, source.paths.live.xor_rows, source.paths.fixed.xor_rows);
    try b.append(2, source.paths.live.boundary_rows, source.paths.fixed.boundary_rows);
    try b.append(7, source.paths.live.route_rows, source.paths.fixed.route_rows);
    try b.append(9, source.paths.live.word_rows, source.paths.fixed.word_rows);
    try b.append(13, source.paths.live.select_rows, source.paths.fixed.select_rows);
    // Only these two VM source roles were not already supplied by joins.
    const vm_uses = try lower.computeUseCountsInto(graphs[0], try temp.alloc(u32, graphs[0].nodes.len));
    var selector_count: usize = 0;
    for (source.composition.circuit.bindings) |binding| switch (binding.source) {
        .segment_selector => {
            if (!values[0][binding.node_id].eql(Q.one())) return error.InvalidNativeParentRows;
            const row = try boundary.logicalCoordinates(1500, binding.node_id, M.fromCanonical(vm_uses[binding.node_id]), Q.one().toM31Array());
            try b.append(2, &.{row}, &.{row});
            selector_count += 1;
        },
        .claimed_sum => {
            const value = values[0][binding.node_id].tryIntoM31() catch return error.InvalidNativeParentRows;
            try b.append(12, &.{try scalar.logicalRow(1500, binding.node_id, vm_uses[binding.node_id], value)}, &.{try scalar.logicalRow(1500, binding.node_id, vm_uses[binding.node_id], M.zero())});
        },
        else => {},
    };
    if (selector_count != 1) return error.InvalidNativeParentRows;
    inline for (.{ source.deep.graph.bindings, source.fri.graph.bindings }, 1..) |bindings, lane| {
        const uses = try lower.computeUseCountsInto(graphs[lane], try temp.alloc(u32, graphs[lane].nodes.len));
        var active_count: usize = 0;
        for (bindings) |binding| if (binding.source == .active_selector) {
            if (!values[lane][binding.node_id].eql(Q.one())) return error.InvalidNativeParentRows;
            const row = try boundary.logicalCoordinates(1500 + 2 * lane, binding.node_id, M.fromCanonical(uses[binding.node_id]), Q.one().toM31Array());
            try b.append(2, &.{row}, &.{row});
            active_count += 1;
        };
        if (active_count != 1) return error.InvalidNativeParentRows;
    }
    const input_count = try inventory(temp, graphs, values, b.rows[12].items, b.rows[2].items);
    // Reuse the canonical lowering plan, including constant and output terms.
    var lanes: [10]lower.Lane = undefined;
    var evaluations: [10]lower.Evaluation = undefined;
    for (graphs, values, 0..) |graph, evaluated, i| {
        lanes[2 * i] = .{ .circuit_id = @intCast(1500 + 2 * i), .active_in = .segment, .circuit_identity = graph.identity_digest, .graph = graph };
        lanes[2 * i + 1] = lanes[2 * i];
        lanes[2 * i + 1].circuit_id += 1;
        lanes[2 * i + 1].active_in = .binary;
        evaluations[2 * i] = .{ .circuit_identity = graph.identity_digest, .values = evaluated };
        evaluations[2 * i + 1] = evaluations[2 * i];
    }
    const reference = try lower.Reference.seal(&lanes);
    var plan = try lower.Plan.init(temp, reference);
    defer plan.deinit();
    var fused = try @import("arithmetic_fusion_rows.zig").materialize(temp, &plan, reference, .{ .lanes = &evaluations }, .segment_leaf);
    defer fused.deinit();
    inline for (.{ 3, 4, 5, 18 }, .{ fused.multiply, fused.inverse, fused.linear, fused.opening }) |i, fused_rows| {
        for (fused_rows) |row| {
            var fixed = row;
            @memset(fixed[0..Airs[i].PHYSICAL_MAIN_COLUMN_COUNT], M.zero());
            try b.append(i, &.{row}, &.{fixed});
        }
    }
    std.debug.print("BLAKE3_NATIVE_FUSION dot4={d} fma={d} arithmetic_rows={d}\n", .{ fused.dot4_matches, fused.fma_matches, fused.multiply.len + fused.inverse.len + fused.linear.len + fused.opening.len });
    for (plan.public_terms) |term| if (term.active_in == .segment) {
        const weight = M.fromCanonical(term.multiplicity);
        const row = try boundary.logicalCoordinates(term.circuit_id, term.node_id, if (term.role == .emit) weight else weight.neg(), term.value.toM31Array());
        try b.append(2, &.{row}, &.{row});
    };
    var rows: Tuple(false) = undefined;
    var fixed: Tuple(false) = undefined;
    inline for (0..Airs.len) |i| {
        rows[i] = try b.rows[i].toOwnedSlice(temp);
        fixed[i] = try b.fixed[i].toOwnedSlice(temp);
    }
    return .{ .arena = arena, .rows = rows, .fixed = fixed, .input_count = input_count };
}
fn inventory(a: std.mem.Allocator, graphs: [5]Graph, values: [5][]const Q, scalars: []const scalar.Row, boundaries: []const boundary.Row) !usize {
    var seen: [5][]bool = undefined;
    for (graphs, &seen) |graph, *mask| {
        mask.* = try a.alloc(bool, graph.nodes.len);
        @memset(mask.*, false);
    }
    for (scalars) |row| try mark(graphs, values, seen, row[1].v, row[2].v, Q.fromBase(row[0]));
    for (boundaries) |row| try mark(graphs, values, seen, row[5].v, row[6].v, Q.fromM31Array(row[0..4].*));
    var count: usize = 0;
    for (graphs, seen) |graph, mask| for (graph.nodes, mask) |node, present| {
        if (node.op == .input) {
            if (!present) return error.MissingNativeParentInput;
            count += 1;
        }
    };
    return count;
}
fn mark(graphs: [5]Graph, values: [5][]const Q, seen: [5][]bool, circuit: u32, node: u32, value: Q) !void {
    if (circuit < 1500 or circuit >= 1510) return;
    if (circuit % 2 != 0) return error.InvalidNativeParentInput;
    const lane = (circuit - 1500) / 2;
    if (node >= graphs[lane].nodes.len or graphs[lane].nodes[node].op != .input or !values[lane][node].eql(value)) return error.InvalidNativeParentInput;
    if (seen[lane][node]) return error.DuplicateNativeParentInput;
    seen[lane][node] = true;
}
