//! One admitted routing/lowering plan for the detached parent's verifier graphs.
//! Graph structure supplies constants, zero anchors and exact wire use counts;
//! semantic input bindings supply sources. No unknown source becomes a hint.
const recursion = struct {
    const detached_parent_prepared_v1 = @import("detached_parent_prepared_v1.zig");
    const segment_transcript_outer_source_v2 = @import("segment_transcript_outer_source_v2.zig");
    const span_continuation_v1 = @import("span_continuation_v1.zig");
};
const air = struct {
    const composition_circuit = @import("air/composition_circuit.zig");
    const detached_arithmetic_fusion_plan = @import("air/detached_arithmetic_fusion_plan.zig");
    const detached_graph_input_v1 = @import("air/detached_graph_input_v1.zig");
    const detached_opening_accumulate4_v1 = @import("air/detached_opening_accumulate4_v1.zig");
    const detached_opening_accumulation_plan = @import("air/detached_opening_accumulation_plan.zig");
    const detached_poseidon_graph_v1 = @import("air/detached_poseidon_graph_v1.zig");
    const fixed_wire_v3 = @import("air/fixed_wire_v3.zig");
    const linear_ops = @import("air/linear_ops.zig");
    const linear_ops_witness = @import("air/linear_ops_witness.zig");
    const qm31_inv = @import("air/qm31_inv.zig");
    const qm31_inv_witness = @import("air/qm31_inv_witness.zig");
    const qm31_mul_add_v1 = @import("air/qm31_mul_add_v1.zig");
    const qm31_mul_full_witness = @import("air/qm31_mul_full_witness.zig");
    const relation_challenge_witness = @import("air/relation_challenge_witness.zig");
    const transcript_payload = @import("air/transcript_payload.zig");
    const verifier_arithmetic_lowering = @import("air/verifier_arithmetic_lowering.zig");
    const verifier_randomness_witness = @import("air/verifier_randomness_witness.zig");
};
const std = @import("std");
const core = @import("stwo_core");
const lowering = air.verifier_arithmetic_lowering;
const bridge = air.detached_graph_input_v1;
const poseidon = air.detached_poseidon_graph_v1;
const composition_mod = @import("detached_composition_preparation_v1.zig");
const boundary_mod = @import("detached_boundary_preparation_v1.zig");
const parent_mod = @import("detached_parent_statement_preparation_v1.zig");
const pcs_mod = @import("detached_pcs_preparation_v1.zig");
const prefix = @import("detached_prefix_preparation_v1.zig");
const cohort = recursion.detached_parent_prepared_v1;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const INPUT_KIND = air.transcript_payload.VerifierInputKind;
const RANDOM_KIND = air.verifier_randomness_witness.Kind;
pub const COMPOSITION_IDS = [2]u32{ 501, 502 };
pub const BOUNDARY_IDS = [2]u32{ 511, 512 };
pub const PARENT_ID: u32 = 521;
pub const PUBLIC_SCOPE: u32 = 3;
pub const Children = struct {
    composition: [2]*const composition_mod.OwnedV1,
    boundary: [2]*const boundary_mod.OwnedV1,
    pcs: [2]*const pcs_mod.OwnedV1,
};
pub const View = struct {
    logical: cohort.LogicalRowsV1,
    provider: []const recursion.segment_transcript_outer_source_v2.ProviderCall,
    parent_words: recursion.span_continuation_v1.Words,
    lowering_identity: [32]u8,
};
pub const OwnedV1 = opaque {
    const Storage = struct { arena: std.heap.ArenaAllocator, view_value: View };
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn init(allocator: std.mem.Allocator, children: Children, parent: *const parent_mod.OwnedV1) !*OwnedV1 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        var logical: cohort.LogicalRowsV1 = undefined;
        inline for (cohort.LOGICAL_ROWS, 0..) |_, index| logical[index] = &.{};
        // Existing shared lowering requires both modes. The inactive segment
        // lane has one zero-output anchor and contributes no active rows or claims.
        const dummy_nodes = [_]air.composition_circuit.Node{.{ .op = .{ .constant = .{ 0, 0, 0, 0 } } }};
        const dummy_graph = try air.composition_circuit.CircuitGraph.authenticate(&dummy_nodes, &.{0}, air.composition_circuit.computeGraphDigest(&dummy_nodes, &.{0}));
        var lanes: [10]lowering.Lane = undefined;
        var evaluations: [10]lowering.Evaluation = undefined;
        lanes[0] = lane(500, .segment, dummy_graph);
        evaluations[0] = .{ .circuit_identity = dummy_graph.identity_digest, .values = &.{QM31.zero()} };
        var boundary_counts: [2][]u32 = undefined;
        for (0..2) |child| {
            const i = 1 + 4 * child;
            lanes[i] = lane(COMPOSITION_IDS[child], .binary, children.composition[child].graph());
            evaluations[i] = evaluation(lanes[i], children.composition[child].evaluatedValues());
            lanes[i + 1] = lane(BOUNDARY_IDS[child], .binary, children.boundary[child].graph());
            evaluations[i + 1] = evaluation(lanes[i + 1], children.boundary[child].evaluatedValues());
            lanes[i + 2] = lane(@intCast(412 + child), .binary, children.pcs[child].pcsGraph());
            evaluations[i + 2] = evaluation(lanes[i + 2], children.pcs[child].pcsValues());
            lanes[i + 3] = lane(@intCast(402 + child), .binary, children.pcs[child].friGraph());
            evaluations[i + 3] = evaluation(lanes[i + 3], children.pcs[child].friValues());
            boundary_counts[child] = try a.alloc(u32, lanes[i + 1].graph.nodes.len);
            @memset(boundary_counts[child], 0);
        }
        lanes[9] = lane(PARENT_ID, .binary, parent.graph());
        evaluations[9] = evaluation(lanes[9], parent.evaluatedValues());
        for (parent.inputBindings()) |binding| switch (binding.source) {
            .child => |source| {
                if (!std.mem.eql(u8, &parent.boundaryGraphIdentities()[source.child], &children.boundary[source.child].graph().identity_digest) or source.boundary_node != (switch (source.projection) {
                    .span => children.boundary[source.child].spanNodes()[source.word],
                    .raw => try children.boundary[source.child].rawWireNode(source.word),
                })) return error.DetachedParentBoundaryMismatch;
                try addExport(boundary_counts[source.child], source.boundary_node);
            },
            else => {},
        };
        // A composition profile may read statement words. Share the actual
        // boundary projection; do not create a second unbound statement input.
        for (0..2) |child| {
            const i = 1 + 4 * child;
            const scratch = try a.alloc(u32, lanes[i].graph.nodes.len);
            const uses = try lowering.computeLaneUseCountsInto(lanes[i], scratch);
            for (children.composition[child].inputBindings()) |binding| if (uses[binding.node_id] != 0) switch (binding.source) {
                .statement_word => |word| try addExport(boundary_counts[child], children.boundary[child].spanNodes()[word]),
                else => {},
            };
            var exports: std.ArrayList(lowering.Export) = .empty;
            for (boundary_counts[child], 0..) |count, node| if (count != 0) try exports.append(a, .{ .node_id = @intCast(node), .uses = count });
            lanes[i + 1].exports = try exports.toOwnedSlice(a);
        }
        const reference = try lowering.Reference.seal(&lanes);
        // Admission/materialization scratch is not part of the immutable
        // prepared witness. Retain only the final logical rows and routing.
        var preparation = std.heap.ArenaAllocator.init(allocator);
        defer preparation.deinit();
        var plan = try lowering.Plan.init(preparation.allocator(), reference);
        var input_rows: std.ArrayList(bridge.Row) = .empty;
        var poseidon_rows: std.ArrayList(poseidon.Row) = .empty;
        var provider: std.ArrayList(recursion.segment_transcript_outer_source_v2.ProviderCall) = .empty;
        for (0..2) |child| {
            const i = 1 + 4 * child;
            const verifier: u32 = @intCast(child + 1);
            const composition = children.composition[child];
            const comp_uses = try a.alloc(u32, composition.graph().nodes.len);
            _ = try lowering.computeLaneUseCountsInto(lanes[i], comp_uses);
            for (composition.inputBindings(), composition.inputValues()) |binding, value| {
                if (comp_uses[binding.node_id] == 0) continue;
                const source = try compositionSource(binding.source, verifier, children.boundary[child]);
                try input_rows.append(a, try bridge.logicalRow(.{ .circuit = lanes[i].circuit_id, .node = binding.node_id, .uses = comp_uses[binding.node_id] }, source, value));
            }
            const boundary = children.boundary[child];
            const boundary_uses = try a.alloc(u32, boundary.graph().nodes.len);
            _ = try lowering.computeLaneUseCountsInto(lanes[i + 1], boundary_uses);
            for (boundary.inputBindings(), boundary.inputValues()) |binding, value| {
                if (binding.source == .provider_word) continue; // sole producer is Poseidon bridge below
                const source: bridge.Source = switch (binding.source) {
                    .transcript => |coordinate| .{ .verifier_input = .{ verifier, @intFromEnum(coordinate.kind), coordinate.item, coordinate.limb } },
                    .challenge => |coordinate| .{ .challenge = .{ verifier, coordinate.scope, @intFromEnum(coordinate.domain), @as(u32, coordinate.draw) * 4 + coordinate.limb } },
                    .end_limb, .increment_carry, .increment_low, .remaining_segments_limb, .remaining_segments_carry, .zero_inverse, .range_bit => .private,
                    .provider_word => unreachable,
                };
                try input_rows.append(a, try bridge.logicalRow(.{ .circuit = lanes[i + 1].circuit_id, .node = binding.node_id, .uses = boundary_uses[binding.node_id] }, source, value));
            }
            for (boundary.providerBindings()) |binding| {
                var words: [32]M31 = undefined;
                var uses: [32]u32 = undefined;
                for (binding.nodes, &words, &uses) |node, *word, *count| {
                    word.* = try boundary.evaluatedValues()[node].tryIntoM31();
                    count.* = boundary_uses[node];
                }
                try poseidon_rows.append(a, try poseidon.logicalRow(lanes[i + 1].circuit_id, binding.nodes, uses, words));
            }
            try provider.appendSlice(a, boundary.providerCalls());
        }
        const parent_uses = try a.alloc(u32, parent.graph().nodes.len);
        _ = try lowering.computeLaneUseCountsInto(lanes[9], parent_uses);
        var publication_count: [recursion.span_continuation_v1.WORD_COUNT]u32 = @splat(0);
        for (parent.inputBindings(), parent.inputValues()) |binding, value| {
            const source: bridge.Source = switch (binding.source) {
                .child => |coordinate| .{ .wire = .{ .circuit = BOUNDARY_IDS[coordinate.child], .node = coordinate.boundary_node } },
                .parent_word => |word| blk: {
                    publication_count[word] += 1;
                    break :blk .{ .statement = .{ .scope = PUBLIC_SCOPE, .word = word } };
                },
                .hint, .word_bit => .private,
            };
            try input_rows.append(a, try bridge.logicalRow(.{ .circuit = PARENT_ID, .node = binding.node_id, .uses = parent_uses[binding.node_id] }, source, value));
        }
        for (publication_count) |count| if (count != 1) return error.DetachedParentPublicationMultiplicity;
        logical[cohort.logicalIndex(11)] = try input_rows.toOwnedSlice(a);
        logical[cohort.logicalIndex(12)] = try poseidon_rows.toOwnedSlice(a);
        var fixed_rows: std.ArrayList(air.fixed_wire_v3.Row) = .empty;
        for (plan.public_terms) |term| if (term.active_in == .binary) try fixed_rows.append(a, try air.fixed_wire_v3.logicalRow(term));
        logical[cohort.logicalIndex(13)] = try fixed_rows.toOwnedSlice(a);
        try arithmeticRows(a, preparation.allocator(), &plan, reference, .{ .lanes = &evaluations }, &logical);
        const provider_calls = try provider.toOwnedSlice(a);
        const value = try allocator.create(Storage);
        value.* = .{ .arena = arena, .view_value = .{ .logical = logical, .provider = provider_calls, .parent_words = parent.parentWords(), .lowering_identity = reference.authority_digest } };
        return @ptrCast(value);
    }
    pub fn view(self: *const OwnedV1) View {
        return self.storage().view_value;
    }
    pub fn deinit(self: *OwnedV1) void {
        const value: *Storage = @ptrCast(@alignCast(self));
        const allocator = value.arena.child_allocator;
        value.arena.deinit();
        allocator.destroy(value);
    }
};
fn lane(id: u32, mode: lowering.Mode, graph: air.composition_circuit.CircuitGraph) lowering.Lane {
    return .{ .circuit_id = id, .active_in = mode, .circuit_identity = graph.identity_digest, .graph = graph };
}
fn evaluation(item: lowering.Lane, values: []const QM31) lowering.Evaluation {
    return .{ .circuit_identity = item.circuit_identity, .values = values };
}
fn addExport(counts: []u32, node: u32) !void {
    if (node >= counts.len) return error.DetachedParentBoundaryMismatch;
    counts[node] = std.math.add(u32, counts[node], 1) catch return error.DetachedParentBoundaryMismatch;
}
fn compositionSource(source: air.composition_circuit.RecursionSource, verifier: u32, boundary: *const boundary_mod.OwnedV1) !bridge.Source {
    return switch (source) {
        .parent_binary_selector => .{ .fixed = QM31.one() },
        .child_kind_selector => |kind| .{ .fixed = if (kind == (if (boundary.family() == .segment) @as(air.composition_circuit.ProofKind, .segment_leaf) else .binary_node)) QM31.one() else QM31.zero() },
        .statement_word => |word| .{ .wire = .{ .circuit = BOUNDARY_IDS[verifier - 1], .node = boundary.spanNodes()[word] } },
        .sampled_value => |coordinate| .{ .verifier_input = .{ verifier, @intFromEnum(INPUT_KIND.sampled_value), coordinate.item_index, coordinate.word_index } },
        .claimed_sum, .transcript_claimed_sum => |coordinate| if (boundary.family() == .parent and coordinate.item_index >= 36 and coordinate.item_index < 39)
            .{ .fixed = QM31.zero() }
        else
            .{ .verifier_input = .{ verifier, @intFromEnum(INPUT_KIND.claimed_sum), coordinate.item_index, coordinate.word_index } },
        .public_wire_boundary => |coordinate| .{ .verifier_input = .{ verifier, @intFromEnum(INPUT_KIND.claimed_sum), prefix.BOUNDARY_CLAIM_INDEX, coordinate.word_index } },
        .relation_challenge => |coordinate| .{ .challenge = .{ verifier, air.relation_challenge_witness.AIR_EVALUATION_CHALLENGE_SCOPE, coordinate.challenge, coordinate.word_index } },
        .composition_randomness => |word| .{ .randomness = .{ verifier, @intFromEnum(RANDOM_KIND.composition_randomness), 0, word } },
        .oods_point => |word| .{ .randomness = .{ verifier, @intFromEnum(RANDOM_KIND.oods_point), 0, word } },
        .field_public_word => error.UnsupportedDetachedCompositionSource,
    };
}
fn arithmeticRows(a: std.mem.Allocator, temporary: std.mem.Allocator, plan: *const lowering.Plan, reference: lowering.Reference, evaluations: lowering.Evaluations, logical: *cohort.LogicalRowsV1) !void {
    const counts = plan.counts(.binary_node);
    const mul = air.qm31_mul_full_witness;
    const inv = air.qm31_inv_witness;
    const lin = air.linear_ops_witness;
    const buffers = lowering.InvocationBuffers{ .multiply = try temporary.alloc(mul.Invocation, counts.multiply), .inverse = try temporary.alloc(inv.Invocation, counts.inverse), .linear = try temporary.alloc(lin.Invocation, counts.linear) };
    try plan.materializeInto(reference, evaluations, .binary_node, buffers);
    // The original admitted graph remains the routing authority. Only a
    // product with one consumer can disappear inside the new row-30 AIR.
    const fused = air.qm31_mul_add_v1;
    const fusion = air.detached_arithmetic_fusion_plan;
    const opening = air.detached_opening_accumulate4_v1;
    const opening_plan = air.detached_opening_accumulation_plan;
    var opening_rows: std.ArrayList(opening.Row) = .empty;
    var mul_rows: std.ArrayList(fused.Row) = .empty;
    var lin_rows: std.ArrayList([air.linear_ops.LOGICAL_INPUT_COUNT]M31) = .empty;
    var mul_cursor: usize = 0;
    var lin_cursor: usize = 0;
    for (reference.lanes, evaluations.lanes) |item, values| {
        if (item.active_in != .binary) continue;
        var lane_scratch = std.heap.ArenaAllocator.init(temporary);
        defer lane_scratch.deinit();
        const scratch = lane_scratch.allocator();
        const uses = try scratch.alloc(u32, item.graph.nodes.len);
        _ = try lowering.computeLaneUseCountsInto(item, uses);
        const reserved = try scratch.alloc(bool, item.graph.nodes.len);
        @memset(reserved, false);
        var opening_matches: std.ArrayList(opening_plan.Match) = .empty;
        try opening_plan.reserve(&opening_matches, scratch, item.graph, uses, reserved);
        for (opening_matches.items) |match| {
            var lhs: [4]u32 = undefined;
            var rhs: [4]u32 = undefined;
            var lhs_values: [4]QM31 = undefined;
            var rhs_values: [4]QM31 = undefined;
            for (match.multiply_nodes, 0..) |node_id, index| {
                const operands = item.graph.nodes[node_id].op.mul;
                lhs[index] = operands.lhs;
                rhs[index] = operands.rhs;
                lhs_values[index] = values.values[operands.lhs];
                rhs_values[index] = values.values[operands.rhs];
            }
            try opening_rows.append(temporary, try opening.logicalRow(.{
                .circuit = item.circuit_id,
                .output = match.output_node,
                .uses = uses[match.output_node],
                .accumulator = match.accumulator_node,
                .lhs = lhs,
                .rhs = rhs,
            }, values.values[match.accumulator_node], lhs_values, rhs_values, values.values[match.output_node]));
        }
        var matches: std.ArrayList(fusion.Match) = .empty;
        try fusion.reserve(&matches, scratch, item.graph, uses, reserved);
        const by_multiply = try scratch.alloc(u32, item.graph.nodes.len);
        @memset(by_multiply, 0);
        for (matches.items, 0..) |match, index| by_multiply[match.multiply_node] = @intCast(index + 1);
        for (item.graph.nodes, 0..) |node, node_id| switch (node.op) {
            .mul => |operands| {
                const invocation = buffers.multiply[mul_cursor];
                mul_cursor += 1;
                const match: ?fusion.Match = if (by_multiply[node_id] == 0) null else matches.items[by_multiply[node_id] - 1];
                if (reserved[node_id] and match == null) continue;
                const output = if (match) |m| m.output_node else @as(u32, @intCast(node_id));
                try mul_rows.append(temporary, try fused.logicalRow(.{
                    .circuit = item.circuit_id,
                    .output = output,
                    .lhs = operands.lhs,
                    .rhs = operands.rhs,
                    .addend = if (match) |m| m.addend_node else 0,
                    .uses = uses[output],
                    .operation = if (match) |m| m.operation else .multiply,
                }, invocation.a, invocation.b, if (match) |m| values.values[m.addend_node] else QM31.zero()));
            },
            .add, .sub, .neg => {
                const invocation = buffers.linear[lin_cursor];
                const pp = plan.linear_rows[lin_cursor];
                lin_cursor += 1;
                if (!reserved[node_id]) try lin_rows.append(temporary, lin.logicalInputs(try lin.mainRow(invocation), lin.preprocessedRow(pp), .binary_node));
            },
            else => {},
        };
        std.debug.print("riscv_detached_arithmetic_fusion lane={d} dot4_rows={d} multiply_add_rows={d}\n", .{ item.circuit_id, opening_matches.items.len, matches.items.len });
    }
    if (mul_cursor != buffers.multiply.len or lin_cursor != buffers.linear.len) return error.DetachedParentArithmeticCountMismatch;
    const inv_rows = try a.alloc([air.qm31_inv.LOGICAL_INPUT_COUNT]M31, counts.inverse);
    for (inv_rows, buffers.inverse, plan.inverse_rows[0..counts.inverse]) |*row, invocation, pp| row.* = inv.logicalInputs(try inv.mainRow(invocation), inv.preprocessedRow(pp), .binary_node);
    logical[cohort.logicalIndex(14)] = try a.dupe(opening.Row, opening_rows.items);
    logical[cohort.logicalIndex(30)] = try a.dupe(fused.Row, mul_rows.items);
    logical[cohort.logicalIndex(31)] = inv_rows;
    logical[cohort.logicalIndex(32)] = try a.dupe([air.linear_ops.LOGICAL_INPUT_COUNT]M31, lin_rows.items);
}
