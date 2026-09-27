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
    var rows = try @import("air/arithmetic_fusion_rows.zig").materialize(temporary, plan, reference, evaluations, .binary_node);
    defer rows.deinit();
    logical[cohort.logicalIndex(14)] = try a.dupe(air.detached_opening_accumulate4_v1.Row, rows.opening);
    logical[cohort.logicalIndex(30)] = try a.dupe(air.qm31_mul_add_v1.Row, rows.multiply);
    logical[cohort.logicalIndex(31)] = try a.dupe(air.qm31_inv.Row, rows.inverse);
    logical[cohort.logicalIndex(32)] = try a.dupe(air.linear_ops.Row, rows.linear);
    std.debug.print("riscv_detached_arithmetic_fusion dot4_rows={d} multiply_add_rows={d}\n", .{ rows.dot4_matches, rows.fma_matches });
}
