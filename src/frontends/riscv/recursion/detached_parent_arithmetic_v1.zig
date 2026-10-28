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
const pcs_key = @import("detached_pcs_key_template_v1.zig");
const prefix = @import("detached_prefix_preparation_v1.zig");
const cohort = recursion.detached_parent_prepared_v1;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const INPUT_KIND = air.transcript_payload.VerifierInputKind;
const RANDOM_KIND = air.verifier_randomness_witness.Kind;
const fixed_arithmetic = @import("air/arithmetic_fusion_rows.zig");
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
        const reference = try referenceFromGraphs(a, children, parent);
        const lanes = reference.lanes;
        var evaluations: [10]lowering.Evaluation = undefined;
        evaluations[0] = .{ .circuit_identity = lanes[0].circuit_identity, .values = &.{QM31.zero()} };
        for (0..2) |child| {
            const i = 1 + 4 * child;
            evaluations[i] = evaluation(lanes[i], children.composition[child].evaluatedValues());
            evaluations[i + 1] = evaluation(lanes[i + 1], children.boundary[child].evaluatedValues());
            evaluations[i + 2] = evaluation(lanes[i + 2], children.pcs[child].pcsValues());
            evaluations[i + 3] = evaluation(lanes[i + 3], children.pcs[child].friValues());
        }
        evaluations[9] = evaluation(lanes[9], parent.evaluatedValues());
        // Admission/materialization scratch is not part of the immutable
        // prepared witness. Retain only the final logical rows and routing.
        var preparation = std.heap.ArenaAllocator.init(allocator);
        defer preparation.deinit();
        var plan = try lowering.Plan.init(preparation.allocator(), reference);
        const graph_rows = try graphRows(a, children, parent, reference);
        logical[cohort.logicalIndex(11)] = graph_rows.input;
        logical[cohort.logicalIndex(12)] = graph_rows.poseidon;
        var fixed_rows: std.ArrayList(air.fixed_wire_v3.Row) = .empty;
        for (plan.public_terms) |term| if (term.active_in == .binary) try fixed_rows.append(a, try air.fixed_wire_v3.logicalRow(term));
        logical[cohort.logicalIndex(13)] = try fixed_rows.toOwnedSlice(a);
        try arithmeticRows(a, preparation.allocator(), &plan, reference, .{ .lanes = &evaluations }, &logical);
        const provider_calls = graph_rows.provider;
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
const GraphRows = struct {
    input: []bridge.Row,
    poseidon: []poseidon.Row,
    provider: []recursion.segment_transcript_outer_source_v2.ProviderCall,
};

fn graphInputValue(owner: anytype, index: usize) QM31 {
    return if (comptime @hasDecl(@typeInfo(@TypeOf(owner)).pointer.child, "inputValues")) owner.inputValues()[index] else QM31.zero();
}

fn graphBoundaryValue(owner: anytype, node: u32) !M31 {
    return if (comptime @hasDecl(@typeInfo(@TypeOf(owner)).pointer.child, "evaluatedValues"))
        try owner.evaluatedValues()[node].tryIntoM31()
    else
        M31.zero();
}

fn graphRows(a: std.mem.Allocator, children: anytype, parent: anytype, reference: lowering.Reference) !GraphRows {
    const lanes = reference.lanes;
    var input_rows: std.ArrayList(bridge.Row) = .empty;
    var poseidon_rows: std.ArrayList(poseidon.Row) = .empty;
    var provider: std.ArrayList(recursion.segment_transcript_outer_source_v2.ProviderCall) = .empty;
    for (0..2) |child| {
        const i = 1 + 4 * child;
        const verifier: u32 = @intCast(child + 1);
        const composition = children.composition[child];
        const comp_uses = try a.alloc(u32, composition.graph().nodes.len);
        _ = try lowering.computeLaneUseCountsInto(lanes[i], comp_uses);
        for (composition.inputBindings(), 0..) |binding, input_index| {
            if (comp_uses[binding.node_id] == 0) continue;
            const source = try compositionSource(binding.source, verifier, children.boundary[child]);
            const value = if (comptime @hasDecl(@typeInfo(@TypeOf(composition)).pointer.child, "inputValues"))
                graphInputValue(composition, input_index)
            else switch (source) {
                .fixed => |constant| constant,
                else => QM31.zero(),
            };
            try input_rows.append(a, try bridge.logicalRow(.{ .circuit = lanes[i].circuit_id, .node = binding.node_id, .uses = comp_uses[binding.node_id] }, source, value));
        }
        const boundary = children.boundary[child];
        const boundary_uses = try a.alloc(u32, boundary.graph().nodes.len);
        _ = try lowering.computeLaneUseCountsInto(lanes[i + 1], boundary_uses);
        for (boundary.inputBindings(), 0..) |binding, input_index| {
            const value = graphInputValue(boundary, input_index);
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
                word.* = try graphBoundaryValue(boundary, node);
                count.* = boundary_uses[node];
            }
            try poseidon_rows.append(a, try poseidon.logicalRow(lanes[i + 1].circuit_id, binding.nodes, uses, words));
        }
        if (comptime @hasDecl(@typeInfo(@TypeOf(boundary)).pointer.child, "providerCalls")) try provider.appendSlice(a, boundary.providerCalls());
    }
    const parent_uses = try a.alloc(u32, parent.graph().nodes.len);
    _ = try lowering.computeLaneUseCountsInto(lanes[9], parent_uses);
    var publication_count: [recursion.span_continuation_v1.WORD_COUNT]u32 = @splat(0);
    for (parent.inputBindings(), 0..) |binding, input_index| {
        const value = graphInputValue(parent, input_index);
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
    return .{ .input = try input_rows.toOwnedSlice(a), .poseidon = try poseidon_rows.toOwnedSlice(a), .provider = try provider.toOwnedSlice(a) };
}

const DUMMY_NODES = [_]air.composition_circuit.Node{.{ .op = .{ .constant = .{ 0, 0, 0, 0 } } }};

/// Shared graph authority for evaluated parent rows and proof-free fixed rows.
/// Every lane and export is derived from symbolic child graphs, never witness
/// values. The caller owns the allocator backing the returned lane slice.
fn referenceFromGraphs(a: std.mem.Allocator, children: anytype, parent: anytype) !lowering.Reference {
    const dummy_graph = try air.composition_circuit.CircuitGraph.authenticate(&DUMMY_NODES, &.{0}, air.composition_circuit.computeGraphDigest(&DUMMY_NODES, &.{0}));
    const lanes = try a.alloc(lowering.Lane, 10);
    lanes[0] = lane(500, .segment, dummy_graph);
    var boundary_counts: [2][]u32 = undefined;
    inline for (0..2) |child| {
        const i = 1 + 4 * child;
        lanes[i] = lane(COMPOSITION_IDS[child], .binary, children.composition[child].graph());
        lanes[i + 1] = lane(BOUNDARY_IDS[child], .binary, children.boundary[child].graph());
        lanes[i + 2] = lane(@intCast(412 + child), .binary, children.pcs[child].pcsGraph());
        lanes[i + 3] = lane(@intCast(402 + child), .binary, children.pcs[child].friGraph());
        boundary_counts[child] = try a.alloc(u32, lanes[i + 1].graph.nodes.len);
        @memset(boundary_counts[child], 0);
    }
    lanes[9] = lane(PARENT_ID, .binary, parent.graph());
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
    return lowering.Reference.seal(lanes);
}

/// Build the arithmetic families' committed fixed columns without a child
/// proof, capture, expected statement, or evaluated graph value. The same
/// reference builder is used by the evaluated parent producer above.
pub const KeyFixedV1 = struct {
    allocator: std.mem.Allocator,
    input_rows: []bridge.Row,
    poseidon_rows: []poseidon.Row,
    wire_rows: []air.fixed_wire_v3.Row,
    arithmetic: fixed_arithmetic.Fixed,
    reference_identity: [32]u8,
    provider_count: usize,

    pub fn deinit(self: *KeyFixedV1) void {
        self.arithmetic.deinit();
        self.allocator.free(self.wire_rows);
        self.allocator.free(self.poseidon_rows);
        self.allocator.free(self.input_rows);
        self.* = undefined;
    }
};

pub fn fixedFromChildKeys(comptime family: @import("detached_child_capture_v1.zig").Family, allocator: std.mem.Allocator, keys: anytype, mode: @import("span_continuation_v1.zig").Mode) !KeyFixedV1 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var compositions: [2]*const composition_mod.KeyGraphV1 = undefined;
    var boundaries: [2]*const if (family == .segment) boundary_mod.SegmentKeyGraphV1 else boundary_mod.ParentKeyGraphV1 = undefined;
    var templates: [2]*const pcs_key.TemplateV1 = undefined;
    inline for (0..2) |child| {
        const composition = try a.create(composition_mod.KeyGraphV1);
        composition.* = try composition_mod.KeyGraphV1.init(family, a, keys[child]);
        compositions[child] = composition;
        const boundary_graph = if (family == .segment)
            try boundary_mod.SegmentKeyGraphV1.init(a, keys[child])
        else
            try boundary_mod.ParentKeyGraphV1.init(a, keys[child]);
        boundaries[child] = boundary_graph;
        const template = try a.create(pcs_key.TemplateV1);
        template.* = try pcs_key.TemplateV1.init(a, keys[child]);
        templates[child] = template;
    }
    const statement = if (family == .segment)
        try parent_mod.SegmentKeyGraphV1.init(a, keys[0], keys[1], mode)
    else
        try parent_mod.ParentKeyGraphV1.init(a, keys[0], keys[1], mode);
    const reference = try referenceFromGraphs(a, .{ .composition = compositions, .boundary = boundaries, .pcs = templates }, statement);
    const graph_rows = try graphRows(a, .{ .composition = compositions, .boundary = boundaries, .pcs = templates }, statement, reference);
    var plan = try lowering.Plan.init(a, reference);
    var wire_rows: std.ArrayList(air.fixed_wire_v3.Row) = .empty;
    for (plan.public_terms) |term| if (term.active_in == .binary)
        try wire_rows.append(a, try air.fixed_wire_v3.logicalRow(term));
    const owned_wire = try allocator.dupe(air.fixed_wire_v3.Row, wire_rows.items);
    errdefer allocator.free(owned_wire);
    const owned_input = try allocator.dupe(bridge.Row, graph_rows.input);
    errdefer allocator.free(owned_input);
    const owned_poseidon = try allocator.dupe(poseidon.Row, graph_rows.poseidon);
    errdefer allocator.free(owned_poseidon);
    return .{
        .allocator = allocator,
        .input_rows = owned_input,
        .poseidon_rows = owned_poseidon,
        .wire_rows = owned_wire,
        .arithmetic = try fixed_arithmetic.materializeFixed(allocator, &plan, reference, .binary_node),
        .reference_identity = reference.authority_digest,
        .provider_count = graph_rows.provider.len,
    };
}

pub fn testSegmentFixedArithmeticAgainstVerifiedChildren(allocator: std.mem.Allocator, left: *const @import("detached_child_capture_v1.zig").OwnedV1, right: *const @import("detached_child_capture_v1.zig").OwnedV1, mode: @import("span_continuation_v1.zig").Mode) !void {
    return testFixedArithmeticAgainstVerifiedChildren(.segment, allocator, left, right, mode);
}

pub fn testParentFixedArithmeticAgainstVerifiedChildren(allocator: std.mem.Allocator, left: *const @import("detached_child_capture_v1.zig").ParentOwnedV1, right: *const @import("detached_child_capture_v1.zig").ParentOwnedV1, mode: @import("span_continuation_v1.zig").Mode) !void {
    return testFixedArithmeticAgainstVerifiedChildren(.parent, allocator, left, right, mode);
}

fn testFixedArithmeticAgainstVerifiedChildren(comptime family: @import("detached_child_capture_v1.zig").Family, allocator: std.mem.Allocator, left: *const @import("detached_child_capture_v1.zig").OwnedFor(family), right: *const @import("detached_child_capture_v1.zig").OwnedFor(family), mode: @import("span_continuation_v1.zig").Mode) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const children = [_]*const @import("detached_child_capture_v1.zig").OwnedFor(family){ left, right };
    var compositions: [2]*const composition_mod.OwnedV1 = undefined;
    var boundaries: [2]*const boundary_mod.OwnedV1 = undefined;
    var checks: [2]*const pcs_mod.OwnedV1 = undefined;
    for (children, 0..) |child, index| {
        compositions[index] = try composition_mod.OwnedV1.init(a, child);
        boundaries[index] = if (family == .segment) blk: {
            const shape = try @import("detached_boundary_key_shape_v1.zig").SegmentShapeV1.init(a, child.key());
            break :blk try boundary_mod.OwnedV1.init(a, child, .{ .counts = child.key().retained_section_counts }, shape.memory);
        } else try boundary_mod.OwnedV1.initParent(a, child);
        checks[index] = try pcs_mod.OwnedV1.init(a, child, @intCast(index + 1));
    }
    const statement = if (family == .segment)
        try parent_mod.OwnedV1.initWithMode(a, boundaries[0], boundaries[1], mode)
    else
        try parent_mod.OwnedV1.initParents(a, boundaries[0], boundaries[1], mode);
    const captured = try OwnedV1.init(a, .{ .composition = compositions, .boundary = boundaries, .pcs = checks }, statement);
    const logical = captured.view().logical;
    var fixed = try fixedFromChildKeys(family, allocator, .{ left.key(), right.key() }, mode);
    defer fixed.deinit();
    try std.testing.expectEqualDeep(captured.view().lowering_identity, fixed.reference_identity);
    const projection = @import("air/blake3_row_columns.zig");
    const storage = @import("air/blake3_parent_row_storage.zig");
    try expectFixedRows(bridge, logical[cohort.logicalIndex(11)], fixed.input_rows);
    try expectFixedRows(poseidon, logical[cohort.logicalIndex(12)], fixed.poseidon_rows);
    const wire_rows = logical[cohort.logicalIndex(13)];
    try std.testing.expectEqual(wire_rows.len, fixed.wire_rows.len);
    for (wire_rows, fixed.wire_rows) |expected, actual|
        try std.testing.expectEqualDeep(storage.compactFixed(air.fixed_wire_v3, expected), storage.compactFixed(air.fixed_wire_v3, actual));
    const row_ids = [_]usize{ 14, 30, 31, 32 };
    inline for (@import("air/arithmetic_fusion_fixed_columns_v1.zig").Airs, 0..) |Air, slot| {
        const row_id = row_ids[slot];
        const rows: []const Air.Row = logical[cohort.logicalIndex(row_id)];
        try std.testing.expectEqual(fixed.arithmetic.counts[slot], rows.len);
        const compact = try a.alloc(storage.FixedRow(Air), rows.len);
        for (rows, compact) |row, *target| target.* = storage.compactFixed(Air, row);
        var expected_columns: std.ArrayList(@import("stwo_prover_engine").pcs.ColumnEvaluation) = .empty;
        defer {
            for (expected_columns.items) |column| allocator.free(column.values);
            expected_columns.deinit(allocator);
        }
        try projection.projectFixed(Air, allocator, compact, fixed.arithmetic.logs[slot], &expected_columns);
        const key_columns = fixed.arithmetic.columnRange(slot);
        try std.testing.expectEqual(key_columns.len, expected_columns.items.len);
        for (key_columns, expected_columns.items) |key_column, expected_column| {
            try std.testing.expectEqual(expected_column.log_size, key_column.log_size);
            try std.testing.expectEqualSlices(M31, expected_column.values, key_column.values);
        }
    }
}

fn expectFixedRows(comptime Air: type, expected: []const Air.Row, actual: []const Air.Row) !void {
    const storage = @import("air/blake3_parent_row_storage.zig");
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |left, right|
        try std.testing.expectEqualDeep(storage.compactFixed(Air, left), storage.compactFixed(Air, right));
}

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
fn compositionSource(source: air.composition_circuit.RecursionSource, verifier: u32, boundary: anytype) !bridge.Source {
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
