const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const bridge = air.detached_graph_input_v1;
const poseidon = air.detached_poseidon_graph_v1;

test "SegmentV2 detached routing preserves exact source and graph export multiplicities" {
    const a = std.testing.allocator;
    const input_digest = try bridge.computeSemanticDigest(a);
    const poseidon_digest = try poseidon.computeSemanticDigest(a);
    std.debug.print("detached routing input={x} poseidon={x}\n", .{ input_digest, poseidon_digest });
    try std.testing.expectEqualSlices(u8, &bridge.SEMANTIC_DIGEST, &input_digest);
    try std.testing.expectEqualSlices(u8, &poseidon.SEMANTIC_DIGEST, &poseidon_digest);
    const kinds = [_]bridge.Source{
        .{ .verifier_input = .{ 1, 2, 3, 0 } },
        .{ .challenge = .{ 1, 7, 9, 2 } },
        .{ .randomness = .{ 2, 1, 0, 3 } },
        .{ .wire = .{ .circuit = 41, .node = 19 } },
        .{ .statement = .{ .scope = 3, .word = 411 } },
        .{ .fixed = felt(13) },
        .private,
    };
    for (kinds) |source| {
        const row = try bridge.logicalRow(.{ .circuit = 42, .node = 7, .uses = 3 }, source, felt(13));
        try checkDirect(bridge, row);
        var ledger = air.relation_interaction.TupleLedger.init(a);
        defer ledger.deinit();
        try appendRow(bridge, row, &ledger);
        try ledger.append(.recursion_wire, 30, 0, .consume, felt(3).neg(), &.{ felt(42), felt(7), felt(13), felt(0), felt(0), felt(0) });
        const domain: ?frontend.air.relation.Domain = switch (source) {
            .verifier_input => .recursion_verifier_input_word,
            .challenge => .recursion_relation_challenge_word,
            .randomness => .recursion_verifier_randomness_word,
            .wire => .recursion_wire,
            .statement => .recursion_statement_word,
            .fixed, .private => null,
        };
        if (domain) |d| switch (source) {
            .verifier_input, .challenge, .randomness => |coords| try ledger.append(d, 5, 0, .emit, felt(1), &.{ felt(coords[0]), felt(coords[1]), felt(coords[2]), felt(coords[3]), felt(13) }),
            .wire => |coord| try ledger.append(d, 30, 0, .emit, felt(1), &.{ felt(coord.circuit), felt(coord.node), felt(13), felt(0), felt(0), felt(0) }),
            .statement => |coord| try ledger.append(d, 0, 0, .emit, felt(1), &.{ felt(coord.scope), felt(coord.word), felt(13) }),
            else => unreachable,
        };
        try std.testing.expect(ledger.classify().isClosed());
        var changed = row;
        changed[1] = M31.fromCanonical(14);
        // Replace one honest row; retain independently supplied endpoints.
        try removeRow(bridge, row, &ledger);
        try appendRow(bridge, changed, &ledger);
        try std.testing.expect(!ledger.classify().isClosed());
        if (source == .fixed) try std.testing.expectError(error.RoutingConstraintMismatch, checkDirect(bridge, changed));
        if (source != .private and source != .wire and source != .fixed) {
            changed = row;
            changed[2] = M31.one();
            try std.testing.expectError(error.RoutingConstraintMismatch, checkDirect(bridge, changed));
        }
    }
    try checkExports();
    try checkPoseidonRouting();
    std.debug.print("detached routing source_kinds=7 changed_value_rejected=true scalar_extension_rejected=true exact_exports=true poseidon_words=32 changed_provider_output_rejected=true changed_fanout_rejected=true\n", .{});
}

fn checkPoseidonRouting() !void {
    const allocator = std.testing.allocator;
    var words: [32]M31 = undefined;
    for (words[0..16], 0..) |*word, index| word.* = M31.fromCanonical(@intCast(index + 17));
    var state = words[0..16].*;
    frontend.air.memory_commitment.poseidon2.permute(&state);
    words[16..32].* = state;
    var nodes: [32]u32 = undefined;
    var uses: [32]u32 = undefined;
    for (&nodes, &uses, 0..) |*node, *count, index| {
        node.* = @intCast(index);
        count.* = @intCast(1 + index % 3);
    }
    const row = try poseidon.logicalRow(73, nodes, uses, words);
    try checkDirect(poseidon, row);
    var ledger = air.relation_interaction.TupleLedger.init(allocator);
    defer ledger.deinit();
    try appendRow(poseidon, row, &ledger);
    var provider_tuple: [32]QM31 = undefined;
    for (&provider_tuple, words) |*value, word| value.* = QM31.fromBase(word);
    try ledger.append(.poseidon2_io, 34, 0, .emit, QM31.one(), &provider_tuple);
    for (nodes, uses, words) |node, count, word|
        try ledger.append(.recursion_wire, 30, 0, .consume, felt(count).neg(), &.{ felt(73), felt(node), QM31.fromBase(word), felt(0), felt(0), felt(0) });
    try std.testing.expect(ledger.classify().isClosed());

    var changed = row;
    changed[1 + 16] = changed[1 + 16].add(M31.one());
    // The honest provider and graph consumers stay fixed. An unconstrained
    // output hint must fail lookup closure even though local row shape is valid.
    try checkDirect(poseidon, changed);
    try removeRow(poseidon, row, &ledger);
    try appendRow(poseidon, changed, &ledger);
    try std.testing.expect(!ledger.classify().isClosed());
    try removeRow(poseidon, changed, &ledger);
    try appendRow(poseidon, row, &ledger);
    try std.testing.expect(ledger.classify().isClosed());

    changed = row;
    const first_use = poseidon.PHYSICAL_MAIN_COLUMN_COUNT + 2 + nodes.len;
    changed[first_use] = changed[first_use].add(M31.one());
    try removeRow(poseidon, row, &ledger);
    try appendRow(poseidon, changed, &ledger);
    try std.testing.expect(!ledger.classify().isClosed());
}

fn felt(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
fn checkDirect(comptime Air: type, row: Air.Row) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const direct = air.direct_constraint_program;
    const compiled = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try compiled.evaluateBaseInto(&row, &scratch, &roots);
    for (roots) |root| if (!root.isZero()) return error.RoutingConstraintMismatch;
}
fn appendRow(comptime Air: type, row: Air.Row, ledger: *air.relation_interaction.TupleLedger) !void {
    try recordRow(Air, row, ledger, false);
}
fn removeRow(comptime Air: type, row: Air.Row, ledger: *air.relation_interaction.TupleLedger) !void {
    try recordRow(Air, row, ledger, true);
}
fn recordRow(comptime Air: type, row: Air.Row, ledger: *air.relation_interaction.TupleLedger, negate: bool) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const Binding = air.universal_relation_binding.Binding(Air);
    const relations = try Binding.authenticate(&definition);
    for (try relations.entries(&definition.arena, Air.SEMANTIC_DIGEST, Binding.events(&definition), row)) |entry|
        try ledger.append(entry.domain, 11, entry.ordinal, entry.role, if (negate) entry.numerator.neg() else entry.numerator, entry.values[0..entry.arity]);
}
fn checkExports() !void {
    const a = std.testing.allocator;
    const recorder = air.composition_graph_recorder;
    var builder = recorder.Builder.init(a);
    defer builder.deinit();
    const input = try builder.input();
    try builder.activate();
    const doubled = input.value.mul(recorder.Scalar.fromSecure(felt(2)));
    try builder.constrainZero(doubled.sub(recorder.Scalar.fromSecure(felt(6))));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const lowering = air.verifier_arithmetic_lowering;
    const exports = [_]lowering.Export{.{ .node_id = input.node_id, .uses = 2 }};
    var lanes = [_]lowering.Lane{
        .{ .circuit_id = 1, .active_in = .segment, .circuit_identity = circuit.graph().identity_digest, .graph = circuit.graph() },
        .{ .circuit_id = 2, .active_in = .binary, .circuit_identity = circuit.graph().identity_digest, .graph = circuit.graph() },
    };
    const original = try lowering.Reference.seal(&lanes);
    var plain = try lowering.Plan.init(a, original);
    defer plain.deinit();
    lanes[1].exports = &exports;
    const exported = try lowering.Reference.seal(&lanes);
    try std.testing.expect(!std.mem.eql(u8, &original.authority_digest, &exported.authority_digest));
    var plan = try lowering.Plan.init(a, exported);
    defer plan.deinit();
    try plan.validateAgainstAuthority(a, exported);
    const scratch = try a.alloc(u32, circuit.nodes.len);
    defer a.free(scratch);
    const uses = try lowering.computeLaneUseCountsInto(lanes[1], scratch);
    try std.testing.expectEqual(@as(u32, 3), uses[input.node_id]);
    lanes[1].exports = &.{};
    const restored = try lowering.Reference.seal(&lanes);
    try std.testing.expectEqualSlices(u8, &original.authority_digest, &restored.authority_digest);
    try plain.validateAgainstAuthority(a, restored);
    try std.testing.expectError(error.AuthorityMismatch, plan.validateAgainst(restored));
    const invalid = [_]lowering.Export{.{ .node_id = input.node_id, .uses = 0 }};
    lanes[1].exports = &invalid;
    try std.testing.expectError(error.InvalidPublicAnchor, lowering.Reference.seal(&lanes));
    const duplicate = [_]lowering.Export{ exports[0], exports[0] };
    lanes[1].exports = &duplicate;
    try std.testing.expectError(error.InvalidPublicAnchor, lowering.Reference.seal(&lanes));
    const outside = [_]lowering.Export{.{ .node_id = @intCast(circuit.nodes.len), .uses = 1 }};
    lanes[1].exports = &outside;
    try std.testing.expectError(error.InvalidPublicAnchor, lowering.Reference.seal(&lanes));
    const extra_read = [_]lowering.Export{.{ .node_id = input.node_id, .uses = 3 }};
    lanes[1].exports = &extra_read;
    const changed_count = try lowering.Reference.seal(&lanes);
    try std.testing.expectError(error.AuthorityMismatch, plan.validateAgainst(changed_count));
    const changed_uses = try lowering.computeLaneUseCountsInto(lanes[1], scratch);
    try std.testing.expectEqual(@as(u32, 4), changed_uses[input.node_id]);
}
