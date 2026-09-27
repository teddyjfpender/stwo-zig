const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const lang = @import("../../air/lang/mod.zig");
const air = @import("detached_opening_accumulate4_v1.zig");
const support = @import("test_support.zig");
const graph = @import("composition_circuit.zig");
const fusion = @import("detached_opening_accumulation_plan.zig");
const binding = @import("universal_relation_binding.zig").Binding(air);
const lowering = @import("verifier_arithmetic_lowering.zig");

const schedule = air.Schedule{ .circuit = 412, .accumulator = 0, .lhs = .{ 1, 3, 5, 7 }, .rhs = .{ 2, 4, 6, 8 }, .output = 16, .uses = 3 };

test "opening accumulation has a pinned degree-two typed definition" {
    const actual = try air.computeSemanticDigest(std.testing.allocator);
    if (!std.mem.eql(u8, &actual, &air.SEMANTIC_DIGEST)) std.debug.print("OPENING_ACCUMULATE4_SEMANTIC_DIGEST={s}\n", .{std.fmt.bytesToHex(actual, .lower)});
    try std.testing.expectEqualSlices(u8, &air.SEMANTIC_DIGEST, &actual);
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    var degrees = try lang.degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(u32, 2), degrees.maximumConstraintDegree());
    _ = try binding.authenticate(&definition);
}

test "opening accumulation matches native QM31 dot products and rejects every coordinate mutation" {
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    for (0..12) |case| {
        const seed: u32 = @intCast(case * 41);
        const accumulator = QM31.fromU32Unchecked(seed + 2, seed + 3, seed + 5, seed + 7);
        var lhs: [4]QM31 = undefined;
        var rhs: [4]QM31 = undefined;
        var expected = accumulator;
        for (&lhs, &rhs, 0..) |*left, *right, term| {
            const offset: u32 = seed + @as(u32, @intCast(term * 13));
            left.* = QM31.fromU32Unchecked(offset + 11, offset + 13, offset + 17, offset + 19);
            right.* = QM31.fromU32Unchecked(offset + 23, offset + 29, offset + 31, offset + 37);
            expected = expected.add(left.mul(right.*));
        }
        const row = try air.logicalRow(schedule, accumulator, lhs, rhs, expected);
        try expectSatisfied(&definition, row, true);
        // Every main coordinate participates in an actual AIR relation; no
        // host recomputation or "verification succeeded" advice is admitted.
        for (0..air.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
            var changed = row;
            changed[column] = changed[column].add(M31.one());
            try expectSatisfied(&definition, changed, false);
        }
        const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
        defer std.testing.allocator.free(values);
        for (definition.events, 0..) |event_id, i| {
            const event = definition.arena.effect(event_id).?;
            const tuple = definition.arena.effectValues(event_id).?;
            try std.testing.expectEqual(@as(usize, 6), tuple.len);
            try std.testing.expectEqual(schedule.circuit, values[lang.types.idIndex(tuple[0])].toU32());
            const expected_node = if (i == 0) schedule.accumulator else if (i == 9) schedule.output else if (i % 2 == 1) schedule.lhs[(i - 1) / 2] else schedule.rhs[(i - 2) / 2];
            try std.testing.expectEqual(expected_node, values[lang.types.idIndex(tuple[1])].toU32());
            try std.testing.expectEqual(if (i == 9) @as(u32, 3) else @as(u32, 1), values[lang.types.idIndex(event.liveness.?)].toU32());
        }
    }
    const padding: air.Row = @splat(M31.zero());
    try expectSatisfied(&definition, padding, true);
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &padding);
    defer std.testing.allocator.free(values);
    for (definition.events) |id| try std.testing.expect(values[lang.types.idIndex(definition.arena.effect(id).?.liveness.?)].isZero());
}

fn expectSatisfied(definition: *const air.Definition, row: air.Row, expected: bool) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &row);
    defer std.testing.allocator.free(values);
    var valid = true;
    for (definition.constraints, 0..) |_, index| valid = valid and support.constraintAt(&definition.arena, &definition.constraints, values, index).isZero();
    try std.testing.expectEqual(expected, valid);
}

fn fixture() [17]graph.Node {
    return chainFixture(4);
}
fn chainFixture(comptime terms: usize) [1 + 4 * terms]graph.Node {
    var nodes: [1 + 4 * terms]graph.Node = undefined;
    const input_count = 1 + 2 * terms;
    for (nodes[0..input_count]) |*node| node.* = .{ .op = .input };
    for (0..terms) |term| {
        const multiply: u32 = @intCast(input_count + term * 2);
        nodes[multiply] = .{ .op = .{ .mul = .{ .lhs = @intCast(1 + term * 2), .rhs = @intCast(2 + term * 2) } } };
        nodes[multiply + 1] = .{ .op = .{ .add = .{ .lhs = if (term == 0) 0 else multiply - 1, .rhs = multiply } } };
    }
    return nodes;
}
fn graphFor(nodes: []const graph.Node) !graph.CircuitGraph {
    return graph.CircuitGraph.authenticate(nodes, &.{16}, graph.computeGraphDigest(nodes, &.{16}));
}

test "opening matcher hides only four unshared multiply-add terms and retains external uses" {
    var nodes = fixture();
    const g = try graphFor(&nodes);
    var uses: [17]u32 = @splat(1);
    var reserved: [17]bool = @splat(false);
    const matched = fusion.matchAt(g, &uses, &reserved, 16).?;
    try std.testing.expectEqualSlices(u32, &.{ 9, 11, 13, 15 }, &matched.multiply_nodes);
    try std.testing.expectEqualSlices(u32, &.{ 10, 12, 14, 16 }, &matched.add_nodes);
    try std.testing.expectEqual(@as(u32, 0), matched.accumulator_node);
    var matches: std.ArrayList(fusion.Match) = .empty;
    defer matches.deinit(std.testing.allocator);
    try fusion.reserve(&matches, std.testing.allocator, g, &uses, &reserved);
    try std.testing.expectEqual(@as(usize, 1), matches.items.len);
    for (reserved[0..9]) |value| try std.testing.expect(!value);
    for (reserved[9..]) |value| try std.testing.expect(value);
    // Every extra graph consumer/export prevents hiding that intermediate.
    for (9..16) |internal| {
        @memset(&reserved, false);
        uses[internal] += 1;
        try std.testing.expect(fusion.matchAt(g, &uses, &reserved, 16) == null);
        uses[internal] -= 1;
        reserved[internal] = true;
        try std.testing.expect(fusion.matchAt(g, &uses, &reserved, 16) == null);
    }
    @memset(&reserved, false);
    uses[16] = 0;
    try std.testing.expect(fusion.matchAt(g, &uses, &reserved, 16) == null);
    uses[16] = 3; // Outputs remain published at the full authenticated fan-out.
    try std.testing.expect(fusion.matchAt(g, &uses, &reserved, 16) != null);
    const changed_operands = nodes[12].op.add;
    nodes[12].op = .{ .sub = changed_operands };
    try std.testing.expect(fusion.matchAt(try graphFor(&nodes), &uses, &reserved, 16) == null);
}

fn admittedUses(g: graph.CircuitGraph, exports: []const lowering.Export, scratch: []u32) !void {
    _ = try lowering.computeLaneUseCountsInto(.{ .circuit_id = 412, .active_in = .binary, .circuit_identity = g.identity_digest, .graph = g, .exports = exports }, scratch);
}

test "opening matcher obeys actual graph consumers and authenticated exports" {
    var nodes = fixture();
    var uses: [17]u32 = undefined;
    const reserved: [17]bool = @splat(false);
    const original = try graphFor(&nodes);
    try admittedUses(original, &.{}, &uses);
    try std.testing.expect(fusion.matchAt(original, &uses, &reserved, 16) != null);
    for (9..16) |internal| {
        try admittedUses(original, &.{.{ .node_id = @intCast(internal), .uses = 1 }}, &uses);
        try std.testing.expect(fusion.matchAt(original, &uses, &reserved, 16) == null);
    }
    try admittedUses(original, &.{.{ .node_id = 16, .uses = 7 }}, &uses);
    try std.testing.expectEqual(@as(u32, 8), uses[16]);
    try std.testing.expect(fusion.matchAt(original, &uses, &reserved, 16) != null);
    // A later product reading an internal product makes the intermediate live.
    nodes[13].op.mul.lhs = 9;
    const shared = try graphFor(&nodes);
    try admittedUses(shared, &.{}, &uses);
    try std.testing.expectEqual(@as(u32, 2), uses[9]);
    try std.testing.expect(fusion.matchAt(shared, &uses, &reserved, 16) == null);
    nodes = fixture();
    nodes[10].op.add.lhs = 9;
    const duplicate = try graphFor(&nodes);
    try admittedUses(duplicate, &.{}, &uses);
    try std.testing.expectEqual(@as(u32, 2), uses[9]);
    try std.testing.expect(fusion.matchAt(duplicate, &uses, &reserved, 16) == null);
}

test "opening matcher composes adjacent blocks without hiding their shared boundary" {
    const nodes = chainFixture(8);
    const g = try graph.CircuitGraph.authenticate(&nodes, &.{32}, graph.computeGraphDigest(&nodes, &.{32}));
    var uses: [33]u32 = undefined;
    try admittedUses(g, &.{.{ .node_id = 32, .uses = 7 }}, &uses);
    var reserved: [33]bool = @splat(false);
    var matches: std.ArrayList(fusion.Match) = .empty;
    defer matches.deinit(std.testing.allocator);
    try fusion.reserve(&matches, std.testing.allocator, g, &uses, &reserved);
    try std.testing.expectEqual(@as(usize, 2), matches.items.len);
    try std.testing.expectEqual(@as(u32, 24), matches.items[0].output_node);
    try std.testing.expectEqual(matches.items[0].output_node, matches.items[1].accumulator_node);
    try std.testing.expectEqual(@as(u32, 1), uses[24]);
    try std.testing.expectEqual(@as(u32, 8), uses[32]);
}

const typed_component = @import("universal_typed_component.zig");
const framework = @import("framework_interaction.zig");
const manifest_mod = @import("universal_adapter_manifest.zig");
const universal = @import("universal_challenges.zig");
const mac = @import("qm31_mul_add_v1.zig");

test "fused arithmetic adapters admit cubic LogUp and close every active and padded row" {
    const lhs = [_]QM31{QM31.fromU32Unchecked(2, 3, 5, 7)} ** 4;
    const rhs = [_]QM31{QM31.fromU32Unchecked(11, 13, 17, 19)} ** 4;
    const accumulator = QM31.fromU32Unchecked(23, 29, 31, 37);
    var output = accumulator;
    for (lhs, rhs) |a, b| output = output.add(a.mul(b));
    try checkCompleteAdapter(air, .vm_public_io_hash, try air.logicalRow(schedule, accumulator, lhs, rhs, output));
    for (std.enums.values(mac.Operation)) |operation| {
        const row = try mac.logicalRow(.{ .circuit = 412, .output = 4, .lhs = 1, .rhs = 2, .addend = if (operation == .multiply) 0 else 3, .uses = 3, .operation = operation }, lhs[0], rhs[0], if (operation == .multiply) QM31.zero() else accumulator);
        try checkCompleteAdapter(mac, .qm31_mul, row);
    }
}

fn checkCompleteAdapter(comptime Air: type, comptime key: manifest_mod.ComponentKey, row: Air.Row) !void {
    const Relation = @import("universal_relation_binding.zig").Binding(Air);
    const Adapter = typed_component.Component(Air, Relation);
    const Interaction = framework.Runtime(Relation.Runtime);
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try Relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    var interaction = try Interaction.generatePrepared(std.testing.allocator, &plan, &.{row}, log_size, &relations);
    defer interaction.deinit(std.testing.allocator);
    var builder = manifest_mod.Builder{};
    const geometry = Adapter.manifestGeometry(key, log_size);
    try std.testing.expectEqual(@as(u8, 2), geometry.profiled_constraint_degree);
    try std.testing.expectEqual(@as(u8, 3), geometry.protocol_constraint_degree);
    _ = try builder.append(geometry);
    const manifest = try builder.seal();
    const component = try Adapter.init(&definition, plan, &manifest, key, log_size, .{}, &relations, interaction.claimed_sum);
    try std.testing.expectEqual(@as(u32, log_size + 1), component.maxConstraintLogDegreeBound());
    for (0..16) |logical_row| {
        const committed = framework.committedRow(logical_row, log_size);
        const previous_row = framework.committedRow((logical_row + 15) % 16, log_size);
        var current: [Air.INTERACTION_BATCH_COUNT]QM31 = undefined;
        for (&current, 0..) |*value, batch| value.* = committedSecure(Air.INTERACTION_BATCH_COUNT, &interaction.columns, batch, committed);
        const previous = committedSecure(Air.INTERACTION_BATCH_COUNT, &interaction.columns, Air.INTERACTION_BATCH_COUNT - 1, previous_row);
        const logical = if (logical_row == 0) row else @as(Air.Row, @splat(M31.zero()));
        var roots: [Adapter.CONSTRAINT_COUNT_TOTAL]QM31 = undefined;
        try component.evaluateBaseRowInto(logical, current, previous, &roots);
        for (roots) |root| try std.testing.expect(root.isZero());
        current[0] = current[0].add(QM31.one());
        try component.evaluateBaseRowInto(logical, current, previous, &roots);
        var nonzero = false;
        for (roots) |root| nonzero = nonzero or !root.isZero();
        try std.testing.expect(nonzero);
    }
}
fn committedSecure(comptime batches: usize, columns: *const [4 * batches][]M31, batch: usize, row: usize) QM31 {
    return QM31.fromM31Array(.{ columns[4 * batch][row], columns[4 * batch + 1][row], columns[4 * batch + 2][row], columns[4 * batch + 3][row] });
}
