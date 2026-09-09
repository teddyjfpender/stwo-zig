//! Isolated bridge gate; no active wrapper admission is selected here.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const helper = @import("recursive_common_ethereum_initial_input_packet_v1.zig");
const genuine = @import("recursive_common_ethereum_initial_input_lane_v1_test.zig");
const Air = helper.Air;
const Lane = Air.lane;
const arithmetic = frontend.recursion.arithmetic_circuit;
const direct = frontend.recursion.air.direct_constraint_program;
const interaction = frontend.recursion.air.relation_interaction;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Value = arithmetic.Value;
const a = std.testing.allocator;
const Memory = frontend.air.relation_challenges.RelationElements(7);
const memory = Memory.dummy();
const CIRCUIT_ID = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4.zig").CIRCUIT_ID;
const FIXED_COUNT = 8 + 4 + 18 + 4;
pub const TestGraph = struct {
    circuit: arithmetic.Circuit,
    inputs: [FIXED_COUNT + Air.INPUT_COUNT]QM31,
    packets: [Air.PACKET_COUNT][4]M31,
    preprocessing: [Air.ROW_COUNT]Air.Preprocessing,
    pub fn init(fixture: *const genuine.Fixture) !TestGraph {
        var builder = arithmetic.Builder.initDefault(a);
        defer builder.deinit();
        var values: [FIXED_COUNT + Air.INPUT_COUNT]Value = undefined;
        for (&values, 0..) |*value, index| value.* = try builder.input(@intCast(index));
        const subtotal = try helper.constrainPackets(&builder, values[FIXED_COUNT..].*, try helper.join(&builder, values[0..4].*), try helper.join(&builder, values[4..8].*), values[8..12].*, values[12..30].*);
        // Existing public memory sum consumer represented by an independent
        // native tuple-derived subtotal, not a packet-derived expected value.
        _ = try builder.markOutput(try builder.sub(subtotal, try helper.join(&builder, values[30..34].*)));
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        var result = TestGraph{ .circuit = circuit, .inputs = undefined, .packets = undefined, .preprocessing = try Air.preprocessing(try Lane.Shape.init(40), &circuit, CIRCUIT_ID, FIXED_COUNT) };
        const coefficients = [_]QM31{ memory.z, memory.alpha, memory.alpha_powers[3], memory.alpha_powers[4], memory.alpha_powers[5], memory.alpha_powers[6] };
        for (coefficients, 0..) |coefficient, i| result.packets[i] = coefficient.toM31Array();
        result.packets[Lane.HEADER_SLOT] = fixture.header();
        result.packets[Lane.SUM_SLOT] = (try fixture.nativeSum()).toM31Array();
        for (Lane.PROGRAM_FIRST_SLOT..Air.PACKET_COUNT) |slot| {
            result.packets[slot] = @splat(M31.zero());
            for (0..4) |limb| {
                const index = (slot - Lane.PROGRAM_FIRST_SLOT) * 4 + limb;
                if (index < fixture.program_words.len) result.packets[slot][limb] = M31.fromCanonical(fixture.program_words[index]);
            }
        }
        for (memory.z.toM31Array(), 0..) |v, i| result.inputs[i] = QM31.fromBase(v);
        for (memory.alpha.toM31Array(), 0..) |v, i| result.inputs[4 + i] = QM31.fromBase(v);
        for (fixture.header(), 0..) |v, i| result.inputs[8 + i] = QM31.fromBase(v);
        for (fixture.program_words, 0..) |v, i| result.inputs[12 + i] = q(v);
        for ((try fixture.nativeSum()).toM31Array(), 0..) |v, i| result.inputs[30 + i] = QM31.fromBase(v);
        for (result.packets, 0..) |packet, slot| for (packet, 0..) |v, i| {
            result.inputs[FIXED_COUNT + 4 * slot + i] = QM31.fromBase(v);
        };
        var program_words: [18]M31 = undefined;
        for (&program_words, fixture.program_words) |*v, raw| v.* = M31.fromCanonical(raw);
        const witness = helper.witnessWords(memory.z, memory.alpha, fixture.header(), try fixture.nativeSum(), program_words);
        for (witness, result.inputs[FIXED_COUNT..]) |word, expected| try std.testing.expect(QM31.fromBase(word).eql(expected));
        return result;
    }
    pub fn rows(self: *const TestGraph) [Air.ROW_COUNT]Air.Row {
        var result: [Air.ROW_COUNT]Air.Row = undefined;
        for (&result, self.preprocessing, 0..) |*row, p, i| row.* = Air.row(p, if (i < Air.PACKET_COUNT) self.packets[i] else @splat(M31.zero()));
        return result;
    }
    fn passes(self: *const TestGraph, inputs: []const QM31) !bool {
        var evaluation = try self.circuit.evaluate(a, inputs);
        defer evaluation.deinit();
        for (self.circuit.outputs()) |output| if (!evaluation.values[output].isZero()) return false;
        return true;
    }
};
fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
fn packetClosure(lane_plan: *const Lane.Relation.Plan, packet_plan: *const Air.Relation.Plan, lane_rows: []const Lane.Row, packet_rows: []const Air.Row) !bool {
    var ledger = interaction.TupleLedger.init(a);
    defer ledger.deinit();
    for (lane_rows) |row| for (lane_plan.preparedEntries(row)) |entry| {
        if (entry.domain == .recursion_wire and entry.values[0].eql(q(Lane.SOURCE_SCOPE))) try ledger.append(entry.domain, 36, 0, if (entry.values[1].eql(q(Lane.SUM_SLOT))) .emit else .consume, entry.numerator, entry.values[0..entry.arity]);
    };
    for (packet_rows) |row| for (packet_plan.preparedEntries(row)[0..2]) |entry| try ledger.append(entry.domain, 37, 0, .emit, entry.numerator, entry.values[0..entry.arity]);
    return ledger.classify().isClosed();
}
fn graphWireClosure(plan: *const Air.Relation.Plan, graph: *const TestGraph, rows: []const Air.Row, lane_plan: *const Lane.Relation.Plan, lane_rows: []const Lane.Row) !bool {
    const r = frontend.recursion.air;
    const lowering = r.verifier_arithmetic_lowering;
    const graph_mod = r.composition_circuit;
    const linear = r.linear_ops_witness;
    const multiply = r.qm31_mul_full_witness;
    const native_support = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
    const nodes = try a.alloc(graph_mod.Node, graph.circuit.nodes().len);
    defer a.free(nodes);
    for (nodes, graph.circuit.nodes()) |*destination, source| destination.* = native_support.graphNode(source);
    const digest = graph_mod.computeGraphDigest(nodes, graph.circuit.outputs());
    const lowered_graph = try graph_mod.CircuitGraph.authenticate(nodes, graph.circuit.outputs(), digest);
    // Shared lowering admits both proof modes. The identical binary overlay
    // is inactive in this segment-only test and contributes no tuples.
    const lanes = [_]lowering.Lane{
        .{ .circuit_id = CIRCUIT_ID, .active_in = .segment, .circuit_identity = digest, .graph = lowered_graph },
        .{ .circuit_id = CIRCUIT_ID + 1, .active_in = .binary, .circuit_identity = digest, .graph = lowered_graph },
    };
    const reference = try lowering.Reference.seal(&lanes);
    var lowered = try lowering.Plan.init(a, reference);
    defer lowered.deinit();
    var evaluated = try graph.circuit.evaluate(a, &graph.inputs);
    defer evaluated.deinit();
    const evaluations = [_]lowering.Evaluation{
        .{ .circuit_identity = digest, .values = evaluated.values },
        .{ .circuit_identity = digest, .values = evaluated.values },
    };
    const counts = lowered.counts(.segment_leaf);
    const mul_invocations = try a.alloc(multiply.Invocation, counts.multiply);
    defer a.free(mul_invocations);
    const linear_invocations = try a.alloc(linear.Invocation, counts.linear);
    defer a.free(linear_invocations);
    try std.testing.expectEqual(@as(usize, 0), counts.inverse);
    try lowered.materializeInto(reference, .{ .lanes = &evaluations }, .segment_leaf, .{ .multiply = mul_invocations, .inverse = &.{}, .linear = linear_invocations });
    var ledger = interaction.TupleLedger.init(a);
    defer ledger.deinit();
    const wire_mask = @as(u64, 1) << @intFromEnum(frontend.air.relation.Domain.recursion_wire);
    try lane_plan.appendPreparedTupleContributions(&ledger, 36, lane_rows, wire_mask);
    try plan.appendPreparedTupleContributions(&ledger, 37, rows, wire_mask);
    // Consume the scalar wires through the actual shared arithmetic AIR rows,
    // including intermediate values, constants, and the graph's zero outputs.
    var mul_definition = try r.qm31_mul_full.build(a, .generated);
    defer mul_definition.deinit();
    const MulRelation = r.universal_relation_binding.Binding(r.qm31_mul_full);
    const mul_plan = try MulRelation.authenticate(&mul_definition);
    const mul_direct = try direct.authenticate(&mul_definition.arena, r.qm31_mul_full.SEMANTIC_DIGEST, r.qm31_mul_full.LOGICAL_INPUT_COUNT);
    for (mul_invocations, lowered.multiply_rows[0..counts.multiply]) |invocation, p| {
        const row = multiply.logicalInputs(multiply.mainRow(invocation), multiply.preprocessedRow(p), .segment_leaf);
        try checkDirect(r.qm31_mul_full, &mul_direct, row);
        try mul_plan.appendPreparedTupleContributions(&ledger, 30, &.{row}, std.math.maxInt(u64));
    }
    var linear_definition = try r.linear_ops.build(a, .generated);
    defer linear_definition.deinit();
    const LinearRelation = r.universal_relation_binding.Binding(r.linear_ops);
    const linear_plan = try LinearRelation.authenticate(&linear_definition);
    const linear_direct = try direct.authenticate(&linear_definition.arena, r.linear_ops.SEMANTIC_DIGEST, r.linear_ops.LOGICAL_INPUT_COUNT);
    for (linear_invocations, lowered.linear_rows[0..counts.linear]) |invocation, p| {
        const row = linear.logicalInputs(try linear.mainRow(invocation), linear.preprocessedRow(p), .segment_leaf);
        try checkDirect(r.linear_ops, &linear_direct, row);
        try linear_plan.appendPreparedTupleContributions(&ledger, 32, &.{row}, std.math.maxInt(u64));
    }
    for (lowered.public_terms) |term| {
        if (term.active_in != .segment) continue;
        const limbs = term.value.toM31Array();
        const weight = q(term.multiplicity);
        try ledger.append(.recursion_wire, 42, 0, term.role, if (term.role == .consume) weight.neg() else weight, &.{ q(term.circuit_id), q(term.node_id), QM31.fromBase(limbs[0]), QM31.fromBase(limbs[1]), QM31.fromBase(limbs[2]), QM31.fromBase(limbs[3]) });
    }
    // Existing authenticated z/alpha/header/program/native subtotal endpoints
    // remain explicit test inputs; production must keep their existing owners.
    for (0..FIXED_COUNT) |input| {
        const node = graph.circuit.inputNodes()[input];
        const uses = try graph.circuit.inputUseCount(@intCast(input));
        const value = graph.inputs[input].toM31Array();
        try ledger.append(.recursion_wire, 16, 0, .emit, q(uses), &.{ q(CIRCUIT_ID), q(node), QM31.fromBase(value[0]), QM31.fromBase(value[1]), QM31.fromBase(value[2]), QM31.fromBase(value[3]) });
    }
    return ledger.classify().isClosed();
}
fn checkDirect(comptime Component: type, program: *const direct.Program, row: [Component.LOGICAL_INPUT_COUNT]M31) !void {
    var scratch: [direct.MAX_NODES]M31 = undefined;
    var roots: [Component.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try program.evaluateBaseInto(&row, &scratch, &roots);
    for (roots) |value| try std.testing.expect(value.isZero());
}
test "Ethereum initial input packet authenticates semantic seal and fixed graph routes" {
    const identity = try Air.semanticIdentity(a);
    std.debug.print("ETHEREUM_INITIAL_INPUT_PACKET_SEAL={s}\n", .{std.fmt.bytesToHex(identity.bytes, .lower)});
    try std.testing.expectEqualStrings(Air.SEMANTIC_DIGEST_HEX, &std.fmt.bytesToHex(identity.bytes, .lower));
    var definition = try Air.build(a);
    defer definition.deinit();
    _ = try Air.Relation.authenticate(&definition);
    const fixture = try genuine.Fixture.init();
    var graph = try TestGraph.init(&fixture);
    defer graph.circuit.deinit();
    try std.testing.expect(try graph.passes(&graph.inputs));
    for (graph.preprocessing[0..Air.PACKET_COUNT], 0..) |p, slot| {
        try std.testing.expectEqual(@as(u32, @intCast(slot)), p[1].toU32());
        try std.testing.expectEqual(@as(u32, @intFromBool(slot == Lane.SUM_SLOT)), p[3].toU32());
        for (0..4) |limb| {
            const input: u32 = @intCast(FIXED_COUNT + slot * 4 + limb);
            try std.testing.expectEqual(graph.circuit.inputNodes()[input], p[5 + limb].toU32());
            try std.testing.expectEqual(try graph.circuit.inputUseCount(input), p[9 + limb].toU32());
        }
    }
    const large = try Air.preprocessing(try Lane.Shape.init(675173), &graph.circuit, CIRCUIT_ID, FIXED_COUNT);
    try std.testing.expectEqual(@as(u32, 1048575), large[0][2].toU32());
    try std.testing.expectEqual(@as(u32, 1048576), large[6][2].toU32());
    try std.testing.expectError(error.InvalidEthereumInitialInputPacketPlan, Air.preprocessing(try Lane.Shape.init(40), &graph.circuit, CIRCUIT_ID, FIXED_COUNT + 1));
    definition.events[1] = definition.events[0];
    try std.testing.expectError(error.InvalidEthereumInitialInputPacketAir, Air.Relation.authenticate(&definition));
}
test "Ethereum initial input packet binds every scalar to genuine lane and graph" {
    const fixture = try genuine.Fixture.init();
    var graph = try TestGraph.init(&fixture);
    defer graph.circuit.deinit();
    var definition = try Air.build(a);
    defer definition.deinit();
    const plan = try Air.Relation.authenticate(&definition);
    var lane_definition = try Lane.build(a);
    defer lane_definition.deinit();
    const lane_plan = try Lane.Relation.authenticate(&lane_definition);
    const rows = graph.rows();
    try std.testing.expect(try packetClosure(&lane_plan, &plan, &fixture.rows, &rows));
    try std.testing.expect(try graphWireClosure(&plan, &graph, &rows, &lane_plan, &fixture.rows));
    const roots = try direct.authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT);
    for (rows) |row| {
        var scratch: [direct.MAX_NODES]M31 = undefined;
        var outputs: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
        try roots.evaluateBaseInto(&row, &scratch, &outputs);
        for (outputs) |value| try std.testing.expect(value.isZero());
    }
    // Every packet scalar, including subtotal and final zero padding, has an
    // actual graph equation; no packet is accepted merely by a local emitter.
    for (0..Air.INPUT_COUNT) |i| {
        var changed = graph.inputs;
        changed[FIXED_COUNT + i] = changed[FIXED_COUNT + i].add(QM31.one());
        try std.testing.expect(!try graph.passes(&changed));
        var changed_rows = rows;
        changed_rows[i / 4][i % 4] = changed_rows[i / 4][i % 4].add(M31.one());
        try std.testing.expect(!try packetClosure(&lane_plan, &plan, &fixture.rows, &changed_rows));
        try std.testing.expect(!try graphWireClosure(&plan, &graph, &changed_rows, &lane_plan, &fixture.rows));
    }
    // Fixed circuit/source coordinates and multiplicity cannot be selected
    // by the packet witness or erased while retaining its graph input.
    for ([_]usize{ 8, 9, 13 }) |column| {
        var wrong_source = rows;
        wrong_source[0][column] = wrong_source[0][column].add(M31.one());
        try std.testing.expect(!try graphWireClosure(&plan, &graph, &wrong_source, &lane_plan, &fixture.rows));
    }
    var bypass = rows;
    bypass[0][4] = M31.zero();
    var bypass_scratch: [direct.MAX_NODES]M31 = undefined;
    var bypass_outputs: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try roots.evaluateBaseInto(&bypass[0], &bypass_scratch, &bypass_outputs);
    var rejected = false;
    for (bypass_outputs) |value| rejected = rejected or !value.isZero();
    try std.testing.expect(rejected);
    var missing = rows;
    missing[0] = @splat(M31.zero());
    try std.testing.expect(!try packetClosure(&lane_plan, &plan, &fixture.rows, &missing));
    var wrong_slot = rows;
    wrong_slot[0][5] = M31.one();
    try std.testing.expect(!try packetClosure(&lane_plan, &plan, &fixture.rows, &wrong_slot));
}
