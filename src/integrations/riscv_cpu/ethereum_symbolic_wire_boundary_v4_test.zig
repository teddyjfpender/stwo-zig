//! Native/symbolic parity for the admitted arithmetic constant/output boundary.
const std = @import("std");
const core = @import("stwo_core");
const air = @import("stwo_riscv_frontend").recursion.air;
const native = @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
const recorder = air.composition_graph_recorder;
const lowering = air.verifier_arithmetic_lowering;
const graph_mod = air.composition_circuit;
const universal = air.universal_challenges;
const QM31 = core.fields.qm31.QM31;

const nodes = [_]graph_mod.Node{
    .{ .op = .input },
    .{ .op = .{ .constant = .{ 3, 4, 5, 6 } } },
    .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } },
    .{ .op = .{ .add = .{ .lhs = 2, .rhs = 1 } } },
    .{ .op = .{ .sub = .{ .lhs = 3, .rhs = 3 } } },
    .{ .op = .{ .constant = .{ 99, 0, 0, 0 } } }, // unused: no boundary
};
const outputs = [_]u32{4};

fn graph(output_nodes: []const u32) graph_mod.CircuitGraph {
    return .{ .nodes = &nodes, .outputs = output_nodes, .identity_digest = graph_mod.computeGraphDigest(&nodes, output_nodes) };
}

fn lanesFor(circuit: graph_mod.CircuitGraph) [2]lowering.Lane {
    return .{
        .{ .circuit_id = 41, .active_in = .segment, .circuit_identity = circuit.identity_digest, .graph = circuit },
        .{ .circuit_id = 42, .active_in = .binary, .circuit_identity = circuit.identity_digest, .graph = circuit },
    };
}

fn record(plan: *const lowering.Plan, reference: lowering.Reference) !recorder.Circuit {
    var builder = recorder.Builder.init(std.testing.allocator);
    defer builder.deinit();
    var draws: [universal.RELATION_COUNT][2]recorder.Scalar = undefined;
    for (&draws) |*pair| for (pair) |*value| {
        value.* = (try builder.input()).value;
    };
    const expected = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const challenges = try recorder.ChallengeSet.init(draws);
    try builder.constrainZero((try native.recordAdmittedPublicWireBoundary(plan, reference, &challenges)).sub(expected));
    try builder.check();
    builder.deactivate();
    return builder.finish();
}

fn inputsFor(relations: *const universal.UniversalRelations, claim: QM31) [2 * universal.RELATION_COUNT + 1]QM31 {
    var inputs: [2 * universal.RELATION_COUNT + 1]QM31 = undefined;
    for (relations.elements, 0..) |element, index| {
        inputs[2 * index] = element.z;
        inputs[2 * index + 1] = element.alpha;
    }
    inputs[inputs.len - 1] = claim;
    return inputs;
}

test "Ethereum symbolic wire boundary matches native constants outputs and changed challenges" {
    const lanes = lanesFor(graph(&outputs));
    const reference = try lowering.Reference.seal(&lanes);
    var plan = try lowering.Plan.init(std.testing.allocator, reference);
    defer plan.deinit();
    try plan.validateAgainstAuthority(std.testing.allocator, reference);
    // Each mode has exactly one used constant (+2) and one zero output (-1).
    // Dynamic input node 0 and unused constant node 5 contribute no anchor.
    try std.testing.expectEqual(@as(usize, 4), plan.public_terms.len);
    try std.testing.expectEqual(@as(u32, 2), plan.public_terms[0].multiplicity);
    try std.testing.expectEqual(@as(u32, 4), plan.public_terms[1].node_id);
    try std.testing.expectEqual(.consume, plan.public_terms[1].role);
    try std.testing.expect(plan.public_terms[1].value.isZero());
    var circuit = try record(&plan, reference);
    defer circuit.deinit();
    var again = try record(&plan, reference);
    defer again.deinit();
    try std.testing.expectEqualSlices(u8, &circuit.identity_digest, &again.identity_digest);
    const values = try std.testing.allocator.alloc(QM31, circuit.nodes.len);
    defer std.testing.allocator.free(values);
    var relations = universal.UniversalRelations.dummy();
    const wire_domain: @FieldType(air.relation_interaction.TupleContribution, "domain") = .recursion_wire;
    const wire_index: usize = @intFromEnum(wire_domain);
    var first_claim: ?QM31 = null;
    for (0..2) |_| {
        const claim = try plan.publicBoundaryClaim(.segment_leaf, &relations);
        if (first_claim) |previous| try std.testing.expect(!claim.eql(previous)) else first_claim = claim;
        var inputs = inputsFor(&relations, claim);
        try circuit.evaluateInto(&inputs, values);
        for ([_]usize{ 2 * wire_index, 2 * wire_index + 1, inputs.len - 1 }) |index| {
            const saved = inputs[index];
            inputs[index] = saved.add(QM31.one());
            try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&inputs, values));
            inputs[index] = saved;
        }
        relations.elements[wire_index].z = relations.elements[wire_index].z.add(QM31.one());
    }
}

test "Ethereum symbolic wire boundary rejects changed admitted terms and output authority" {
    const lanes = lanesFor(graph(&outputs));
    const reference = try lowering.Reference.seal(&lanes);
    var plan = try lowering.Plan.init(std.testing.allocator, reference);
    defer plan.deinit();
    const original = plan.public_terms[1];
    plan.public_terms[1].value = QM31.one();
    try std.testing.expectError(error.AuthorityMismatch, record(&plan, reference));
    plan.public_terms[1] = original;
    plan.public_terms[1].node_id += 1;
    try std.testing.expectError(error.AuthorityMismatch, record(&plan, reference));
    plan.public_terms[1] = original;
    plan.public_terms[1].role = .emit;
    try std.testing.expectError(error.AuthorityMismatch, record(&plan, reference));
    plan.public_terms[1] = original;
    plan.public_terms[0].multiplicity += 1;
    try std.testing.expectError(error.AuthorityMismatch, record(&plan, reference));
    plan.public_terms[0].multiplicity -= 1;

    // A separately sealed different output schedule is a different authority,
    // never a same-profile witness change. The original plan rejects it.
    const changed_outputs = [_]u32{3};
    const changed_lanes = lanesFor(graph(&changed_outputs));
    const changed_reference = try lowering.Reference.seal(&changed_lanes);
    try std.testing.expectError(error.AuthorityMismatch, record(&plan, changed_reference));
    var changed_plan = try lowering.Plan.init(std.testing.allocator, changed_reference);
    defer changed_plan.deinit();
    var first_circuit = try record(&plan, reference);
    defer first_circuit.deinit();
    var second_circuit = try record(&changed_plan, changed_reference);
    defer second_circuit.deinit();
    try std.testing.expect(!std.mem.eql(u8, &first_circuit.identity_digest, &second_circuit.identity_digest));
    const relations = universal.UniversalRelations.dummy();
    try std.testing.expect(!(try plan.publicBoundaryClaim(.segment_leaf, &relations)).eql(try changed_plan.publicBoundaryClaim(.segment_leaf, &relations)));
}
