//! Multi-graph schedule, overlay, and mutation gates for shared lowering.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const graph_mod = @import("composition_circuit.zig");
const lowering = @import("verifier_arithmetic_lowering.zig");
const universal = @import("universal_challenges.zig");

test "R-012 shared arithmetic lowering concatenates graphs and overlays modes" {
    const segment_nodes = [_]graph_mod.Node{
        .{ .op = .input },
        .{ .op = .{ .constant = .{ 3, 0, 0, 0 } } },
        .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } },
        .{ .op = .{ .sub = .{ .lhs = 2, .rhs = 2 } } },
    };
    const segment_outputs = [_]u32{3};
    const segment_graph = graph_mod.CircuitGraph{
        .nodes = &segment_nodes,
        .outputs = &segment_outputs,
        .identity_digest = graph_mod.computeGraphDigest(
            &segment_nodes,
            &segment_outputs,
        ),
    };
    const binary_nodes = [_]graph_mod.Node{
        .{ .op = .input },
        .{ .op = .{ .inverse = 0 } },
        .{ .op = .{ .mul = .{ .lhs = 0, .rhs = 1 } } },
        .{ .op = .{ .constant = .{ 1, 0, 0, 0 } } },
        .{ .op = .{ .sub = .{ .lhs = 2, .rhs = 3 } } },
    };
    const binary_outputs = [_]u32{4};
    const binary_graph = graph_mod.CircuitGraph{
        .nodes = &binary_nodes,
        .outputs = &binary_outputs,
        .identity_digest = graph_mod.computeGraphDigest(
            &binary_nodes,
            &binary_outputs,
        ),
    };
    const identity_a = [_]u8{0x11} ** 32;
    const identity_b = [_]u8{0x22} ** 32;
    const identity_c = [_]u8{0x33} ** 32;
    const lanes = [_]lowering.Lane{
        .{
            .circuit_id = 10,
            .active_in = .segment,
            .circuit_identity = identity_a,
            .graph = segment_graph,
        },
        .{
            .circuit_id = 11,
            .active_in = .segment,
            .circuit_identity = identity_b,
            .graph = segment_graph,
        },
        .{
            .circuit_id = 12,
            .active_in = .binary,
            .circuit_identity = identity_c,
            .graph = binary_graph,
        },
    };
    const reference = try lowering.Reference.seal(&lanes);
    var plan = try lowering.Plan.init(std.testing.allocator, reference);
    defer plan.deinit();
    try plan.validateAgainstAuthority(std.testing.allocator, reference);

    const segment_counts = plan.counts(.segment_leaf);
    const binary_counts = plan.counts(.binary_node);
    try std.testing.expectEqual(@as(usize, 2), segment_counts.multiply);
    try std.testing.expectEqual(@as(usize, 2), segment_counts.linear);
    try std.testing.expectEqual(@as(usize, 1), binary_counts.multiply);
    try std.testing.expectEqual(@as(usize, 1), binary_counts.inverse);
    try std.testing.expect(plan.multiply_rows[0].segment != null);
    try std.testing.expect(plan.multiply_rows[0].binary != null);

    const segment_values_a = [_]QM31{
        QM31.fromBase(M31.fromCanonical(2)),
        QM31.fromBase(M31.fromCanonical(3)),
        QM31.fromBase(M31.fromCanonical(6)),
        QM31.zero(),
    };
    const segment_values_b = [_]QM31{
        QM31.fromBase(M31.fromCanonical(5)),
        QM31.fromBase(M31.fromCanonical(3)),
        QM31.fromBase(M31.fromCanonical(15)),
        QM31.zero(),
    };
    const binary_values = [_]QM31{
        QM31.fromBase(M31.fromCanonical(2)),
        QM31.fromBase(M31.fromCanonical(@as(u32, 1) << 30)),
        QM31.one(),
        QM31.one(),
        QM31.zero(),
    };
    var evaluations_storage = [_]lowering.Evaluation{
        .{ .circuit_identity = identity_a, .values = &segment_values_a },
        .{ .circuit_identity = identity_b, .values = &segment_values_b },
        .{ .circuit_identity = identity_c, .values = &binary_values },
    };
    const evaluations = lowering.Evaluations{ .lanes = &evaluations_storage };
    const relations = universal.UniversalRelations.dummy();
    const segment_input_claim = try plan.inputBoundaryClaim(
        std.testing.allocator,
        reference,
        evaluations,
        .segment_leaf,
        &relations,
    );
    const expected_segment_input = (try expectedInputClaim(
        &relations,
        10,
        0,
        segment_values_a[0],
        1,
    )).add(try expectedInputClaim(
        &relations,
        11,
        0,
        segment_values_b[0],
        1,
    ));
    try std.testing.expect(segment_input_claim.eql(expected_segment_input));
    try std.testing.expect((try plan.inputBoundaryClaim(
        std.testing.allocator,
        reference,
        evaluations,
        .binary_node,
        &relations,
    )).eql(try expectedInputClaim(
        &relations,
        12,
        0,
        binary_values[0],
        2,
    )));
    try std.testing.expect((try plan.inputBoundaryClaim(
        std.testing.allocator,
        reference,
        evaluations,
        .empty_leaf,
        &relations,
    )).isZero());

    const mutated_segment_values_a = [_]QM31{
        QM31.fromBase(M31.fromCanonical(7)),
        segment_values_a[1],
        segment_values_a[2],
        segment_values_a[3],
    };
    evaluations_storage[0].values = &mutated_segment_values_a;
    try std.testing.expect(!(try plan.inputBoundaryClaim(
        std.testing.allocator,
        reference,
        evaluations,
        .segment_leaf,
        &relations,
    )).eql(segment_input_claim));
    evaluations_storage[0].values = &segment_values_a;

    const multiply_invocations = try std.testing.allocator.alloc(
        @import("qm31_mul_full_witness.zig").Invocation,
        segment_counts.multiply,
    );
    defer std.testing.allocator.free(multiply_invocations);
    const inverse_invocations = try std.testing.allocator.alloc(
        @import("qm31_inv_witness.zig").Invocation,
        segment_counts.inverse,
    );
    defer std.testing.allocator.free(inverse_invocations);
    const linear_invocations = try std.testing.allocator.alloc(
        @import("linear_ops_witness.zig").Invocation,
        segment_counts.linear,
    );
    defer std.testing.allocator.free(linear_invocations);
    try plan.materializeInto(reference, evaluations, .segment_leaf, .{
        .multiply = multiply_invocations,
        .inverse = inverse_invocations,
        .linear = linear_invocations,
    });
    try std.testing.expectEqual(
        @as(u32, 10),
        multiply_invocations[0].circuit.?.circuit_id.toU32(),
    );
    try std.testing.expectEqual(
        @as(u32, 11),
        multiply_invocations[1].circuit.?.circuit_id.toU32(),
    );

    evaluations_storage[0].circuit_identity[0] ^= 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        plan.materializeInto(reference, evaluations, .segment_leaf, .{
            .multiply = multiply_invocations,
            .inverse = inverse_invocations,
            .linear = linear_invocations,
        }),
    );
}

fn expectedInputClaim(
    relations: *const universal.UniversalRelations,
    circuit_id: u32,
    node_id: u32,
    value: QM31,
    multiplicity: u32,
) !QM31 {
    const words = value.toM31Array();
    const challenge = try relations.getExact(.recursion_wire);
    const denominator = try challenge.combineSecure(&.{
        QM31.fromBase(M31.fromCanonical(circuit_id)),
        QM31.fromBase(M31.fromCanonical(node_id)),
        QM31.fromBase(words[0]),
        QM31.fromBase(words[1]),
        QM31.fromBase(words[2]),
        QM31.fromBase(words[3]),
    });
    return QM31.fromBase(M31.fromCanonical(multiplicity)).mul(
        try denominator.inv(),
    );
}
