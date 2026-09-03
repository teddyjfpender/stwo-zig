const std = @import("std");
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const component_mod = @import("typed_poseidon2_degree_bounded_component.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const relations_mod = @import("../relation_challenges.zig");

test "degree-six component evaluates the genuine candidate and LogUp AIR" {
    var candidate = try candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree6,
    );
    defer candidate.deinit();
    const relations = relations_mod.Relations.dummy();

    var input: [candidate_mod.WIDTH]u32 = undefined;
    for (&input, 0..) |*value, lane| {
        value.* = @intCast(0x0102_0304 + lane * 0x0010_0203);
    }
    const call = poseidon2_air.Call{ .input = input };
    const row = try std.testing.allocator.alloc(
        M31,
        candidate.mainColumnCount(),
    );
    defer std.testing.allocator.free(row);
    try candidate.fillRow(row, call);

    const pairs = poseidon2_air.rowPairsFromCall(call, &relations);
    var claims: [component_mod.LOGUP_CONSTRAINTS]QM31 = undefined;
    for (pairs, &claims) |pair, *claim| {
        const denominator = pair.d1.mul(pair.d2);
        const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
        claim.* = numerator.mul(try denominator.inv());
    }
    const component = try component_mod.Component.init(
        &candidate,
        4,
        1,
        0,
        1,
        0,
        0,
        &relations,
        claims,
    );

    var secure_row: [component_mod.MAIN_COLUMNS]QM31 = undefined;
    for (row, &secure_row) |value, *destination| {
        destination.* = QM31.fromBase(value);
    }
    const constraints = try component.evaluateConstraints(
        secure_row,
        QM31.one(),
        QM31.one(),
        claims,
        claims,
    );
    for (constraints) |constraint| {
        try std.testing.expect(constraint.eql(QM31.zero()));
    }

    secure_row[candidate_mod.MATERIALIZATION_COLUMN_START] =
        secure_row[candidate_mod.MATERIALIZATION_COLUMN_START].add(QM31.one());
    const forged = try component.evaluateConstraints(
        secure_row,
        QM31.one(),
        QM31.one(),
        claims,
        claims,
    );
    var rejected = false;
    for (forged[0..component_mod.PERMUTATION_CONSTRAINTS]) |constraint| {
        rejected = rejected or !constraint.eql(QM31.zero());
    }
    try std.testing.expect(rejected);
}

test "degree-six component pins exact proof and sampling geometry" {
    var candidate = try candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree6,
    );
    defer candidate.deinit();
    const relations = relations_mod.Relations.dummy();
    const component = try component_mod.Component.init(
        &candidate,
        7,
        13,
        11,
        12,
        19,
        23,
        &relations,
        .{ QM31.zero(), QM31.zero() },
    );

    const prover_component = component.asProverComponent();
    const verifier_component = component.asVerifierComponent();
    try std.testing.expectEqual(
        @as(usize, component_mod.CONSTRAINTS),
        prover_component.nConstraints(),
    );
    try std.testing.expectEqual(@as(u32, 10), prover_component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(u32, 10), verifier_component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(@as(u32, 3), prover_component.compositionLogSplit());
    try std.testing.expectEqual(@as(u32, 3), verifier_component.compositionLogSplit());
    try std.testing.expectEqual(@as(u32, 7), component.samplingLogDegreeBound());

    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(@as(usize, 2), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 161), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 8), bounds.items[2].len);
    for (bounds.items) |tree| for (tree) |log_size| {
        try std.testing.expectEqual(@as(u32, 7), log_size);
    };

    const point = circle.SECURE_FIELD_CIRCLE_GEN;
    var mask = try component.maskPoints(
        std.testing.allocator,
        point,
        component.samplingLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), mask.items[0].len);
    try std.testing.expectEqual(@as(usize, 161), mask.items[1].len);
    try std.testing.expectEqual(@as(usize, 8), mask.items[2].len);
    for (mask.items[2]) |column| {
        try std.testing.expectEqual(@as(usize, 2), column.len);
        try std.testing.expect(column[0].eql(point));
        try std.testing.expect(!column[1].eql(point));
    }

    const indices = try component.preprocessedColumnIndices(std.testing.allocator);
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 11, 12 }, indices);

    const degree_five = try candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree5,
    );
    var degree_five_owned = degree_five;
    defer degree_five_owned.deinit();
    try std.testing.expectError(
        error.InvalidCandidateComponent,
        component_mod.Component.init(
            &degree_five_owned,
            7,
            13,
            11,
            12,
            19,
            23,
            &relations,
            .{ QM31.zero(), QM31.zero() },
        ),
    );
}
