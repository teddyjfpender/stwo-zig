const std = @import("std");
const stwo_core = @import("stwo_core");
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const inventory = @import("inventory.zig");
const qm31_mul = @import("qm31_mul.zig");
const support = @import("test_support.zig");
const witness = @import("qm31_mul_witness.zig");

const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

test "R-012 typed QM31 multiplication has exact degree-two compiler geometry" {
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    try definition.validate();

    try std.testing.expectEqual(@as(usize, 12), definition.columns.physical().len);
    try std.testing.expectEqual(@as(usize, 4), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 48), definition.arena.nodeCount());
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, qm31_mul.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    for (definition.constraints) |constraint_id| {
        const constraint = definition.arena.constraint(constraint_id).?;
        try std.testing.expect(constraint.gate == null);
    }

    const identity = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqual(digest.format_version, identity.format_version);
    try std.testing.expectEqualStrings(
        qm31_mul.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
}

test "R-012 typed QM31 multiplication profile is compiler-derived and closed" {
    const profile = try inventory.collectProfile(
        std.testing.allocator,
        .qm31_mul_standalone,
    );
    try profile.validate();
    try std.testing.expectEqual(@as(?u32, 12), profile.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 12), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 4), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 0), profile.effects);
    try std.testing.expectEqual(@as(u32, 0), profile.lookup_events);
    try std.testing.expectEqual(@as(u32, 2), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(
        @as(u32, 0),
        profile.nodes_outside_constraint_effect_closure,
    );
    try std.testing.expectEqual(@as(u32, 48), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 72), profile.expression_dag_edges);
    try std.testing.expectEqualStrings(
        qm31_mul.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.program_digest, .lower),
    );
    try std.testing.expectEqualStrings(
        "f38ce9c61b1c94adc1bed03f94efbb47b32ec0e1a891f977c885461da2f7b12a",
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 typed QM31 multiplication witness matches canonical field arithmetic" {
    const invocations = [_]witness.Invocation{
        .{ .a = QM31.zero(), .b = QM31.zero() },
        .{ .a = QM31.one(), .b = QM31.one() },
        .{
            .a = QM31.fromM31Array(.{M31.fromCanonical(m31.Modulus - 1)} ** 4),
            .b = QM31.fromM31Array(.{
                M31.fromCanonical(m31.Modulus - 2),
                M31.fromCanonical(1),
                M31.fromCanonical(m31.Modulus - 3),
                M31.fromCanonical(2),
            }),
        },
        .{
            .a = QM31.fromU32Unchecked(1, 2, 3, 4),
            .b = QM31.fromU32Unchecked(5, 6, 7, 8),
        },
    };
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.WITNESS_BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
    var storage: [witness.PHYSICAL_COLUMN_COUNT][8]M31 = undefined;
    var columns: [witness.PHYSICAL_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*column_storage, *column| {
        @memset(column_storage, M31.fromCanonical(99));
        column.* = column_storage;
    }
    try executor.generateMainInto(&columns, &invocations, 3);

    for (invocations, 0..) |invocation, row_index| {
        var row: [witness.PHYSICAL_COLUMN_COUNT]M31 = undefined;
        for (&row, columns) |*value, column| value.* = column[row_index];
        const expected = support.rowFor(invocation.a, invocation.b);
        try std.testing.expectEqualSlices(M31, &expected, &row);
        const values = try support.evaluateQm31Mul(
            std.testing.allocator,
            &definition,
            &row,
        );
        defer std.testing.allocator.free(values);
        for (0..qm31_mul.CONSTRAINT_COUNT) |constraint_index| {
            try std.testing.expect(
                support.constraintValue(&definition, values, constraint_index).isZero(),
            );
        }
    }
    for (columns) |column| {
        for (column[invocations.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "R-012 typed QM31 multiplication agrees on randomized canonical coordinates" {
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var prng = std.Random.DefaultPrng.init(0x5230_3132_514d_3331);
    const random = prng.random();
    for (0..1024) |_| {
        const a = randomQm31(random);
        const b = randomQm31(random);
        const row = support.rowFor(a, b);
        const values = try support.evaluateQm31Mul(
            std.testing.allocator,
            &definition,
            &row,
        );
        defer std.testing.allocator.free(values);
        for (0..qm31_mul.CONSTRAINT_COUNT) |constraint_index| {
            try std.testing.expect(
                support.constraintValue(&definition, values, constraint_index).isZero(),
            );
        }
    }
}

test "R-012 typed QM31 multiplication construction is allocation-failure clean" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildFailureCase,
        .{},
    );
}

fn buildFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try qm31_mul.build(allocator, .generated);
    defer definition.deinit();
}

fn randomQm31(random: std.Random) QM31 {
    return QM31.fromM31(
        randomM31(random),
        randomM31(random),
        randomM31(random),
        randomM31(random),
    );
}

fn randomM31(random: std.Random) M31 {
    return M31.fromCanonical(random.int(u32) % m31.Modulus);
}
