const std = @import("std");
const compat_layout = @import("stwo_riscv_rv32").air.lang.compat_layout;
const compat = @import("stwo_riscv_air_lang").testing.typed_air_compatibility_test_support;
const degree = @import("stwo_riscv_air_lang").degree;
const digest = @import("stwo_riscv_air_lang").digest;
const lower_effects = @import("stwo_riscv_air_lang").lower_effects;
const shadow_program = @import("stwo_riscv_rv32").air.lang.shadow_program;
const source = @import("stwo_riscv_air_lang").source;
const typed = @import("stwo_riscv_air_lang").typed_shifts_reg;
const types = @import("stwo_riscv_air_lang").types;
const witness_layout = @import("stwo_riscv_rv32").witness_layout;

test "typed SHIFTS_REG is compatibility-exact for every constraint and effect" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .shifts_reg,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var degrees = try degree.analyze(std.testing.allocator, &authored.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(@as(degree.Degree, 3), degrees.maximumConstraintDegree());
    try std.testing.expectEqual(typed.MAIN_COLUMN_COUNT, layout.main().len);
    for (authored.columns.physical(), witness_layout.columnNames(.shifts_reg)) |
        value,
        expected_name,
    | {
        const node = authored.arena.node(value).?;
        const name = switch (node.key.op) {
            .input => |name_id| authored.arena.name(name_id).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, name);
    }

    var authored_bindings: [typed.MAIN_COLUMN_COUNT + 1]compat.Binding = undefined;
    for (authored.columns.physical(), authored_bindings[0..typed.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    authored_bindings[typed.MAIN_COLUMN_COUNT] = .{
        .value = authored.is_active,
        .column = typed.MAIN_COLUMN_COUNT,
    };
    var production_bindings: [typed.MAIN_COLUMN_COUNT + 1]compat.Binding = undefined;
    for (layout.main(), production_bindings[0..typed.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed.MAIN_COLUMN_COUNT,
    };
    const actual_fingerprints = try compat.fingerprintProgram(
        std.testing.allocator,
        &authored.arena,
        &authored_bindings,
    );
    defer std.testing.allocator.free(actual_fingerprints);
    const expected_fingerprints = try compat.fingerprintProgram(
        std.testing.allocator,
        &imported.imported.arena,
        &production_bindings,
    );
    defer std.testing.allocator.free(expected_fingerprints);
    try std.testing.expectEqual(
        typed.DIRECT_CONSTRAINT_COUNT,
        imported.direct_constraints.len,
    );
    for (authored.constraints, imported.direct_constraints, 0..) |
        actual_id,
        expected_id,
        index,
    | {
        const actual = authored.arena.constraint(actual_id).?;
        const expected = imported.imported.arena.constraint(expected_id).?;
        if (!std.mem.eql(
            u8,
            &compat.at(expected_fingerprints, expected.root),
            &compat.at(actual_fingerprints, actual.root),
        )) std.debug.print("SHIFTS_REG constraint mismatch {d}\n", .{index});
        try std.testing.expectEqual(
            compat.at(expected_fingerprints, expected.root),
            compat.at(actual_fingerprints, actual.root),
        );
    }

    const typed_events = try lower_effects.ValidatedProgram.init(&authored.arena);
    try std.testing.expectEqual(typed.RELATION_EVENT_COUNT, imported.lookups.len);
    for (imported.lookups, typed.EVENT_SPECS, 0..) |expected, spec, index| {
        const actual = typed_events.event(try types.idFromIndex(types.EffectId, index)).?;
        try std.testing.expectEqual(spec.kind, actual.kind);
        try std.testing.expectEqual(expected.schema, actual.schema);
        try std.testing.expectEqual(expected.role, actual.role);
        try std.testing.expectEqual(expected.access_ordinal, actual.access_ordinal);
        const expected_values = imported.lookupFields(index).?;
        try std.testing.expectEqual(expected_values.len, actual.values.len);
        for (expected_values, actual.values, 0..) |expected_value, actual_value, field| {
            if (!std.mem.eql(
                u8,
                &compat.at(expected_fingerprints, expected_value),
                &compat.at(actual_fingerprints, actual_value),
            )) std.debug.print("SHIFTS_REG effect mismatch {d}:{d}\n", .{ index, field });
            try std.testing.expectEqual(
                compat.at(expected_fingerprints, expected_value),
                compat.at(actual_fingerprints, actual_value),
            );
        }
        const signed_liveness = switch (expected.role) {
            .emit => compat.at(actual_fingerprints, actual.liveness),
            .request, .consume => compat.unary(
                5,
                compat.at(actual_fingerprints, actual.liveness),
            ),
        };
        try std.testing.expectEqual(
            compat.at(expected_fingerprints, expected.numerator),
            signed_liveness,
        );
    }
}

test "typed SHIFTS_REG identity is source-independent and allocation-atomic" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/shifts_reg.air",
        .start = .{ .byte_offset = 40, .line = 5, .column = 1 },
        .end = .{ .byte_offset = 51, .line = 5, .column = 12 },
    } });
    defer moved.deinit();
    try std.testing.expectEqual(
        try digest.computeIdentity(&generated.arena),
        try digest.computeIdentity(&moved.arena),
    );
    try std.testing.expectEqual(typed.SEMANTIC_DIGEST, try digest.computeV7(&generated.arena));
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
}
