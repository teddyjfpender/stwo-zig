const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const lower_effects = @import("lower_effects.zig");
const polynomial = @import("typed_load_store_polynomial_test_support.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const corpus = @import("typed_mul_corpus.zig");
const evaluation = @import("typed_load_store_test_support.zig");
const typed_mul = @import("typed_mul.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

test "typed MUL has exact 39 columns 17 roots and 16 ordered lookups" {
    var authored = try typed_mul.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .mul,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    try std.testing.expectEqual(typed_mul.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed_mul.LOOKUP_BATCH_SIZE, imported.batch_size);
    try std.testing.expectEqual(typed_mul.LOOKUP_COUNT, imported.lookups.len);
    var authored_degrees = try degree.analyze(std.testing.allocator, &authored.arena);
    defer authored_degrees.deinit();
    var production_degrees = try degree.analyze(
        std.testing.allocator,
        &imported.imported.arena,
    );
    defer production_degrees.deinit();
    try std.testing.expectEqual(
        production_degrees.maximumConstraintDegree(),
        authored_degrees.maximumConstraintDegree(),
    );
    try std.testing.expectEqual(
        @as(degree.Degree, 2),
        authored_degrees.maximumConstraintDegree(),
    );

    for (authored.columns.physical(), witness_layout.columnNames(.mul)) |
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

    const actual_bindings = typedBindings(&authored);
    var expected_bindings: [typed_mul.MAIN_COLUMN_COUNT + 1]polynomial.Binding = undefined;
    for (layout.main(), expected_bindings[0..typed_mul.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    expected_bindings[typed_mul.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_mul.MAIN_COLUMN_COUNT,
    };
    const actual = try polynomial.fingerprintProgram(
        std.testing.allocator,
        &authored.arena,
        &actual_bindings,
    );
    defer std.testing.allocator.free(actual);
    const expected = try polynomial.fingerprintProgram(
        std.testing.allocator,
        &imported.imported.arena,
        &expected_bindings,
    );
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqual(
        typed_mul.DIRECT_CONSTRAINT_COUNT,
        imported.direct_constraints.len,
    );
    for (authored.model.constraints, imported.direct_constraints, 0..) |
        actual_id,
        expected_id,
        index,
    | {
        const actual_root = authored.arena.constraint(actual_id).?.root;
        const expected_root = imported.imported.arena.constraint(expected_id).?.root;
        if (!std.mem.eql(
            u8,
            &polynomial.fingerprintAt(expected, expected_root),
            &polynomial.fingerprintAt(actual, actual_root),
        )) std.log.err("MUL direct fingerprint mismatch at root {d}", .{index});
        try std.testing.expectEqual(
            polynomial.fingerprintAt(expected, expected_root),
            polynomial.fingerprintAt(actual, actual_root),
        );
    }

    const lowered = try lower_effects.ValidatedProgram.init(&authored.arena);
    for (imported.lookups, 0..) |expected_lookup, index| {
        const id = try types.idFromIndex(types.EffectId, index);
        const actual_event = lowered.event(id).?;
        try std.testing.expectEqual(expected_lookup.schema, actual_event.schema);
        try std.testing.expectEqual(expected_lookup.role, actual_event.role);
        try std.testing.expectEqual(
            expected_lookup.access_ordinal,
            actual_event.access_ordinal,
        );
        try polynomial.expectFingerprintEqual(
            expected,
            expected_lookup.numerator,
            actual,
            null,
            index,
            null,
            polynomial.eventNumeratorFingerprint(
                actual,
                authored.arena.effectsView()[index],
            ),
        );
        const expected_fields = imported.lookupFields(index).?;
        try std.testing.expectEqual(expected_fields.len, actual_event.values.len);
        for (expected_fields, actual_event.values, 0..) |
            expected_field,
            actual_field,
            field,
        | try polynomial.expectFingerprintEqual(
            expected,
            expected_field,
            actual,
            actual_field,
            index,
            field,
            null,
        );
        const interaction = layout.interactions()[index * 4];
        try std.testing.expectEqual(index, @as(usize, interaction.batch));
        try std.testing.expectEqual(index, interaction.first_lookup);
        try std.testing.expectEqual(@as(usize, 1), interaction.entry_count);
    }
}

test "typed MUL exact 256-row boundary corpus matches direct and lookup programs" {
    var authored = try typed_mul.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .mul,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const bindings = typedBindings(&authored);
    const actual_values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(actual_values);
    const expected_values = try std.testing.allocator.alloc(
        M31,
        imported.imported.arena.nodeCount(),
    );
    defer std.testing.allocator.free(expected_values);

    var saw_x0 = false;
    var saw_rs1_alias = false;
    var saw_rs2_alias = false;
    for (0..corpus.CORPUS_ROW_COUNT) |case_index| {
        const row = corpus.honestRow(case_index);
        try evaluation.evaluateInto(
            &authored.arena,
            &bindings,
            &row,
            actual_values,
        );
        try imported.imported.replay(&row, expected_values);
        for (authored.model.constraints, imported.direct_constraints) |
            actual_id,
            expected_id,
        | {
            const actual_root = authored.arena.constraint(actual_id).?.root;
            const expected_root = imported.imported.arena.constraint(expected_id).?.root;
            try std.testing.expect(actual_values[types.idIndex(actual_root)].isZero());
            try std.testing.expectEqual(
                expected_values[types.idIndex(expected_root)],
                actual_values[types.idIndex(actual_root)],
            );
        }
        for (authored.arena.effectsView(), imported.lookups, 0..) |
            actual_effect,
            expected_lookup,
            lookup_index,
        | {
            const effect_id = try types.idFromIndex(types.EffectId, lookup_index);
            try std.testing.expectEqual(
                expected_values[types.idIndex(expected_lookup.numerator)],
                signedNumerator(
                    actual_values[types.idIndex(actual_effect.liveness.?)],
                    expected_lookup.role,
                ),
            );
            for (authored.arena.effectValues(effect_id).?, imported.lookupFields(lookup_index).?) |
                actual_field,
                expected_field,
            | try std.testing.expectEqual(
                expected_values[types.idIndex(expected_field)],
                actual_values[types.idIndex(actual_field)],
            );
        }
        inline for (0..4) |limb| {
            const range_id = try types.idFromIndex(types.EffectId, 9 + limb);
            const fields = authored.arena.effectValues(range_id).?;
            try std.testing.expect(actual_values[types.idIndex(fields[0])].toU32() < 256);
            try std.testing.expect(actual_values[types.idIndex(fields[1])].toU32() < 1 << 11);
        }
        const trace_row = corpus.traceRow(case_index);
        saw_x0 = saw_x0 or trace_row.rd == 0;
        saw_rs1_alias = saw_rs1_alias or trace_row.rd == trace_row.rs1;
        saw_rs2_alias = saw_rs2_alias or trace_row.rd == trace_row.rs2;
    }
    try std.testing.expect(saw_x0);
    try std.testing.expect(saw_rs1_alias);
    try std.testing.expect(saw_rs2_alias);
}

test "typed MUL identity is source-independent and allocation-atomic" {
    var generated = try typed_mul.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var first = try typed_mul.build(
        std.testing.allocator,
        fileLocation("guest/mul.air", 11),
    );
    defer first.deinit();
    var moved = try typed_mul.build(
        std.testing.allocator,
        fileLocation("moved/mul.air", 97),
    );
    defer moved.deinit();
    try std.testing.expectEqual(
        try digest.computeIdentity(&generated.arena),
        try digest.computeIdentity(&first.arena),
    );
    try std.testing.expectEqual(
        try digest.computeIdentity(&generated.arena),
        try digest.computeIdentity(&moved.arena),
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "typed MUL semantic digest is pinned" {
    var definition = try typed_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const identity = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqual(typed_mul.SEMANTIC_DIGEST, identity.bytes);
}

fn typedBindings(
    definition: *const typed_mul.Definition,
) [typed_mul.MAIN_COLUMN_COUNT + 1]polynomial.Binding {
    var bindings: [typed_mul.MAIN_COLUMN_COUNT + 1]polynomial.Binding = undefined;
    for (definition.columns.physical(), bindings[0..typed_mul.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed_mul.MAIN_COLUMN_COUNT] = .{
        .value = definition.is_active,
        .column = typed_mul.MAIN_COLUMN_COUNT,
    };
    return bindings;
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try typed_mul.build(allocator, .generated);
    defer definition.deinit();
}

fn signedNumerator(value: M31, role: @import("relation.zig").Role) M31 {
    return switch (role) {
        .emit => value,
        .request, .consume => value.neg(),
    };
}

fn fileLocation(path: []const u8, line: u32) typed_mul.Location {
    return .{ .file = .{
        .path = path,
        .start = .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .end = .{ .byte_offset = line * 8 + 7, .line = line, .column = 8 },
    } };
}
