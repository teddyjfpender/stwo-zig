const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const support = @import("typed_div_test_support.zig");
const typed_div = @import("typed_div.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

test "typed DIV has exact 67 columns 79 roots and 25 ordered lookups" {
    var authored = try typed_div.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    try std.testing.expectEqual(typed_div.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed_div.LOOKUP_BATCH_SIZE, imported.batch_size);
    try std.testing.expectEqual(typed_div.LOOKUP_COUNT, imported.lookups.len);
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
        @as(degree.Degree, 3),
        authored_degrees.maximumConstraintDegree(),
    );

    const physical = authored.columns.physical();
    for (physical, witness_layout.columnNames(.div)) |value, expected_name| {
        const node = authored.arena.node(value).?;
        const name = switch (node.key.op) {
            .input => |name_id| authored.arena.name(name_id).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, name);
    }

    const authored_bindings = support.typedBindings(&authored);
    var production_bindings: [support.ROW_WIDTH]support.Binding = undefined;
    for (layout.main(), production_bindings[0..typed_div.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed_div.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_div.MAIN_COLUMN_COUNT,
    };
    const actual = try support.fingerprintProgram(
        std.testing.allocator,
        &authored.arena,
        &authored_bindings,
    );
    defer std.testing.allocator.free(actual);
    const expected = try support.fingerprintProgram(
        std.testing.allocator,
        &imported.imported.arena,
        &production_bindings,
    );
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqual(
        typed_div.DIRECT_CONSTRAINT_COUNT,
        imported.direct_constraints.len,
    );
    for (authored.model.constraints, imported.direct_constraints) |actual_id, expected_id| {
        const actual_root = authored.arena.constraint(actual_id).?.root;
        const expected_root = imported.imported.arena.constraint(expected_id).?.root;
        try std.testing.expectEqual(
            support.fingerprintAt(expected, expected_root),
            support.fingerprintAt(actual, actual_root),
        );
    }
    for (authored.arena.effectsView(), imported.lookups, 0..) |
        authored_effect,
        imported_lookup,
        index,
    | {
        const binding = authored_effect.binding.?;
        try std.testing.expectEqual(imported_lookup.schema, binding.schema);
        try std.testing.expectEqual(imported_lookup.role, binding.role);
        try std.testing.expectEqual(
            imported_lookup.access_ordinal,
            authored_effect.access_ordinal,
        );
        try std.testing.expectEqual(
            support.fingerprintAt(expected, importedLiveness(&imported, index)),
            support.fingerprintAt(actual, authored_effect.liveness.?),
        );
    }
    for (authored.arena.effectsView(), imported.lookups, 0..) |
        _,
        imported_lookup,
        index,
    | {
        const id = try types.idFromIndex(types.EffectId, index);
        const authored_fields = authored.arena.effectValues(id).?;
        const imported_fields = imported.lookupFields(index).?;
        try std.testing.expectEqual(imported_fields.len, authored_fields.len);
        for (authored_fields, imported_fields, 0..) |
            actual_value,
            expected_value,
            field_index,
        | {
            const expected_fingerprint = support.fingerprintAt(expected, expected_value);
            const actual_fingerprint = support.fingerprintAt(actual, actual_value);
            if (!std.mem.eql(u8, &expected_fingerprint, &actual_fingerprint)) {
                std.log.err("DIV lookup fingerprint mismatch at {d}:{d}", .{
                    index,
                    field_index,
                });
                return error.LookupFingerprintMismatch;
            }
        }
        const batch_column = layout.interactions()[index * 4];
        try std.testing.expectEqual(index, @as(usize, batch_column.batch));
        try std.testing.expectEqual(index, batch_column.first_lookup);
        try std.testing.expectEqual(@as(usize, 1), batch_column.entry_count);
        _ = imported_lookup;
    }
}

test "typed DIV exact 292-row operand-class corpus matches direct and lookup programs" {
    var authored = try typed_div.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const bindings = support.typedBindings(&authored);
    const actual_values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(actual_values);
    const expected_values = try std.testing.allocator.alloc(
        M31,
        imported.imported.arena.nodeCount(),
    );
    defer std.testing.allocator.free(expected_values);

    var visited: usize = 0;
    var saw_zero_divisor = false;
    var saw_signed_overflow = false;
    var saw_rd_zero = false;
    var saw_rd_alias = false;
    var signed_sign_classes: u4 = 0;
    for (0..support.OPERAND_CLASS_COUNT) |class_index| {
        const operands = support.operandClass(class_index);
        for (0..4) |opcode_index| {
            const op = support.opcode(opcode_index);
            const row = try support.honestRow(op, operands, class_index * 4 + opcode_index);
            try support.evaluateInto(&authored.arena, &bindings, &row, actual_values);
            try imported.imported.replay(&row, expected_values);
            try std.testing.expect(support.rowAccepted(&authored, actual_values));
            for (authored.model.constraints, imported.direct_constraints) |
                actual_id,
                expected_id,
            | {
                const actual_root = authored.arena.constraint(actual_id).?.root;
                const expected_root = imported.imported.arena.constraint(expected_id).?.root;
                try std.testing.expectEqual(
                    expected_values[types.idIndex(expected_root)].toU32(),
                    actual_values[types.idIndex(actual_root)].toU32(),
                );
            }
            for (authored.arena.effectsView(), imported.lookups, 0..) |
                actual_effect,
                expected_lookup,
                lookup_index,
            | {
                const effect_id = try types.idFromIndex(types.EffectId, lookup_index);
                try std.testing.expectEqual(
                    expected_values[types.idIndex(expected_lookup.numerator)].toU32(),
                    signedNumerator(
                        actual_values[types.idIndex(actual_effect.liveness.?)],
                        expected_lookup.role,
                    ).toU32(),
                );
                for (authored.arena.effectValues(effect_id).?, imported.lookupFields(lookup_index).?) |
                    actual_field,
                    expected_field,
                | try std.testing.expectEqual(
                    expected_values[types.idIndex(expected_field)].toU32(),
                    actual_values[types.idIndex(actual_field)].toU32(),
                );
            }
            saw_zero_divisor = saw_zero_divisor or operands.rhs == 0;
            saw_signed_overflow = saw_signed_overflow or
                ((op == .DIV or op == .REM) and
                    operands.lhs == 0x8000_0000 and operands.rhs == 0xffff_ffff);
            saw_rd_zero = saw_rd_zero or row[2].isZero();
            saw_rd_alias = saw_rd_alias or row[2].eql(row[12]) or row[2].eql(row[22]);
            if ((op == .DIV or op == .REM) and operands.rhs != 0) {
                const sign_class: u2 = @intCast(
                    ((operands.lhs >> 31) << 1) | (operands.rhs >> 31),
                );
                signed_sign_classes |= @as(u4, 1) << sign_class;
            }
            visited += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 292), visited);
    try std.testing.expect(saw_zero_divisor);
    try std.testing.expect(saw_signed_overflow);
    try std.testing.expect(saw_rd_zero);
    try std.testing.expect(saw_rd_alias);
    try std.testing.expectEqual(@as(u4, 0b1111), signed_sign_classes);
}

test "typed DIV semantic and lookup identities ignore diagnostic source moves" {
    var generated = try typed_div.build(std.testing.allocator, .generated);
    defer generated.deinit();
    const first_location = typed_div.Location{ .file = .{
        .path = "guest/div.air",
        .start = .{ .byte_offset = 80, .line = 10, .column = 4 },
        .end = .{ .byte_offset = 90, .line = 10, .column = 14 },
    } };
    var moved = try typed_div.build(std.testing.allocator, first_location);
    defer moved.deinit();
    try std.testing.expectEqual(
        typed_div.SEMANTIC_DIGEST,
        (try @import("digest.zig").computeIdentity(&generated.arena)).bytes,
    );
    try std.testing.expectEqual(
        typed_div.SEMANTIC_DIGEST,
        (try @import("digest.zig").computeIdentity(&moved.arena)).bytes,
    );
}

fn importedLiveness(imported: *const shadow_program.ImportedProgram, index: usize) types.ValueId {
    const lookup = imported.lookups[index];
    return switch (lookup.role) {
        .emit => lookup.numerator,
        .request, .consume => switch (imported.imported.arena.node(lookup.numerator).?.key.op) {
            .neg => |value| value,
            else => unreachable,
        },
    };
}

fn signedNumerator(value: M31, role: @import("relation.zig").Role) M31 {
    return switch (role) {
        .emit => value,
        .request, .consume => value.neg(),
    };
}
