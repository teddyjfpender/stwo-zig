const std = @import("std");
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const lower_effects = @import("lower_effects.zig");
const polynomial = @import("typed_load_store_polynomial_test_support.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const typed_mulh = @import("typed_mulh.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

test "typed MULH has exact 47 columns 24 roots and 22 ordered lookups" {
    var authored = try typed_mulh.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .mulh,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    try std.testing.expectEqual(typed_mulh.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed_mulh.LOOKUP_BATCH_SIZE, imported.batch_size);
    try std.testing.expectEqual(typed_mulh.LOOKUP_COUNT, imported.lookups.len);
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

    for (authored.columns.physical(), witness_layout.columnNames(.mulh)) |
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
    var expected_bindings: [typed_mulh.MAIN_COLUMN_COUNT + 1]polynomial.Binding = undefined;
    for (layout.main(), expected_bindings[0..typed_mulh.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    expected_bindings[typed_mulh.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_mulh.MAIN_COLUMN_COUNT,
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
        typed_mulh.DIRECT_CONSTRAINT_COUNT,
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
        )) std.log.err("MULH direct fingerprint mismatch at root {d}", .{index});
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

    const identity = try digest.computeIdentity(&authored.arena);
    try std.testing.expectEqual(typed_mulh.SEMANTIC_DIGEST, identity.bytes);
}

test "typed MULH semantic digest is pinned" {
    var definition = try typed_mulh.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const identity = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqual(typed_mulh.SEMANTIC_DIGEST, identity.bytes);
}

test "typed MULH identity is source-independent and allocation-atomic" {
    var generated = try typed_mulh.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var first = try typed_mulh.build(
        std.testing.allocator,
        fileLocation("guest/mulh.air", 11),
    );
    defer first.deinit();
    var moved = try typed_mulh.build(
        std.testing.allocator,
        fileLocation("moved/mulh.air", 97),
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

fn typedBindings(
    definition: *const typed_mulh.Definition,
) [typed_mulh.MAIN_COLUMN_COUNT + 1]polynomial.Binding {
    var bindings: [typed_mulh.MAIN_COLUMN_COUNT + 1]polynomial.Binding = undefined;
    for (definition.columns.physical(), bindings[0..typed_mulh.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed_mulh.MAIN_COLUMN_COUNT] = .{
        .value = definition.is_active,
        .column = typed_mulh.MAIN_COLUMN_COUNT,
    };
    return bindings;
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try typed_mulh.build(allocator, .generated);
    defer definition.deinit();
}

fn fileLocation(path: []const u8, line: u32) typed_mulh.Location {
    return .{ .file = .{
        .path = path,
        .start = .{ .byte_offset = line * 8, .line = line, .column = 1 },
        .end = .{ .byte_offset = line * 8 + 7, .line = line, .column = 8 },
    } };
}
