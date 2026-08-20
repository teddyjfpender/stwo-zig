const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const relation = @import("relation.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const support = @import("typed_jalr_test_support.zig");
const typed_jalr = @import("typed_jalr.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

test "typed JALR has exact 41 columns 23 roots and 18 native ordered lookups" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .jalr,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    try std.testing.expectEqual(typed_jalr.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed_jalr.LOOKUP_COUNT, imported.lookups.len);
    try std.testing.expectEqual(typed_jalr.LOOKUP_BATCH_SIZE, imported.batch_size);
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

    for (authored.columns.physical(), witness_layout.columnNames(.jalr)) |
        value,
        expected_name,
    | {
        const node = authored.arena.node(value).?;
        const actual_name = switch (node.key.op) {
            .input => |name| authored.arena.name(name).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, actual_name);
    }

    const authored_bindings = support.typedBindings(&authored);
    var production_bindings: [support.ROW_WIDTH]support.Binding = undefined;
    for (layout.main(), production_bindings[0..typed_jalr.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed_jalr.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_jalr.MAIN_COLUMN_COUNT,
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
        typed_jalr.DIRECT_CONSTRAINT_COUNT,
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
            &support.fingerprintAt(actual, actual_root),
            &support.fingerprintAt(expected, expected_root),
        )) {
            std.log.err("JALR direct fingerprint mismatch at {d}", .{index});
            return error.DirectFingerprintMismatch;
        }
    }

    for (authored.arena.effectsView(), imported.lookups, 0..) |
        actual_effect,
        expected_lookup,
        index,
    | {
        const binding = actual_effect.binding.?;
        try std.testing.expectEqual(expected_lookup.schema, binding.schema);
        try std.testing.expectEqual(expected_lookup.role, binding.role);
        try std.testing.expectEqual(
            expected_lookup.access_ordinal,
            actual_effect.access_ordinal,
        );
        const signed_liveness = switch (expected_lookup.role) {
            .emit => support.fingerprintAt(actual, actual_effect.liveness.?),
            .request, .consume => support.unaryFingerprint(
                5,
                support.fingerprintAt(actual, actual_effect.liveness.?),
            ),
        };
        try std.testing.expectEqual(
            support.fingerprintAt(expected, expected_lookup.numerator),
            signed_liveness,
        );
        const effect_id = try types.idFromIndex(types.EffectId, index);
        const actual_fields = authored.arena.effectValues(effect_id).?;
        const expected_fields = imported.lookupFields(index).?;
        try std.testing.expectEqual(expected_fields.len, actual_fields.len);
        for (actual_fields, expected_fields, 0..) |
            actual_field,
            expected_field,
            field_index,
        | if (!std.mem.eql(
            u8,
            &support.fingerprintAt(actual, actual_field),
            &support.fingerprintAt(expected, expected_field),
        )) {
            std.log.err("JALR lookup fingerprint mismatch at {d}:{d}", .{
                index,
                field_index,
            });
            return error.LookupFingerprintMismatch;
        };

        const batch = index / imported.batch_size;
        const batch_column = layout.interactions()[batch * 4];
        try std.testing.expectEqual(batch, @as(usize, batch_column.batch));
        try std.testing.expectEqual(
            batch * imported.batch_size,
            batch_column.first_lookup,
        );
        try std.testing.expectEqual(
            @min(
                @as(usize, imported.batch_size),
                imported.lookups.len - batch * imported.batch_size,
            ),
            batch_column.entry_count,
        );
    }
}

test "typed JALR exhaustively reconstructs every signed I-immediate and target bit zero" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .jalr,
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

    const target: u32 = 0x0200_0000;
    var visited: usize = 0;
    var saw_negative = false;
    var saw_positive = false;
    var saw_x0 = false;
    var saw_alias = false;
    var immediate: i32 = -2048;
    while (immediate <= 2047) : (immediate += 1) {
        const immediate_bits: u32 = @bitCast(immediate);
        for (0..2) |low_bit| {
            const rs1_value = (target +% @as(u32, @intCast(low_bit))) -% immediate_bits;
            const rd: u5 = if (visited % 17 == 0)
                0
            else if (visited % 13 == 0)
                5
            else
                10;
            const row = try support.honestRow(.{
                .rs1_value = rs1_value,
                .immediate = immediate,
                .rd = rd,
                .rs1 = 5,
                .clock = @intCast(9 + visited),
            });
            try compareAcceptedRow(
                &authored,
                &imported,
                &bindings,
                &row,
                actual_values,
                expected_values,
            );
            saw_negative = saw_negative or immediate < 0;
            saw_positive = saw_positive or immediate > 0;
            saw_x0 = saw_x0 or rd == 0;
            saw_alias = saw_alias or rd == 5;
            visited += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 8192), visited);
    try std.testing.expect(saw_negative and saw_positive and saw_x0 and saw_alias);
}

test "typed JALR target split boundaries wraparound and padding are accepted exactly" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .jalr,
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

    const words = [_]u32{
        0,           1,           2,           0x000f_fffe, 0x000f_ffff,
        0x0010_0000, 0x0010_0001, 0x0fff_fffe, 0x0fff_ffff,
    };
    const immediates = [_]i32{ -2048, -1, 0, 1, 2047 };
    var visited: usize = 0;
    for (words) |word| for (immediates) |immediate| for (0..2) |low_bit| {
        const target = word * 4;
        const immediate_bits: u32 = @bitCast(immediate);
        const rs1_value = (target +% @as(u32, @intCast(low_bit))) -% immediate_bits;
        const row = try support.honestRow(.{
            .rs1_value = rs1_value,
            .immediate = immediate,
            .pc = 0x2000,
            .clock = @intCast(20 + visited),
        });
        try compareAcceptedRow(
            &authored,
            &imported,
            &bindings,
            &row,
            actual_values,
            expected_values,
        );
        visited += 1;
    };
    const wrapped = try support.honestRow(.{
        .rs1_value = 0xffff_ffff,
        .immediate = 5,
    });
    try compareAcceptedRow(
        &authored,
        &imported,
        &bindings,
        &wrapped,
        actual_values,
        expected_values,
    );
    const padding = support.paddedRow();
    try compareAcceptedRow(
        &authored,
        &imported,
        &bindings,
        &padding,
        actual_values,
        expected_values,
    );
    try std.testing.expectEqual(@as(usize, 90), visited);
}

test "typed JALR identity is pinned and independent of diagnostic source" {
    var generated = try typed_jalr.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed_jalr.build(std.testing.allocator, .{ .file = .{
        .path = "moved/control/jalr.air",
        .start = .{ .byte_offset = 71, .line = 9, .column = 3 },
        .end = .{ .byte_offset = 99, .line = 9, .column = 31 },
    } });
    defer moved.deinit();
    const generated_identity = try digest.computeIdentity(&generated.arena);
    const moved_identity = try digest.computeIdentity(&moved.arena);
    try std.testing.expectEqual(
        digest.range_refinement_format_version,
        generated_identity.format_version,
    );
    try std.testing.expectEqual(generated_identity, moved_identity);
    try std.testing.expectEqual(typed_jalr.SEMANTIC_DIGEST, generated_identity.bytes);
    const rendered = std.fmt.bytesToHex(generated_identity.bytes, .lower);
    try std.testing.expectEqualStrings(typed_jalr.SEMANTIC_DIGEST_HEX, &rendered);
}

test "typed JALR fixed authority compiles with the authenticated definition" {
    const fixed = @import("typed_jalr_authority.zig");
    var definition = try typed_jalr.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try fixed.Binding.canonical(&definition);
    try std.testing.expectEqual(
        fixed.AUTHORITY_BINDING_DIGEST,
        binding.identityDigest(),
    );
    _ = try fixed.Authority.init(&definition, &binding);
}

test "typed JALR fixed authority contract suite" {
    _ = @import("typed_jalr_authority_test.zig");
}

test "typed JALR production retirement contract suite" {
    _ = @import("../../runner/jalr_retirement_test.zig");
}

fn compareAcceptedRow(
    authored: *const typed_jalr.Definition,
    imported: *const shadow_program.ImportedProgram,
    bindings: []const support.Binding,
    row: []const M31,
    actual_values: []M31,
    expected_values: []M31,
) !void {
    try support.evaluateInto(&authored.arena, bindings, row, actual_values);
    try imported.imported.replay(row, expected_values);
    try std.testing.expect(support.rowAccepted(authored, actual_values));
    for (authored.model.constraints, imported.direct_constraints) |
        actual_id,
        expected_id,
    | try std.testing.expectEqual(
        expected_values[types.idIndex(imported.imported.arena.constraint(expected_id).?.root)].toU32(),
        actual_values[types.idIndex(authored.arena.constraint(actual_id).?.root)].toU32(),
    );
    for (authored.arena.effectsView(), imported.lookups, 0..) |
        actual_effect,
        expected_lookup,
        lookup_index,
    | {
        try std.testing.expectEqual(
            expected_values[types.idIndex(expected_lookup.numerator)].toU32(),
            signedNumerator(
                actual_values[types.idIndex(actual_effect.liveness.?)],
                expected_lookup.role,
            ).toU32(),
        );
        const actual_id = try types.idFromIndex(types.EffectId, lookup_index);
        for (authored.arena.effectValues(actual_id).?, imported.lookupFields(lookup_index).?) |
            actual_field,
            expected_field,
        | try std.testing.expectEqual(
            expected_values[types.idIndex(expected_field)].toU32(),
            actual_values[types.idIndex(actual_field)].toU32(),
        );
    }
}

fn signedNumerator(value: M31, role: relation.Role) M31 {
    return switch (role) {
        .emit => value,
        .request, .consume => value.neg(),
    };
}
