const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const lower_effects = @import("lower_effects.zig");
const manifest = @import("manifest.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const support = @import("typed_load_store_test_support.zig");
const typed_load_store = @import("typed_load_store.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

test "typed load/store has exact 50 columns 63 roots and 17 ordered lookups" {
    var authored = try typed_load_store.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .load_store,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    try std.testing.expectEqual(typed_load_store.AuthoringBoundary.native_direct_native_effects, typed_load_store.AUTHORING_BOUNDARY);
    try std.testing.expectEqual(typed_load_store.LOOKUP_COUNT, authored.arena.effectsView().len);
    try std.testing.expectEqual(typed_load_store.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed_load_store.LOOKUP_BATCH_SIZE, imported.batch_size);
    try std.testing.expectEqual(typed_load_store.LOOKUP_COUNT, imported.lookups.len);

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
    try std.testing.expectEqual(
        production_degrees.maximumValueDegree(),
        authored_degrees.maximumValueDegree(),
    );

    const physical = authored.columns.physical();
    for (physical, witness_layout.columnNames(.load_store)) |value, expected_name| {
        const node = authored.arena.node(value).?;
        const name = switch (node.key.op) {
            .input => |name_id| authored.arena.name(name_id).?,
            else => return error.ExpectedPhysicalInput,
        };
        try std.testing.expectEqualStrings(expected_name, name);
    }

    const authored_bindings = support.typedBindings(&authored);
    var production_bindings: [support.ROW_WIDTH]support.Binding = undefined;
    for (layout.main(), production_bindings[0..typed_load_store.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed_load_store.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_load_store.MAIN_COLUMN_COUNT,
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
    var native_events = (try lower_effects.ValidatedProgram.init(&authored.arena)).iterator();

    try std.testing.expectEqual(
        typed_load_store.DIRECT_CONSTRAINT_COUNT,
        imported.direct_constraints.len,
    );
    for (authored.model.constraints, imported.direct_constraints, 0..) |
        actual_id,
        expected_id,
        index,
    | {
        const actual_root = authored.arena.constraint(actual_id).?.root;
        const expected_root = imported.imported.arena.constraint(expected_id).?.root;
        const actual_fingerprint = support.fingerprintAt(actual, actual_root);
        const expected_fingerprint = support.fingerprintAt(expected, expected_root);
        if (!std.mem.eql(u8, &actual_fingerprint, &expected_fingerprint)) {
            std.log.err("load/store direct fingerprint mismatch at {d}", .{index});
            return error.DirectFingerprintMismatch;
        }
    }
    for (authored.arena.effectsView(), imported.lookups, 0..) |
        authored_effect,
        imported_lookup,
        index,
    | {
        const native = native_events.next() orelse return error.MissingNativeEvent;
        try std.testing.expectEqual(index, types.idIndex(native.effect));
        try std.testing.expectEqual(authored_effect.kind, native.kind);
        try std.testing.expectEqual(imported_lookup.schema, authored_effect.binding.?.schema);
        try std.testing.expectEqual(imported_lookup.schema, native.schema);
        try std.testing.expectEqual(imported_lookup.role, authored_effect.binding.?.role);
        try std.testing.expectEqual(imported_lookup.role, native.role);
        try std.testing.expectEqual(
            imported_lookup.access_ordinal,
            authored_effect.access_ordinal,
        );
        try std.testing.expectEqual(
            production_degrees.value(imported_lookup.numerator).?,
            authored_degrees.value(authored_effect.liveness.?).?,
        );
        try support.expectFingerprintEqual(
            expected,
            imported_lookup.numerator,
            actual,
            null,
            index,
            null,
            support.eventNumeratorFingerprint(actual, authored_effect),
        );
        const imported_fields = imported.lookupFields(index).?;
        const authored_fields = support.effectFields(&authored, index);
        try std.testing.expectEqualSlices(types.ValueId, authored_fields, native.values);
        try std.testing.expectEqual(imported_fields.len, authored_fields.len);
        for (authored_fields, imported_fields, 0..) |
            actual_value,
            expected_value,
            field_index,
        | {
            try std.testing.expectEqual(
                production_degrees.value(expected_value).?,
                authored_degrees.value(actual_value).?,
            );
            try support.expectFingerprintEqual(
                expected,
                expected_value,
                actual,
                actual_value,
                index,
                field_index,
                null,
            );
        }
        const batch = index / typed_load_store.LOOKUP_BATCH_SIZE;
        const batch_column = layout.interactions()[batch * 4];
        try std.testing.expectEqual(batch, @as(usize, batch_column.batch));
        try std.testing.expectEqual(
            batch * typed_load_store.LOOKUP_BATCH_SIZE,
            batch_column.first_lookup,
        );
        try std.testing.expectEqual(
            @min(
                @as(usize, typed_load_store.LOOKUP_BATCH_SIZE),
                typed_load_store.LOOKUP_COUNT -
                    batch * typed_load_store.LOOKUP_BATCH_SIZE,
            ),
            batch_column.entry_count,
        );
    }
    try std.testing.expect(native_events.next() == null);
}

test "typed signed LB exact high-bit cohort matches production roots and lookups" {
    var authored = try typed_load_store.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .load_store,
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

    const bytes = [_]u8{ 0x00, 0x7f, 0x80, 0xff };
    const destinations = [_]u5{ 0, 4, 5 };
    var visited: usize = 0;
    var saw_high_bit = false;
    var saw_x0 = false;
    var saw_alias = false;
    for (0..4) |offset| {
        for (bytes) |byte| {
            for (destinations) |rd| {
                const row = try support.honestLbRow(.{
                    .offset = @intCast(offset),
                    .selected_byte = byte,
                    .rd = rd,
                    .rs1 = 5,
                    .clock = @intCast(2 + visited),
                });
                try support.evaluateInto(&authored.arena, &bindings, &row, actual_values);
                try imported.imported.replay(&row, expected_values);
                try std.testing.expect(support.rowAccepted(&authored, actual_values));
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
                        support.eventNumeratorValue(actual_values, actual_effect).toU32(),
                    );
                    for (support.effectFields(&authored, lookup_index), imported.lookupFields(lookup_index).?) |
                        actual_field,
                        expected_field,
                    | try std.testing.expectEqual(
                        expected_values[types.idIndex(expected_field)].toU32(),
                        actual_values[types.idIndex(actual_field)].toU32(),
                    );
                }
                saw_high_bit = saw_high_bit or byte >= 0x80;
                saw_x0 = saw_x0 or rd == 0;
                saw_alias = saw_alias or rd == 5;
                visited += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 48), visited);
    try std.testing.expect(saw_high_bit);
    try std.testing.expect(saw_x0);
    try std.testing.expect(saw_alias);
}

test "typed signed-load identities ignore diagnostic source moves" {
    var generated = try typed_load_store.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed_load_store.build(std.testing.allocator, .{ .file = .{
        .path = "guest/load_store.air",
        .start = .{ .byte_offset = 80, .line = 10, .column = 4 },
        .end = .{ .byte_offset = 90, .line = 10, .column = 14 },
    } });
    defer moved.deinit();
    const generated_identity = try @import("digest.zig").computeIdentity(&generated.arena);
    const moved_identity = try @import("digest.zig").computeIdentity(&moved.arena);
    try std.testing.expectEqual(
        @import("digest.zig").conditional_access_format_version,
        generated_identity.format_version,
    );
    try std.testing.expectEqual(
        typed_load_store.SEMANTIC_DIGEST,
        generated_identity.bytes,
    );
    try std.testing.expectEqual(generated_identity.format_version, moved_identity.format_version);
    try std.testing.expectEqual(generated_identity.bytes, moved_identity.bytes);

    try std.testing.expectError(
        error.ConditionalAccessRequiresManifestV10,
        manifest.serializeAllocV9(std.testing.allocator, &generated.arena),
    );
    const v10 = try manifest.serializeAllocV10(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(v10);
    const current = try manifest.serializeAllocCurrent(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v10, current);
    const version_offset = manifest.magic.len;
    try std.testing.expectEqual(
        manifest.conditional_access_format_version,
        std.mem.readInt(u16, v10[version_offset..][0..2], .little),
    );
    try std.testing.expectEqual(
        manifest.conditional_access_logical_schema_version,
        std.mem.readInt(u16, v10[version_offset + 2 ..][0..2], .little),
    );
}
