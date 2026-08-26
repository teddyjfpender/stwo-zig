const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const manifest = @import("manifest.zig");
const polynomial = @import("typed_load_store_polynomial_test_support.zig");
const program = @import("program.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const support = @import("typed_branch_lt_test_support.zig");
const typed = @import("typed_branch_lt.zig");
const witness_support = @import("typed_branch_lt_witness_test_support.zig");
const legacy_oracle = @import("../../runner/witness/branch_lt_legacy_test_oracle.zig");
const TraceRow = @import("../../runner/trace_row.zig").TraceRow;
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

const Binding = polynomial.Binding;
const ROW_WIDTH = typed.MAIN_COLUMN_COUNT + 1;
const AUTHORED_BINDING_COUNT = typed.MAIN_COLUMN_COUNT + 3;

test "typed BRANCH_LT has exact physical direct and ordered-effect compatibility" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .branch_lt,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    try std.testing.expectEqual(typed.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed.LOOKUP_COUNT, imported.lookups.len);
    try std.testing.expectEqual(typed.LOOKUP_BATCH_SIZE, imported.batch_size);
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

    for (authored.columns.physical(), witness_layout.columnNames(.branch_lt)) |
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

    const authored_bindings = typedBindings(&authored);
    var production_bindings: [ROW_WIDTH]Binding = undefined;
    for (layout.main(), production_bindings[0..typed.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed.MAIN_COLUMN_COUNT,
    };
    const actual = try polynomial.fingerprintProgram(
        std.testing.allocator,
        &authored.arena,
        &authored_bindings,
    );
    defer std.testing.allocator.free(actual);
    const expected = try polynomial.fingerprintProgram(
        std.testing.allocator,
        &imported.imported.arena,
        &production_bindings,
    );
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqual(
        typed.DIRECT_CONSTRAINT_COUNT,
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
            &polynomial.fingerprintAt(actual, actual_root),
            &polynomial.fingerprintAt(expected, expected_root),
        )) {
            std.log.err("BRANCH_LT direct fingerprint mismatch at {d}", .{index});
            return error.DirectFingerprintMismatch;
        }
    }

    const expected_kinds = [_]program.EffectKind{
        .program_fetch,
        .state_consume,
        .state_produce,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .range_request,
        .range_request,
    };
    for (authored.arena.effectsView(), imported.lookups, expected_kinds, 0..) |
        actual_effect,
        expected_lookup,
        expected_kind,
        index,
    | {
        try std.testing.expectEqual(expected_kind, actual_effect.kind);
        const binding = actual_effect.binding.?;
        try std.testing.expectEqual(expected_lookup.schema, binding.schema);
        try std.testing.expectEqual(expected_lookup.role, binding.role);
        try std.testing.expectEqual(
            expected_lookup.access_ordinal,
            actual_effect.access_ordinal,
        );
        try std.testing.expectEqual(
            polynomial.fingerprintAt(expected, expected_lookup.numerator),
            polynomial.eventNumeratorFingerprint(actual, actual_effect),
        );
        const effect_id = try types.idFromIndex(types.EffectId, index);
        const actual_fields = authored.arena.effectValues(effect_id).?;
        const expected_fields = imported.lookupFields(index).?;
        try std.testing.expectEqual(expected_fields.len, actual_fields.len);
        for (actual_fields, expected_fields, 0..) |
            actual_field,
            expected_field,
            field_index,
        | try polynomial.expectFingerprintEqual(
            actual,
            actual_field,
            expected,
            expected_field,
            index,
            field_index,
            null,
        );

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

test "typed BRANCH_LT identity is pinned source-independent and requires manifest v12" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/control/branch_lt.air",
        .start = .{ .byte_offset = 71, .line = 9, .column = 3 },
        .end = .{ .byte_offset = 99, .line = 9, .column = 31 },
    } });
    defer moved.deinit();

    const generated_identity = try digest.computeIdentity(&generated.arena);
    const moved_identity = try digest.computeIdentity(&moved.arena);
    try std.testing.expectEqual(
        digest.committed_program_control_target_format_version,
        generated_identity.format_version,
    );
    try std.testing.expectEqual(generated_identity, moved_identity);
    try std.testing.expectEqual(
        generated_identity.bytes,
        try digest.computeV10(&generated.arena),
    );
    try std.testing.expectEqual(typed.SEMANTIC_DIGEST, generated_identity.bytes);
    const rendered = std.fmt.bytesToHex(generated_identity.bytes, .lower);
    try std.testing.expectEqualStrings(typed.SEMANTIC_DIGEST_HEX, &rendered);
    try std.testing.expectError(
        error.CommittedProgramControlTargetRequiresManifestV12,
        manifest.serializeAllocV11(std.testing.allocator, &generated.arena),
    );
    const v12 = try manifest.serializeAllocV12(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(v12);
    const current = try manifest.serializeAllocCurrent(
        std.testing.allocator,
        &generated.arena,
    );
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v12, current);
}

test "typed BRANCH_LT honest boundary and randomized rows match production" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .branch_lt,
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

    const fixed = [_]TraceRow{
        witness_support.makeRow(.BLT, 0, 0, 0, 0, 0, 1, 0x10_000, 0, 0),
        witness_support.makeRow(
            .BLT,
            5,
            6,
            0x8000_0000,
            0,
            -4096,
            2,
            0x20_000,
            0,
            0,
        ),
        witness_support.makeRow(
            .BLTU,
            31,
            1,
            0xffff_ffff,
            0,
            4092,
            3,
            0x30_000,
            0,
            0,
        ),
        witness_support.makeRow(
            .BGE,
            7,
            7,
            0xffff_ffff,
            0,
            8,
            4,
            0x40_000,
            0,
            0,
        ),
        witness_support.makeRow(
            .BGEU,
            3,
            4,
            1,
            2,
            -8,
            5,
            0x50_000,
            0,
            0,
        ),
    };
    for (fixed) |trace_row| {
        const row = semanticRow(trace_row);
        try expectAcceptedParity(
            &authored,
            &imported,
            &bindings,
            &row,
            actual_values,
            expected_values,
        );
    }

    const operations = [_]@TypeOf(fixed[0].opcode){ .BLT, .BLTU, .BGE, .BGEU };
    var prng = std.Random.DefaultPrng.init(0x4252_414e_4348_4c54);
    const random = prng.random();
    for (0..256) |index| {
        const trace_row = witness_support.makeRow(
            operations[index & 3],
            random.int(u5),
            random.int(u5),
            random.int(u32),
            random.int(u32),
            random.intRangeAtMost(i32, -1024, 1023) * 4,
            @intCast(index + 1000),
            @intCast(0x10_0000 + index * 4),
            random.uintLessThan(u32, 100),
            random.uintLessThan(u32, 100),
        );
        const row = semanticRow(trace_row);
        try expectAcceptedParity(
            &authored,
            &imported,
            &bindings,
            &row,
            actual_values,
            expected_values,
        );
    }

    const padding = [_]M31{M31.zero()} ** support.ROW_WIDTH;
    try expectAcceptedParity(
        &authored,
        &imported,
        &bindings,
        &padding,
        actual_values,
        expected_values,
    );
}

test "typed BRANCH_LT rejects semantic selector result marker target and access forgeries" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);
    const base = semanticRow(witness_support.makeRow(
        .BLTU,
        3,
        4,
        1,
        2,
        8,
        9,
        0x10_000,
        0,
        0,
    ));

    var forged = base;
    forged[typed.MAIN_COLUMN_COUNT] = M31.zero();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[25] = M31.fromCanonical(2);
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[33] = M31.one();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[28] = M31.one();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[26] = M31.zero();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[32] = forged[32].add(M31.one());
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[24] = forged[24].add(M31.fromCanonical(2));
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[8] = forged[8].add(M31.one());
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[22] = forged[22].add(M31.one());
    try expectRejected(&authored, &bindings, &forged, values);
}

test "typed BRANCH_LT fixed range requests reject values unconstrained by direct roots" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);
    const base = semanticRow(witness_support.makeRow(
        .BLTU,
        3,
        4,
        1,
        2,
        8,
        9,
        0x10_000,
        0,
        0,
    ));

    var forged_msl = base;
    const physical_byte = M31.fromCanonical(44);
    const non_canonical_byte = physical_byte.sub(M31.fromCanonical(256));
    inline for (.{ 6, 11, 16, 21 }) |column|
        forged_msl[column] = physical_byte;
    forged_msl[22] = non_canonical_byte;
    forged_msl[23] = non_canonical_byte;
    try support.evaluateInto(&authored.arena, &bindings, &forged_msl, values);
    try std.testing.expect(support.directConstraintsAccepted(&authored, values));
    try std.testing.expect(!support.rowAccepted(&authored, values));

    var forged_difference = base;
    const rhs = M31.fromCanonical((1 << 20) + 2);
    forged_difference[3] = M31.zero();
    forged_difference[8] = M31.zero();
    forged_difference[13] = rhs;
    forged_difference[18] = rhs;
    forged_difference[31] = rhs;
    try support.evaluateInto(&authored.arena, &bindings, &forged_difference, values);
    try std.testing.expect(support.directConstraintsAccepted(&authored, values));
    try std.testing.expect(!support.rowAccepted(&authored, values));
}

test "typed BRANCH_LT construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn typedBindings(authored: *const typed.Definition) [AUTHORED_BINDING_COUNT]Binding {
    var bindings: [AUTHORED_BINDING_COUNT]Binding = undefined;
    for (authored.columns.physical(), bindings[0..typed.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed.MAIN_COLUMN_COUNT] = .{
        .value = authored.is_active,
        .column = typed.MAIN_COLUMN_COUNT,
    };
    bindings[typed.MAIN_COLUMN_COUNT + 1] = .{
        .value = authored.pc_polynomial,
        .column = 1,
    };
    bindings[typed.MAIN_COLUMN_COUNT + 2] = .{
        .value = authored.branch_target_polynomial,
        .column = 32,
    };
    return bindings;
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed.build(allocator, .generated);
    defer authored.deinit();
    try authored.validate();
}

fn semanticRow(trace_row: TraceRow) [support.ROW_WIDTH]M31 {
    var storage: [typed.MAIN_COLUMN_COUNT][1]M31 =
        .{.{M31.zero()}} ** typed.MAIN_COLUMN_COUNT;
    var views: [typed.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&views, &storage) |*view, *column| view.* = column;
    legacy_oracle.writeRow(&views, 0, trace_row);
    var row: [support.ROW_WIDTH]M31 = undefined;
    for (storage, row[0..typed.MAIN_COLUMN_COUNT]) |column, *value|
        value.* = column[0];
    row[typed.MAIN_COLUMN_COUNT] = M31.one();
    return row;
}

fn expectAcceptedParity(
    authored: *const typed.Definition,
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
    | {
        const actual_root = authored.arena.constraint(actual_id).?.root;
        const expected_root = imported.imported.arena.constraint(expected_id).?.root;
        try std.testing.expectEqual(
            support.at(expected_values, expected_root).toU32(),
            support.at(actual_values, actual_root).toU32(),
        );
        try std.testing.expect(support.at(actual_values, actual_root).isZero());
    }
    for (authored.arena.effectsView(), imported.lookups, 0..) |
        actual_effect,
        expected_lookup,
        index,
    | {
        const liveness = support.at(actual_values, actual_effect.liveness.?);
        const signed = switch (expected_lookup.role) {
            .emit => liveness,
            .request, .consume => liveness.neg(),
        };
        try std.testing.expectEqual(
            support.at(expected_values, expected_lookup.numerator).toU32(),
            signed.toU32(),
        );
        const effect_id = try types.idFromIndex(types.EffectId, index);
        for (authored.arena.effectValues(effect_id).?, imported.lookupFields(index).?) |
            actual_field,
            expected_field,
        | try std.testing.expectEqual(
            support.at(expected_values, expected_field).toU32(),
            support.at(actual_values, actual_field).toU32(),
        );
    }
}

fn expectRejected(
    authored: *const typed.Definition,
    bindings: []const support.Binding,
    row: []const M31,
    values: []M31,
) !void {
    try support.evaluateInto(&authored.arena, bindings, row, values);
    try std.testing.expect(!support.rowAccepted(authored, values));
}
