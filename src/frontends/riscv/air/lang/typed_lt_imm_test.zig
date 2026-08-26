const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const Opcode = @import("../../runner/decode.zig").Opcode;
const legacy_oracle = @import("../../runner/witness/lt_imm_legacy_test_oracle.zig");
const manifest = @import("manifest.zig");
const polynomial = @import("typed_load_store_polynomial_test_support.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const typed_lt_imm = @import("typed_lt_imm.zig");
const support = @import("typed_lt_imm_test_support.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

const Binding = polynomial.Binding;

test "typed LT_IMM has exact physical direct and ordered-effect compatibility" {
    var authored = try typed_lt_imm.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lt_imm,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    try authored.validate();
    try std.testing.expectEqual(typed_lt_imm.MAIN_COLUMN_COUNT, layout.main().len);
    try std.testing.expectEqual(typed_lt_imm.LOOKUP_COUNT, imported.lookups.len);
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

    for (authored.columns.physical(), witness_layout.columnNames(.lt_imm)) |
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
    var production_bindings: [typed_lt_imm.MAIN_COLUMN_COUNT + 1]Binding = undefined;
    for (layout.main(), production_bindings[0..typed_lt_imm.MAIN_COLUMN_COUNT]) |
        column,
        *binding,
    | binding.* = .{ .value = column.value, .column = column.reference.local_index };
    production_bindings[typed_lt_imm.MAIN_COLUMN_COUNT] = .{
        .value = imported.selector,
        .column = typed_lt_imm.MAIN_COLUMN_COUNT,
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
        typed_lt_imm.DIRECT_CONSTRAINT_COUNT,
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
            std.log.err("LT_IMM direct fingerprint mismatch at {d}", .{index});
            return error.DirectFingerprintMismatch;
        }
    }

    const expected_kinds = [_]program.EffectKind{
        .program_fetch,
        .range_request,
        .state_consume,
        .state_produce,
        .register_read,
        .register_read,
        .register_read,
        .range_request,
        .register_write,
        .register_write,
        .register_write,
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

test "typed LT_IMM identity is pinned and diagnostic-source independent" {
    var generated = try typed_lt_imm.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed_lt_imm.build(std.testing.allocator, .{ .file = .{
        .path = "moved/compare/lt_imm.air",
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
    try std.testing.expectEqual(typed_lt_imm.SEMANTIC_DIGEST, generated_identity.bytes);
    const rendered = std.fmt.bytesToHex(generated_identity.bytes, .lower);
    try std.testing.expectEqualStrings(typed_lt_imm.SEMANTIC_DIGEST_HEX, &rendered);
    try std.testing.expectError(
        error.RangeRefinementRequiresManifestV9,
        manifest.serializeAllocV8(std.testing.allocator, &generated.arena),
    );
    const v9 = try manifest.serializeAllocV9(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(v9);
    const current = try manifest.serializeAllocCurrent(
        std.testing.allocator,
        &generated.arena,
    );
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v9, current);
}

test "typed LT_IMM honest boundary and randomized rows match production" {
    var authored = try typed_lt_imm.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lt_imm,
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

    const fixed = [_]supportRow{
        .{ .opcode = .SLTI, .source = 0, .immediate = 0, .rd = 0, .rs1 = 0, .clock = 1 },
        .{ .opcode = .SLTI, .source = 0xffff_ffff, .immediate = 0, .rd = 5, .rs1 = 5, .clock = 2 },
        .{ .opcode = .SLTI, .source = 0x8000_0000, .immediate = -2048, .rd = 31, .rs1 = 1, .clock = 3 },
        .{ .opcode = .SLTI, .source = 0x7fff_ffff, .immediate = 2047, .rd = 7, .rs1 = 2, .clock = 4 },
        .{ .opcode = .SLTIU, .source = 0, .immediate = -1, .rd = 8, .rs1 = 3, .clock = 5 },
        .{ .opcode = .SLTIU, .source = 0xffff_ffff, .immediate = -1, .rd = 9, .rs1 = 4, .clock = 6 },
        .{ .opcode = .SLTIU, .source = 2047, .immediate = 2047, .rd = 10, .rs1 = 6, .clock = 7 },
    };
    for (fixed) |config| {
        const row = honestRow(config);
        try expectAcceptedParity(
            &authored,
            &imported,
            &bindings,
            &row,
            actual_values,
            expected_values,
        );
    }

    var prng = std.Random.DefaultPrng.init(0x4c54_494d_4d2d_4149);
    const random = prng.random();
    for (0..128) |index| {
        const row = honestRow(.{
            .opcode = if ((index & 1) == 0) .SLTI else .SLTIU,
            .source = random.int(u32),
            .immediate = random.intRangeAtMost(i16, -2048, 2047),
            .rd = random.int(u5),
            .rs1 = random.int(u5),
            .clock = @intCast(index + 1),
            .rd_previous = random.int(u32),
        });
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

test "typed LT_IMM rejects semantic selector result marker and range forgeries" {
    var authored = try typed_lt_imm.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);

    const base = honestRow(.{
        .opcode = .SLTIU,
        .source = 1,
        .immediate = 2,
        .rd = 7,
        .rs1 = 3,
        .clock = 9,
    });
    var forged = base;
    forged[28] = M31.fromCanonical(2);
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[26] = M31.fromCanonical(2);
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[22] = M31.zero();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[30] = M31.one();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[33] = forged[33].add(M31.one());
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[8] = forged[8].add(M31.one());
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[18] = forged[18].add(M31.one());
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[37] = M31.zero();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[25] = M31.fromCanonical(8);
    try expectRejected(&authored, &bindings, &forged, values);
}

fn typedBindings(
    authored: *const typed_lt_imm.Definition,
) [typed_lt_imm.MAIN_COLUMN_COUNT + 1]Binding {
    var bindings: [typed_lt_imm.MAIN_COLUMN_COUNT + 1]Binding = undefined;
    for (authored.columns.physical(), bindings[0..typed_lt_imm.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed_lt_imm.MAIN_COLUMN_COUNT] = .{
        .value = authored.is_active,
        .column = typed_lt_imm.MAIN_COLUMN_COUNT,
    };
    return bindings;
}

const supportRow = struct {
    opcode: Opcode,
    source: u32,
    immediate: i32,
    rd: u5,
    rs1: u5,
    clock: u32,
    pc: u32 = 0x1000,
    rd_previous: u32 = 0x1122_3344,
};

const LegacyRow = struct {
    clk: u32,
    pc: u32,
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    rs1_val: u32,
    rs1_prev_clk: u32,
    rd_prev_val: u32,
    rd_prev_clk: u32,
    rd_val: u32,
    imm: i32,
};

fn honestRow(config: supportRow) [support.ROW_WIDTH]M31 {
    std.debug.assert(config.opcode == .SLTI or config.opcode == .SLTIU);
    std.debug.assert(config.immediate >= -2048 and config.immediate <= 2047);
    std.debug.assert(config.clock != 0);
    const source_value = if (config.rs1 == 0) 0 else config.source;
    const immediate_bits: u32 = @bitCast(config.immediate);
    const less = if (config.opcode == .SLTI)
        @as(i32, @bitCast(source_value)) < config.immediate
    else
        source_value < immediate_bits;
    const source_clock = (config.clock - 1) *% 4 +% 1;
    const writer_row = LegacyRow{
        .clk = config.clock,
        .pc = config.pc,
        .opcode = config.opcode,
        .rd = config.rd,
        .rs1 = config.rs1,
        .rs1_val = source_value,
        .rs1_prev_clk = 0,
        .rd_prev_val = if (config.rd == 0)
            0
        else if (config.rd == config.rs1)
            source_value
        else
            config.rd_previous,
        .rd_prev_clk = if (config.rd == config.rs1) source_clock else 0,
        .rd_val = if (config.rd == 0) 0 else @intFromBool(less),
        .imm = config.immediate,
    };
    var storage: [typed_lt_imm.MAIN_COLUMN_COUNT][1]M31 =
        .{.{M31.zero()}} ** typed_lt_imm.MAIN_COLUMN_COUNT;
    var views: [typed_lt_imm.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&views, &storage) |*view, *column| view.* = column;
    legacy_oracle.writeRow(&views, 0, writer_row);
    var row: [support.ROW_WIDTH]M31 = undefined;
    for (storage, row[0..typed_lt_imm.MAIN_COLUMN_COUNT]) |column, *value|
        value.* = column[0];
    row[typed_lt_imm.MAIN_COLUMN_COUNT] = M31.one();
    return row;
}

fn expectAcceptedParity(
    authored: *const typed_lt_imm.Definition,
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
    authored: *const typed_lt_imm.Definition,
    bindings: []const support.Binding,
    row: []const M31,
    values: []M31,
) !void {
    try support.evaluateInto(&authored.arena, bindings, row, values);
    try std.testing.expect(!support.rowAccepted(authored, values));
}
