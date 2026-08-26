const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const compat_layout = @import("compat_layout.zig");
const degree = @import("degree.zig");
const digest = @import("digest.zig");
const legacy = @import("../../runner/witness/branch_eq_legacy_test_oracle.zig");
const manifest = @import("manifest.zig");
const polynomial = @import("typed_load_store_polynomial_test_support.zig");
const program = @import("program.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const support = @import("typed_branch_eq_test_support.zig");
const TraceRow = @import("../../runner/trace_row.zig").TraceRow;
const Opcode = @import("../../isa/decode.zig").Opcode;
const typed = @import("typed_branch_eq.zig");
const types = @import("types.zig");
const witness_layout = @import("../../witness_layout.zig");

const Binding = polynomial.Binding;
const ROW_WIDTH = typed.MAIN_COLUMN_COUNT + 1;

test "typed BRANCH_EQ has exact physical direct and ordered-effect compatibility" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .branch_eq,
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

    for (authored.columns.physical(), witness_layout.columnNames(.branch_eq)) |
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

    const authored_bindings = fingerprintBindings(&authored);
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
            std.log.err("BRANCH_EQ direct fingerprint mismatch at {d}", .{index});
            return error.DirectFingerprintMismatch;
        }
    }

    const expected_kinds = [_]program.EffectKind{
        .program_fetch,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .register_read,
        .state_consume,
        .state_produce,
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
    }
}

test "typed BRANCH_EQ identity is pinned source-independent and requires manifest v11" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var moved = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "moved/control/branch_eq.air",
        .start = .{ .byte_offset = 71, .line = 9, .column = 3 },
        .end = .{ .byte_offset = 99, .line = 9, .column = 31 },
    } });
    defer moved.deinit();

    const generated_identity = try digest.computeIdentity(&generated.arena);
    const moved_identity = try digest.computeIdentity(&moved.arena);
    try std.testing.expectEqual(
        digest.program_control_target_format_version,
        generated_identity.format_version,
    );
    try std.testing.expectEqual(generated_identity, moved_identity);
    try std.testing.expectEqual(
        generated_identity.bytes,
        try digest.computeV9(&generated.arena),
    );
    try std.testing.expectEqual(typed.SEMANTIC_DIGEST, generated_identity.bytes);
    const rendered = std.fmt.bytesToHex(generated_identity.bytes, .lower);
    try std.testing.expectEqualStrings(typed.SEMANTIC_DIGEST_HEX, &rendered);
    try std.testing.expectError(
        error.ProgramControlTargetRequiresManifestV11,
        manifest.serializeAllocV10(std.testing.allocator, &generated.arena),
    );
    const v11 = try manifest.serializeAllocV11(std.testing.allocator, &generated.arena);
    defer std.testing.allocator.free(v11);
    const current = try manifest.serializeAllocCurrent(
        std.testing.allocator,
        &generated.arena,
    );
    defer std.testing.allocator.free(current);
    try std.testing.expectEqualSlices(u8, v11, current);
}

test "typed BRANCH_EQ honest boundary and randomized rows match production" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .branch_eq,
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
        makeRow(.BEQ, 0, 0, 0, 0, -4096, 1, 0x20_000, 0, 0),
        makeRow(.BEQ, 1, 2, 0, 1, 4092, 2, 0x30_000, 0, 0),
        makeRow(.BEQ, 31, 30, 0xffff_ffff, 0xffff_ffff, 0, 3, 0x40_000, 0, 0),
        makeRow(.BNE, 3, 4, 0x1122_3344, 0x1122_3344, 8, 4, 0x50_000, 0, 0),
        makeRow(.BNE, 7, 7, 9, 10, -8, 5, 0x60_000, 0, 0),
    };
    for (fixed) |trace_row| try expectAcceptedParity(
        &authored,
        &imported,
        &bindings,
        &semanticRow(trace_row),
        actual_values,
        expected_values,
    );

    var prng = std.Random.DefaultPrng.init(0x4252_414e_4348_4551);
    const random = prng.random();
    for (0..256) |index| {
        const trace_row = makeRow(
            if ((index & 1) == 0) .BEQ else .BNE,
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
        try expectAcceptedParity(
            &authored,
            &imported,
            &bindings,
            &semanticRow(trace_row),
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

test "typed BRANCH_EQ rejects selector decision inverse equality and access forgeries" {
    var authored = try typed.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);
    const base = semanticRow(makeRow(
        .BNE,
        3,
        4,
        0x0102_0304,
        0x0102_0305,
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
    forged[23] = M31.fromCanonical(2);
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[28] = M31.one();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[24] = M31.zero();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[23] = M31.zero();
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[8] = forged[8].add(M31.one());
    try expectRejected(&authored, &bindings, &forged, values);
    forged = base;
    forged[18] = forged[18].add(M31.one());
    try expectRejected(&authored, &bindings, &forged, values);
}

test "typed BRANCH_EQ construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn fingerprintBindings(authored: *const typed.Definition) [ROW_WIDTH]Binding {
    var bindings: [ROW_WIDTH]Binding = undefined;
    for (authored.columns.physical(), bindings[0..typed.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed.MAIN_COLUMN_COUNT] = .{
        .value = authored.is_active,
        .column = typed.MAIN_COLUMN_COUNT,
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
    legacy.writeRow(&views, 0, trace_row);
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

fn makeRow(
    opcode: Opcode,
    rs1: u5,
    rs2: u5,
    raw_rs1_value: u32,
    raw_rs2_value: u32,
    immediate: i32,
    clock: u32,
    pc: u32,
    rs1_previous_clock: u32,
    raw_rs2_previous_clock: u32,
) TraceRow {
    const source_1_clock = (clock - 1) *% 4 +% 1;
    const rs1_value = if (rs1 == 0) 0 else raw_rs1_value;
    const rs2_value = if (rs2 == 0)
        0
    else if (rs2 == rs1)
        rs1_value
    else
        raw_rs2_value;
    const equal = rs1_value == rs2_value;
    const taken = if (opcode == .BEQ) equal else !equal;
    const target = if (taken)
        pc +% @as(u32, @bitCast(immediate))
    else
        pc +% 4;
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = opcode,
        .rd = 0,
        .rs1 = rs1,
        .rs2 = rs2,
        .imm = immediate,
        .rs1_val = rs1_value,
        .rs2_val = rs2_value,
        .rs1_prev_clk = rs1_previous_clock,
        .rs2_prev_clk = if (rs2 == rs1) source_1_clock else raw_rs2_previous_clock,
        .rd_prev_val = 0,
        .rd_prev_clk = 0,
        .rd_val = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = target != pc +% 4,
        .next_pc = target,
        .inst_word = 0,
    };
}
