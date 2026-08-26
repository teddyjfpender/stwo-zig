const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/div_legacy_test_oracle.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_div_authority.zig");
const corpus = @import("typed_div_corpus.zig");
const support = @import("typed_div_test_support.zig");
const typed = @import("typed_div.zig");
const witness = @import("typed_div_witness.zig");
const legacy_writer = @import("../../runner/witness/div_legacy_test_oracle.zig");
const Opcode = @import("../../isa/decode.zig").Opcode;

const OPERATIONS = [_]Opcode{ .DIV, .DIVU, .REM, .REMU };

test "DIV fixed authority is pinned pointer-free and source independent" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/m-extension/div.air",
        .start = .{ .byte_offset = 351, .line = 18, .column = 2 },
        .end = .{ .byte_offset = 419, .line = 20, .column = 20 },
    } });
    defer relocated.deinit();

    const binding = try authority.Binding.canonical(&generated);
    const admitted = try authority.Authority.init(&generated, &binding);
    const moved_binding = try authority.Binding.canonical(&relocated);
    const moved = try authority.Authority.init(&relocated, &moved_binding);
    try std.testing.expectEqualDeep(binding, moved_binding);
    try std.testing.expectEqual(typed.SEMANTIC_DIGEST, binding.semantic_digest);
    try std.testing.expectEqual(
        witness.WITNESS_BINDING_DIGEST,
        binding.witness_binding_digest,
    );
    try std.testing.expectEqual(
        authority.AUTHORITY_BINDING_DIGEST,
        binding.identityDigest(),
    );
    try std.testing.expectEqual(admitted.identityDigest(), moved.identityDigest());
    try std.testing.expectEqualDeep(admitted, authority.Authority.pinned());
    try std.testing.expect(!containsPointer(authority.Binding));
    try std.testing.expect(!containsPointer(authority.Authority));
    try std.testing.expectEqual(@as(usize, 67), authority.MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 79), authority.DIRECT_CONSTRAINT_COUNT);
    try std.testing.expectEqual(@as(usize, 25), authority.LOOKUP_COUNT);
    try std.testing.expectEqual(@as(usize, 1), authority.LOOKUP_BATCH_SIZE);

    for (OPERATIONS) |opcode| {
        const instruction = inst(opcode, 4, 3, 2);
        const retired = try admitted.retire(instruction, 0x8000_0000, 0xffff_ffff);
        try std.testing.expectEqual(
            independentResult(opcode, 0x8000_0000, 0xffff_ffff),
            retired.visible_value,
        );
    }
}

test "DIV authority rejects every authenticated binding surface" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = try authority.Binding.canonical(&definition);

    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    inline for (0..4) |index| {
        malformed = canonical;
        malformed.opcode_ids[index] +%= 1;
        try expectInvalidBinding(&definition, malformed);
    }
    malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.witness_binding_digest[31] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.main_column_count +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.execution = .reserved;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(authority.DirectRecipe, &malformed.direct[35], &malformed.direct[36]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(authority.LookupDescriptor, &malformed.lookups[17], &malformed.lookups[18]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[9].domain = .range_check_8_11;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[19].arity = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].role = .consume;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[22].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 2;
    try expectInvalidBinding(&definition, malformed);
}

test "DIV authority rejects forged typed roots effects and range evidence" {
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.model.roots[35] = malformed.model.roots[36];
        try std.testing.expectError(
            error.InvalidDivDefinition,
            authority.Authority.init(&malformed, &binding),
        );
    }
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.arena.range_refinements.items[5].source = malformed.columns.pc;
        try std.testing.expectError(
            error.InvalidRangeRefinement,
            authority.Authority.init(&malformed, &binding),
        );
    }
}

test "DIV roots placement and ordered lookups exactly equal legacy symbols" {
    const admitted = try authenticatedAuthority();
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    for (&columns) |*column| column.* = arena.column("");
    const selector = arena.column("is_active");
    const Legacy = legacy.Semantics(symbolic.Scalar);
    const row = try Legacy.Row.fromOracleColumns(&columns);
    const direct = Legacy.evaluate(row);
    const placement = Legacy.placementConstraint(row, selector);
    const lookups = legacyLookups(symbolic.Scalar, row);
    const nodes_before = arena.nodes.items.len;

    const actual = try admitted.buildProgram(symbolic.Scalar, &columns, selector);
    try std.testing.expectEqual(nodes_before, arena.nodes.items.len);
    for (direct.values, actual.direct_constraints.values[0..direct.values.len]) |
        expected,
        got,
    | try std.testing.expectEqual(expected.id, got.id);
    try std.testing.expectEqual(
        placement.id,
        actual.direct_constraints.values[direct.values.len].id,
    );
    try expectLookupListsEqual(symbolic.Scalar, lookups, actual.lookup_entries);
}

test "DIV authority owns exact operand classes special cases aliases x0 and AIR" {
    const admitted = try authenticatedAuthority();
    var columns = try OwnedColumns.init(std.testing.allocator, 1 << 9, M31.zero());
    defer columns.deinit();
    var rows: [corpus.CORPUS_ROW_COUNT]authority.TraceRow = undefined;
    var visited: usize = 0;
    for (0..corpus.OPERAND_CLASS_COUNT) |class_index| {
        const operands = corpus.operandClass(class_index);
        for (OPERATIONS) |opcode| {
            rows[visited] = canonicalCorpusRow(opcode, operands, visited);
            const retirement = try admitted.retire(
                inst(opcode, rows[visited].rd, rows[visited].rs1, rows[visited].rs2),
                rows[visited].rs1_val,
                rows[visited].rs2_val,
            );
            try std.testing.expectEqual(
                independentResult(
                    opcode,
                    rows[visited].rs1_val,
                    rows[visited].rs2_val,
                ),
                retirement.attempted_value,
            );
            try std.testing.expectEqual(rows[visited].rd_val, retirement.visible_value);
            visited += 1;
        }
    }
    try std.testing.expectEqual(corpus.CORPUS_ROW_COUNT, visited);
    try admitted.generateMainInto(&columns.views, &rows, 9);

    for (rows, 0..) |row, row_index| {
        var expected_storage: [authority.MAIN_COLUMN_COUNT][1]M31 =
            .{.{M31.zero()}} ** authority.MAIN_COLUMN_COUNT;
        var expected_views: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&expected_storage, &expected_views) |*owned, *view| view.* = owned;
        legacy_writer.writeRow(&expected_views, 0, row);
        for (columns.views, expected_storage) |actual_column, expected|
            try std.testing.expectEqual(expected[0], actual_column[row_index]);

        var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&scalars, columns.views) |*scalar, column|
            scalar.* = QM31.fromBase(column[row_index]);
        const program = try admitted.buildProgram(QM31, &scalars, QM31.one());
        try std.testing.expect(program.direct_constraints.allZero());
        try std.testing.expect(programAccepted(program));
    }

    try std.testing.expectError(
        error.WrongDivOpcode,
        admitted.retire(inst(.MUL, 1, 2, 3), 7, 9),
    );
    try std.testing.expectError(
        error.InvalidImmediate,
        admitted.retire(.{ .opcode = .DIV, .rd = 1, .rs1 = 2, .rs2 = 3, .imm = 1 }, 7, 9),
    );
}

test "DIV arithmetic exhausts every byte pair and signed architectural boundaries" {
    for (0..256) |lhs| for (0..256) |rhs| for (OPERATIONS) |opcode| {
        const lhs32: u32 = @intCast(lhs);
        const rhs32: u32 = @intCast(rhs);
        try std.testing.expectEqual(
            independentResult(opcode, lhs32, rhs32),
            authority.resultFor(opcode, lhs32, rhs32),
        );
    };

    const boundaries = [_]u32{
        0,           1,           2,           3,           7, 0x7fff_ffff, 0x8000_0000, 0x8000_0001,
        0xffff_fff9, 0xffff_fffd, 0xffff_fffe, 0xffff_ffff,
    };
    for (boundaries) |lhs| for (boundaries) |rhs| for (OPERATIONS) |opcode| {
        try std.testing.expectEqual(
            independentResult(opcode, lhs, rhs),
            authority.resultFor(opcode, lhs, rhs),
        );
    };
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), authority.resultFor(.DIV, 7, 0));
    try std.testing.expectEqual(@as(u32, 7), authority.resultFor(.REM, 7, 0));
    try std.testing.expectEqual(
        @as(u32, 0x8000_0000),
        authority.resultFor(.DIV, 0x8000_0000, 0xffff_ffff),
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        authority.resultFor(.REM, 0x8000_0000, 0xffff_ffff),
    );
}

test "DIV quotient remainder carry sign and bound mutation matrix rejects" {
    const admitted = try authenticatedAuthority();
    const Mutation = struct {
        opcode: Opcode,
        operands: corpus.OperandClass,
        column: usize,
        replacement: u32,
    };
    const mutations = [_]Mutation{
        .{ .opcode = .REM, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 34, .replacement = 99 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 38, .replacement = 99 },
        .{ .opcode = .DIVU, .operands = .{ .lhs = 97, .rhs = 0 }, .column = 32, .replacement = 0 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 0x8000_0000, .rhs = 0xffff_ffff }, .column = 33, .replacement = 0 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 0xffff_fff9, .rhs = 3 }, .column = 42, .replacement = 0 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 7, .rhs = 0xffff_fffd }, .column = 43, .replacement = 0 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 7, .rhs = 0xffff_fffd }, .column = 44, .replacement = 0 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 7, .rhs = 0xffff_fffd }, .column = 45, .replacement = 0 },
        .{ .opcode = .DIVU, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 46, .replacement = 0 },
        .{ .opcode = .DIVU, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 47, .replacement = 0 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 0xffff_fff9, .rhs = 3 }, .column = 52, .replacement = 0 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 0xffff_fff9, .rhs = 3 }, .column = 48, .replacement = 7 },
        .{ .opcode = .DIVU, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 56, .replacement = 0 },
        .{ .opcode = .DIVU, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 60, .replacement = 2 },
        .{ .opcode = .DIVU, .operands = .{ .lhs = 100, .rhs = 2 }, .column = 28, .replacement = 256 },
        .{ .opcode = .REM, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 34, .replacement = 256 },
        .{ .opcode = .DIV, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 66, .replacement = 0 },
    };
    for (mutations, 0..) |mutation, index| {
        var row = try support.honestRow(mutation.opcode, mutation.operands, index + 1);
        row[mutation.column] = M31.fromCanonical(mutation.replacement);
        const program = try buildProgramFromM31(&admitted, row);
        try std.testing.expect(!programAccepted(program));
    }

    var forged = try support.honestRow(.REMU, .{ .lhs = 7, .rhs = 3 }, 1);
    forged[34] = M31.fromCanonical(3);
    const forged_program = try buildProgramFromM31(&admitted, forged);
    try std.testing.expect(forged_program.direct_constraints.allZero());
    try std.testing.expect(!programAccepted(forged_program));
}

test "DIV authority rejects malformed rows before any write" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = try corpus.traceRow(.DIV, .{ .lhs = 0x8000_1234, .rhs = 3 }, 5);

    inline for (.{
        "word",               "opcode",              "immediate",           "clock",          "next_pc",
        "result",             "source_1_x0",         "source_2_x0",         "destination_x0", "source_alias_value",
        "source_alias_clock", "destination_1_alias", "destination_2_alias", "source_1_gap",   "source_2_gap",
        "destination_gap",    "load",                "store",               "branch",
    }) |mutation| {
        var forged = honest;
        if (std.mem.eql(u8, mutation, "word")) forged.inst_word ^= 1 << 20;
        if (std.mem.eql(u8, mutation, "opcode")) forged.opcode = .MUL;
        if (std.mem.eql(u8, mutation, "immediate")) forged.imm = 1;
        if (std.mem.eql(u8, mutation, "clock")) forged.clk = 0;
        if (std.mem.eql(u8, mutation, "next_pc")) forged.next_pc +%= 4;
        if (std.mem.eql(u8, mutation, "result")) forged.rd_val ^= 1;
        if (std.mem.eql(u8, mutation, "source_1_x0")) {
            forged.rs1 = 0;
            forged.rs1_val = 1;
        }
        if (std.mem.eql(u8, mutation, "source_2_x0")) {
            forged.rs2 = 0;
            forged.rs2_val = 1;
        }
        if (std.mem.eql(u8, mutation, "destination_x0")) {
            forged.rd = 0;
            forged.rd_prev_val = 1;
            forged.rd_val = 0;
        }
        if (std.mem.eql(u8, mutation, "source_alias_value")) {
            forged.rs2 = forged.rs1;
            forged.rs2_val = forged.rs1_val ^ 1;
        }
        if (std.mem.eql(u8, mutation, "source_alias_clock")) {
            forged.rs2 = forged.rs1;
            forged.rs2_val = forged.rs1_val;
            forged.rs2_prev_clk = 0;
        }
        if (std.mem.eql(u8, mutation, "destination_1_alias")) {
            forged.rd = forged.rs1;
            forged.rd_prev_val = forged.rs1_val ^ 1;
        }
        if (std.mem.eql(u8, mutation, "destination_2_alias")) {
            forged.rd = forged.rs2;
            forged.rd_prev_val = forged.rs2_val ^ 1;
        }
        if (std.mem.eql(u8, mutation, "source_1_gap")) forged.rs1_prev_clk = 37;
        if (std.mem.eql(u8, mutation, "source_2_gap")) forged.rs2_prev_clk = 38;
        if (std.mem.eql(u8, mutation, "destination_gap")) forged.rd_prev_clk = 39;
        if (std.mem.eql(u8, mutation, "load")) forged.is_load = true;
        if (std.mem.eql(u8, mutation, "store")) forged.is_store = true;
        if (std.mem.eql(u8, mutation, "branch")) forged.branch_taken = true;
        if (!std.mem.eql(u8, mutation, "word") and forged.opcode != .MUL)
            forged.inst_word = corpus.encode(
                forged.opcode,
                forged.rd,
                forged.rs1,
                forged.rs2,
            );
        try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    }
}

test "DIV authority construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "DIV fixed direct evaluator strictly preserves legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const admitted = try authenticatedAuthority();
    const row_count = 1 << 9;
    const rows = try std.testing.allocator.alloc(
        [authority.MAIN_COLUMN_COUNT]QM31,
        row_count,
    );
    defer std.testing.allocator.free(rows);
    for (rows, 0..) |*row, row_index| for (row, 0..) |*value, column_index| {
        const seed = @as(u64, row_index + 1) *% 0x9e37_79b1 +%
            @as(u64, column_index + 1) *% 0x85eb_ca77;
        value.* = QM31.fromM31(
            M31.fromU64(seed),
            M31.fromU64(seed *% 3),
            M31.fromU64(seed *% 5),
            M31.fromU64(seed *% 7),
        );
    };
    const active = QM31.fromBase(M31.fromCanonical(17));
    _ = try measureFixed(&admitted, rows, active, 1 << 8);
    _ = try measureLegacy(rows, active, 1 << 8);
    const samples = 13;
    const iterations = 1 << 16;
    var fixed: [samples]u64 = undefined;
    var old: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        fixed[sample] = try measureFixed(&admitted, rows, active, iterations);
        old[sample] = try measureLegacy(rows, active, iterations);
    } else {
        old[sample] = try measureLegacy(rows, active, iterations);
        fixed[sample] = try measureFixed(&admitted, rows, active, iterations);
    };
    const fixed_median = median(&fixed);
    const old_median = median(&old);
    std.debug.print(
        "\n  DIV fixed direct={d} ns legacy={d} ns speed={d:.4}x\n",
        .{ fixed_median, old_median, @as(f64, @floatFromInt(old_median)) /
            @as(f64, @floatFromInt(fixed_median)) },
    );
    try std.testing.expect(
        @as(u128, fixed_median) * 97 <= @as(u128, old_median) * 100,
    );
}

fn authenticatedAuthority() !authority.Authority {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try authority.Binding.canonical(&definition);
    return authority.Authority.init(&definition, &binding);
}

fn expectInvalidBinding(definition: *const typed.Definition, binding: authority.Binding) !void {
    try std.testing.expectError(
        error.InvalidAuthorityBinding,
        authority.Authority.init(definition, &binding),
    );
}

fn expectInvalidRowAtomic(
    admitted: *const authority.Authority,
    columns: *[authority.MAIN_COLUMN_COUNT][]M31,
    storage: *const [authority.MAIN_COLUMN_COUNT][4]M31,
    row: authority.TraceRow,
    sentinel: M31,
) !void {
    try std.testing.expectError(
        error.InvalidTraceRow,
        admitted.generateMainInto(columns, &.{row}, 2),
    );
    for (storage) |column| for (column) |value|
        try std.testing.expectEqual(sentinel, value);
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
    const binding = try authority.Binding.canonical(&definition);
    _ = try authority.Authority.init(&definition, &binding);
}

fn buildProgramFromM31(
    admitted: *const authority.Authority,
    row: [support.ROW_WIDTH]M31,
) !authority.Evaluator(QM31).ConstraintProgram {
    var columns: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
    for (&columns, row[0..authority.MAIN_COLUMN_COUNT]) |*value, limb|
        value.* = QM31.fromBase(limb);
    return admitted.buildProgram(
        QM31,
        &columns,
        QM31.fromBase(row[authority.MAIN_COLUMN_COUNT]),
    );
}

fn programAccepted(program: authority.Evaluator(QM31).ConstraintProgram) bool {
    if (!program.direct_constraints.allZero()) return false;
    for (program.lookup_entries.entries[0..program.lookup_entries.len]) |request| {
        if (request.numerator.isZero()) continue;
        const first = request.values[0].tryIntoM31() catch return false;
        const valid = switch (request.domain) {
            .range_check_20 => first.toU32() < 1 << 20,
            .range_check_8_11 => blk: {
                const second = request.values[1].tryIntoM31() catch break :blk false;
                break :blk first.toU32() < 256 and second.toU32() < 1 << 11;
            },
            .range_check_8_8 => blk: {
                const second = request.values[1].tryIntoM31() catch break :blk false;
                break :blk first.toU32() < 256 and second.toU32() < 256;
            },
            .range_check_m31 => blk: {
                const second = request.values[1].tryIntoM31() catch break :blk false;
                break :blk first.toU32() < 256 and second.toU32() < 128;
            },
            else => true,
        };
        if (!valid) return false;
    }
    return true;
}

fn legacyLookups(
    comptime S: type,
    row: legacy.Semantics(S).Row,
) entry.Builder(S).List {
    const module = legacy.Semantics(S);
    const e = entry.Builder(S);
    const lookups = module.lookups(row);
    var list = e.List{ .batch_size = module.LOOKUP_BATCH_SIZE };
    e.program(&list, lookups.program.numerator, lookups.program.tuple);
    e.stateRequests(&list, lookups.state);
    e.accessAt(&list, lookups.rs1, 1);
    e.accessAt(&list, lookups.rs2, 2);
    for (lookups.divisor_ranges) |request|
        e.range88(&list, request.numerator, request.tuple.values());
    for (lookups.quotient_remainder_ranges) |request|
        e.range811(&list, request.numerator, request.tuple.values());
    e.rangeM31(
        &list,
        lookups.quotient_sign_range.numerator,
        lookups.quotient_sign_range.tuple.values(),
    );
    e.range88(
        &list,
        lookups.sign_range.numerator,
        lookups.sign_range.tuple.values(),
    );
    e.range20(
        &list,
        lookups.positive_remainder_diff.numerator,
        lookups.positive_remainder_diff.tuple.value,
    );
    e.accessAt(&list, lookups.rd, 3);
    return list;
}

fn expectLookupListsEqual(
    comptime S: type,
    expected: entry.Builder(S).List,
    actual: entry.Builder(S).List,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected.batch_size, actual.batch_size);
    for (expected.entries[0..expected.len], actual.entries[0..actual.len]) |
        want,
        got,
    | {
        try std.testing.expectEqual(want.domain, got.domain);
        try std.testing.expectEqual(want.role, got.role);
        try std.testing.expectEqual(want.arity, got.arity);
        try std.testing.expectEqual(want.access_ordinal, got.access_ordinal);
        try std.testing.expectEqual(want.numerator.id, got.numerator.id);
        for (want.values[0..want.arity], got.values[0..got.arity]) |
            want_value,
            got_value,
        | try std.testing.expectEqual(want_value.id, got_value.id);
    }
}

fn inst(opcode: Opcode, rd: u5, rs1: u5, rs2: u5) authority.DecodedInst {
    return .{ .opcode = opcode, .rd = rd, .rs1 = rs1, .rs2 = rs2, .imm = 0 };
}

fn independentResult(opcode: Opcode, lhs: u32, rhs: u32) u32 {
    return switch (opcode) {
        .DIV => blk: {
            if (rhs == 0) break :blk std.math.maxInt(u32);
            if (lhs == 0x8000_0000 and rhs == 0xffff_ffff) break :blk lhs;
            const signed_lhs: i32 = @bitCast(lhs);
            const signed_rhs: i32 = @bitCast(rhs);
            break :blk @bitCast(@divTrunc(signed_lhs, signed_rhs));
        },
        .DIVU => if (rhs == 0) std.math.maxInt(u32) else lhs / rhs,
        .REM => blk: {
            if (rhs == 0) break :blk lhs;
            if (lhs == 0x8000_0000 and rhs == 0xffff_ffff) break :blk 0;
            const signed_lhs: i32 = @bitCast(lhs);
            const signed_rhs: i32 = @bitCast(rhs);
            break :blk @bitCast(@rem(signed_lhs, signed_rhs));
        },
        .REMU => if (rhs == 0) lhs else lhs % rhs,
        else => unreachable,
    };
}

fn canonicalCorpusRow(
    opcode: Opcode,
    operands: corpus.OperandClass,
    index: usize,
) authority.TraceRow {
    const rs1: u5 = if (index % 37 == 0) 0 else 5;
    const rs2: u5 = if (index % 41 == 0)
        rs1
    else if (index % 43 == 0)
        0
    else
        6;
    const rd: u5 = if (index % 11 == 0)
        0
    else if (index % 7 == 0)
        rs1
    else if (index % 13 == 0)
        rs2
    else
        10;
    const clock: u32 = @intCast(index + 100);
    const source_1_clock = (clock - 1) * 4 + 1;
    const source_2_clock = source_1_clock + 1;
    const lhs = if (rs1 == 0) 0 else operands.lhs;
    const rhs = if (rs2 == 0)
        0
    else if (rs2 == rs1)
        lhs
    else
        operands.rhs;
    const previous = if (rd == 0)
        0
    else if (rd == rs2)
        rhs
    else if (rd == rs1)
        lhs
    else
        @as(u32, @truncate(0x1122_3344 +% index));
    const previous_clock = if (rd == rs2)
        source_2_clock
    else if (rd == rs1)
        source_1_clock
    else
        0;
    const result = independentResult(opcode, lhs, rhs);
    return .{
        .clk = clock,
        .pc = @intCast(0x1000 + index * 4),
        .opcode = opcode,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .imm = 0,
        .rs1_val = lhs,
        .rs2_val = rhs,
        .rs1_prev_clk = 0,
        .rs2_prev_clk = if (rs2 == rs1) source_1_clock else 0,
        .rd_prev_val = previous,
        .rd_prev_clk = previous_clock,
        .rd_val = if (rd == 0) 0 else result,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = @intCast(0x1004 + index * 4),
        .inst_word = corpus.encode(opcode, rd, rs1, rs2),
    };
}

const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    views: [authority.MAIN_COLUMN_COUNT][]M31,

    fn init(allocator: std.mem.Allocator, rows: usize, fill: M31) !OwnedColumns {
        const storage = try allocator.alloc(M31, authority.MAIN_COLUMN_COUNT * rows);
        @memset(storage, fill);
        var result = OwnedColumns{
            .allocator = allocator,
            .storage = storage,
            .views = undefined,
        };
        for (&result.views, 0..) |*view, column|
            view.* = storage[column * rows ..][0..rows];
        return result;
    }

    fn deinit(self: *OwnedColumns) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

fn measureFixed(
    admitted: *const authority.Authority,
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0;
    for (0..iterations) |index| {
        const direct = try admitted.evaluateDirect(
            QM31,
            &rows[index & (rows.len - 1)],
            active,
        );
        for (direct.values) |value| checksum +%= value.toM31Array()[0].v;
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn measureLegacy(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    const Legacy = legacy.Semantics(QM31);
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0;
    for (0..iterations) |index| {
        const row = try Legacy.Row.fromOracleColumns(&rows[index & (rows.len - 1)]);
        const direct = Legacy.evaluate(row);
        for (direct.values) |value| checksum +%= value.toM31Array()[0].v;
        checksum +%= Legacy.placementConstraint(row, active).toM31Array()[0].v;
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}

fn containsPointer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .array => |array| containsPointer(array.child),
        .optional => |optional| containsPointer(optional.child),
        .@"struct" => |structure| blk: {
            inline for (structure.fields) |field|
                if (containsPointer(field.type)) break :blk true;
            break :blk false;
        },
        .@"union" => |union_info| blk: {
            inline for (union_info.fields) |field|
                if (containsPointer(field.type)) break :blk true;
            break :blk false;
        },
        else => false,
    };
}
