const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/mul_legacy_test_oracle.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_mul_authority.zig");
const corpus = @import("typed_mul_corpus.zig");
const typed = @import("typed_mul.zig");
const witness = @import("typed_mul_witness.zig");

test "MUL fixed authority is pinned pointer-free and source independent" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/m-extension/mul.air",
        .start = .{ .byte_offset = 251, .line = 14, .column = 2 },
        .end = .{ .byte_offset = 319, .line = 16, .column = 20 },
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
    try std.testing.expectEqual(@as(usize, 39), authority.MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 17), authority.DIRECT_CONSTRAINT_COUNT);
    try std.testing.expectEqual(@as(usize, 16), authority.LOOKUP_COUNT);
    try std.testing.expectEqual(@as(usize, 1), authority.LOOKUP_BATCH_SIZE);

    generated.deinit();
    const retired = try admitted.retire(instruction(4, 3, 2), 0xffff_ffff, 2);
    try std.testing.expectEqual(@as(u32, 0xffff_fffe), retired.visible_value);
}

test "MUL authority rejects every authenticated binding surface" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = try authority.Binding.canonical(&definition);

    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.opcode_id +%= 1;
    try expectInvalidBinding(&definition, malformed);
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
    std.mem.swap(authority.DirectRecipe, &malformed.direct[8], &malformed.direct[9]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(
        authority.LookupDescriptor,
        &malformed.lookups[9],
        &malformed.lookups[10],
    );
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[9].domain = .range_check_8_8;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[9].arity = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].role = .consume;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[13].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 2;
    try expectInvalidBinding(&definition, malformed);
}

test "MUL authority rejects forged typed roots and range evidence" {
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.model.roots[8] = malformed.model.roots[9];
        try std.testing.expectError(
            error.InvalidMulDefinition,
            authority.Authority.init(&malformed, &binding),
        );
    }
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.arena.range_refinements.items[0].source = malformed.columns.pc;
        try std.testing.expectError(
            error.InvalidRangeRefinement,
            authority.Authority.init(&malformed, &binding),
        );
    }
}

test "MUL roots placement and ordered lookups exactly equal legacy symbols" {
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

test "MUL authority owns boundary corpus aliases x0 witness carries and AIR" {
    const admitted = try authenticatedAuthority();
    var columns = try OwnedColumns.init(
        std.testing.allocator,
        corpus.CORPUS_ROW_COUNT,
        M31.zero(),
    );
    defer columns.deinit();
    var rows: [corpus.CORPUS_ROW_COUNT]authority.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        const base = corpus.traceRow(index);
        row.* = makeRow(
            base.rd,
            base.rs1,
            base.rs2,
            base.rs1_val,
            base.rs2_val,
            base.clk,
            base.pc,
            base.rd_prev_val,
        );
        const retirement = try admitted.retire(
            instruction(row.rd, row.rs1, row.rs2),
            row.rs1_val,
            row.rs2_val,
        );
        try std.testing.expectEqual(
            independentLowProduct(row.rs1_val, row.rs2_val),
            retirement.attempted_value,
        );
        try std.testing.expectEqual(row.rd_val, retirement.visible_value);
    }
    try admitted.generateMainInto(&columns.views, &rows, 8);
    for (rows, 0..) |_, row_index| {
        var expected_storage: [authority.MAIN_COLUMN_COUNT][1]M31 =
            .{.{M31.zero()}} ** authority.MAIN_COLUMN_COUNT;
        var expected_views: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&expected_storage, &expected_views) |*owned, *view| view.* = owned;
        witness.writeActiveRow(&expected_views, 0, rows[row_index]);
        for (columns.views, expected_storage) |column, expected|
            try std.testing.expectEqual(expected[0], column[row_index]);

        var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&scalars, columns.views) |*scalar, column|
            scalar.* = QM31.fromBase(column[row_index]);
        const program = try admitted.buildProgram(QM31, &scalars, QM31.one());
        try std.testing.expect(program.direct_constraints.allZero());
        try std.testing.expectEqual(authority.LOOKUP_COUNT, program.lookup_entries.len);
        for (program.lookup_entries.entries[9..13]) |request| {
            const result_limb = try request.values[0].tryIntoM31();
            const carry = try request.values[1].tryIntoM31();
            try std.testing.expect(result_limb.toU32() < 256);
            try std.testing.expect(carry.toU32() < 1 << 11);
        }
    }

    try std.testing.expectError(
        error.WrongMulOpcode,
        admitted.retire(.{ .opcode = .MULH, .rd = 1, .rs1 = 2, .rs2 = 3, .imm = 0 }, 7, 9),
    );
    try std.testing.expectError(
        error.InvalidImmediate,
        admitted.retire(.{ .opcode = .MUL, .rd = 1, .rs1 = 2, .rs2 = 3, .imm = 1 }, 7, 9),
    );
}

test "MUL range tuples exhaust every byte product and exact carry" {
    const admitted = try authenticatedAuthority();
    for (0..256) |lhs| for (0..256) |rhs| {
        const product = lhs * rhs;
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 =
            .{QM31.zero()} ** authority.MAIN_COLUMN_COUNT;
        columns[0] = QM31.one();
        columns[1] = q(1);
        columns[2] = q(0x1000);
        columns[3] = q(1);
        columns[9] = q(product & 0xff);
        columns[10] = q(product >> 8);
        columns[13] = q(2);
        columns[14] = q(lhs);
        columns[19] = q(lhs);
        columns[23] = q(3);
        columns[24] = q(rhs);
        columns[29] = q(rhs);
        columns[33] = q(product & 0xff);
        columns[34] = q(product >> 8);
        columns[37] = QM31.one();
        columns[38] = QM31.one();
        const program = try admitted.buildProgram(QM31, &columns, QM31.one());
        try std.testing.expect(program.direct_constraints.allZero());
        const first = program.lookup_entries.entries[9];
        try std.testing.expect((try first.values[0].tryIntoM31()).toU32() ==
            product & 0xff);
        try std.testing.expect((try first.values[1].tryIntoM31()).toU32() ==
            product >> 8);
        for (program.lookup_entries.entries[10..13], 0..) |request, index| {
            const expected_result: u32 = if (index == 0) @intCast(product >> 8) else 0;
            try std.testing.expectEqual(
                expected_result,
                (try request.values[0].tryIntoM31()).toU32(),
            );
            try std.testing.expect((try request.values[1].tryIntoM31()).isZero());
        }
    };
}

test "MUL adversarial high-word and field-alias products fail exact range evidence" {
    const admitted = try authenticatedAuthority();
    const Case = struct { lhs: u32, rhs: u32, forged: [4]u32 };
    const cases = [_]Case{
        .{ .lhs = 1, .rhs = 1, .forged = .{ 2, 0, 0, 0 } },
        .{ .lhs = 0xffff_ffff, .rhs = 0xffff_ffff, .forged = .{ 2, 0, 0, 0 } },
        .{ .lhs = 0x8000_0000, .rhs = 0x8000_0000, .forged = .{ 0, 0, 0, 1 } },
        .{ .lhs = 0xffff_ff00, .rhs = 0x0101_0101, .forged = .{ 256, 0, 0, 0 } },
        .{ .lhs = 0x7fff_ffff, .rhs = 0xffff_ffff, .forged = .{ 0x7fff_ffff, 0, 0, 0 } },
    };
    for (cases) |case| {
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 = .{QM31.zero()} **
            authority.MAIN_COLUMN_COUNT;
        const row = makeRow(3, 1, 2, case.lhs, case.rhs, 9, 0x1000, 0x1122_3344);
        var storage: [authority.MAIN_COLUMN_COUNT][1]M31 =
            .{.{M31.zero()}} ** authority.MAIN_COLUMN_COUNT;
        var views: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&storage, &views) |*owned, *view| view.* = owned;
        admitted.writeActiveRow(&views, 0, row);
        for (&columns, views) |*scalar, view| scalar.* = QM31.fromBase(view[0]);
        inline for (0..4) |limb| {
            columns[33 + limb] = QM31.fromBase(M31.fromU64(case.forged[limb]));
            columns[9 + limb] = columns[33 + limb];
        }
        const program = try admitted.buildProgram(QM31, &columns, QM31.one());
        try std.testing.expect(program.direct_constraints.allZero());
        var saw_out_of_range = false;
        for (program.lookup_entries.entries[9..13]) |request| {
            const result_limb = try request.values[0].tryIntoM31();
            const carry = try request.values[1].tryIntoM31();
            saw_out_of_range = saw_out_of_range or
                result_limb.toU32() >= 256 or carry.toU32() >= 1 << 11;
        }
        try std.testing.expect(saw_out_of_range);
    }
}

test "MUL authority rejects malformed rows before any write" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = makeRow(3, 1, 2, 0x8000_1234, 0xffff_ffff, 2, 0x1000, 9);

    inline for (.{
        "word",               "opcode",              "immediate",           "clock",          "next_pc",
        "result",             "source_1_x0",         "source_2_x0",         "destination_x0", "source_alias_value",
        "source_alias_clock", "destination_1_alias", "destination_2_alias", "source_1_gap",   "source_2_gap",
        "destination_gap",    "load",                "store",               "branch",
    }) |mutation| {
        var forged = honest;
        if (std.mem.eql(u8, mutation, "word")) forged.inst_word ^= 1 << 20;
        if (std.mem.eql(u8, mutation, "opcode")) forged.opcode = .MULH;
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
        if (std.mem.eql(u8, mutation, "source_1_gap")) forged.rs1_prev_clk = 5;
        if (std.mem.eql(u8, mutation, "source_2_gap")) forged.rs2_prev_clk = 6;
        if (std.mem.eql(u8, mutation, "destination_gap")) forged.rd_prev_clk = 7;
        if (std.mem.eql(u8, mutation, "load")) forged.is_load = true;
        if (std.mem.eql(u8, mutation, "store")) forged.is_store = true;
        if (std.mem.eql(u8, mutation, "branch")) forged.branch_taken = true;
        if (!std.mem.eql(u8, mutation, "word") and forged.opcode == .MUL)
            forged.inst_word = encode(forged.rd, forged.rs1, forged.rs2);
        try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    }
}

test "MUL authority construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "MUL fixed direct evaluator strictly preserves legacy throughput" {
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
    _ = try measureFixed(&admitted, rows, active, 1 << 9);
    _ = try measureLegacy(rows, active, 1 << 9);
    const samples = 13;
    // Keep each paired sample long enough to dominate scheduler/timer noise;
    // this evaluator is deliberately small (seventeen quadratic roots).
    const iterations = 1 << 18;
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
        "\n  MUL fixed direct={d} ns legacy={d} ns speed={d:.4}x\n",
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
    for (lookups.product_ranges) |request|
        e.range811(&list, request.numerator, request.tuple.values());
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

fn instruction(rd: u5, rs1: u5, rs2: u5) authority.DecodedInst {
    return .{ .opcode = .MUL, .rd = rd, .rs1 = rs1, .rs2 = rs2, .imm = 0 };
}

fn encode(rd: u5, rs1: u5, rs2: u5) u32 {
    return (1 << 25) | (@as(u32, rs2) << 20) | (@as(u32, rs1) << 15) |
        (@as(u32, rd) << 7) | 0x33;
}

fn independentLowProduct(lhs: u32, rhs: u32) u32 {
    return @truncate(@as(u64, lhs) * @as(u64, rhs));
}

fn q(value: usize) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}

fn makeRow(
    rd: u5,
    rs1: u5,
    rs2: u5,
    lhs: u32,
    rhs: u32,
    clock: u32,
    pc: u32,
    previous: u32,
) authority.TraceRow {
    const source_1_clock = (clock - 1) * 4 + 1;
    const source_2_clock = (clock - 1) * 4 + 2;
    const source_2_previous = if (rs2 == rs1) source_1_clock else 0;
    const source_2_value = if (rs2 == rs1) lhs else rhs;
    const destination_previous_clock = if (rd == rs2)
        source_2_clock
    else if (rd == rs1)
        source_1_clock
    else
        0;
    const destination_previous_value = if (rd == 0)
        0
    else if (rd == rs2)
        source_2_value
    else if (rd == rs1)
        lhs
    else
        previous;
    const product = independentLowProduct(lhs, source_2_value);
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = .MUL,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = rs2,
        .imm = 0,
        .rs1_val = if (rs1 == 0) 0 else lhs,
        .rs2_val = if (rs2 == 0) 0 else source_2_value,
        .rs1_prev_clk = 0,
        .rs2_prev_clk = source_2_previous,
        .rd_prev_val = destination_previous_value,
        .rd_prev_clk = destination_previous_clock,
        .rd_val = if (rd == 0) 0 else product,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc +% 4,
        .inst_word = encode(rd, rs1, rs2),
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
