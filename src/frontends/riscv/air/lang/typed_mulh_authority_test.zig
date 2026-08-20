const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/mulh_legacy_test_oracle.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_mulh_authority.zig");
const support = @import("typed_mulh_witness_test_support.zig");
const typed = @import("typed_mulh.zig");
const witness = @import("typed_mulh_witness.zig");
const Opcode = @import("../../isa/decode.zig").Opcode;

const CORPUS_ROW_COUNT = support.operations.len *
    support.boundary_operands.len * support.boundary_operands.len;

test "MULH fixed authority is pinned pointer-free and source independent" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/m-extension/mulh.air",
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
    try std.testing.expectEqual(@as(usize, 47), authority.MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 24), authority.DIRECT_CONSTRAINT_COUNT);
    try std.testing.expectEqual(@as(usize, 22), authority.LOOKUP_COUNT);
    try std.testing.expectEqual(@as(usize, 1), authority.LOOKUP_BATCH_SIZE);

    for (support.operations) |opcode| {
        const instruction = inst(opcode, 4, 3, 2);
        const retired = try admitted.retire(instruction, 0xffff_ffff, 2);
        try std.testing.expectEqual(
            support.result(opcode, 0xffff_ffff, 2),
            retired.visible_value,
        );
    }
}

test "MULH authority rejects every authenticated binding surface" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = try authority.Binding.canonical(&definition);

    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.semantic_format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    inline for (0..3) |index| {
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
    std.mem.swap(authority.DirectRecipe, &malformed.direct[6], &malformed.direct[7]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(authority.LookupDescriptor, &malformed.lookups[15], &malformed.lookups[16]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[9].domain = .range_check_8_8;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[17].arity = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].role = .consume;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[19].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 2;
    try expectInvalidBinding(&definition, malformed);
}

test "MULH authority rejects forged typed roots and range evidence" {
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.model.roots[6] = malformed.model.roots[7];
        try std.testing.expectError(
            error.InvalidMulhDefinition,
            authority.Authority.init(&malformed, &binding),
        );
    }
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.arena.range_refinements.items[9].source = malformed.columns.pc;
        try std.testing.expectError(
            error.InvalidRangeRefinement,
            authority.Authority.init(&malformed, &binding),
        );
    }
}

test "MULH roots placement and ordered lookups exactly equal legacy symbols" {
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

test "MULH authority owns signed boundary corpus aliases x0 witness carries and AIR" {
    const admitted = try authenticatedAuthority();
    var columns = try OwnedColumns.init(std.testing.allocator, 1 << 10, M31.zero());
    defer columns.deinit();
    var rows: [CORPUS_ROW_COUNT]authority.TraceRow = undefined;
    for (&rows, 0..) |*row, index| {
        row.* = support.corpusRow(index);
        const retirement = try admitted.retire(
            inst(row.opcode, row.rd, row.rs1, row.rs2),
            row.rs1_val,
            row.rs2_val,
        );
        try std.testing.expectEqual(
            support.result(row.opcode, row.rs1_val, row.rs2_val),
            retirement.attempted_value,
        );
        try std.testing.expectEqual(row.rd_val, retirement.visible_value);
    }
    try admitted.generateMainInto(&columns.views, &rows, 10);
    try support.expectLegacyColumns(&rows, 10, &columns.views);
    for (rows, 0..) |row, row_index| {
        var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&scalars, columns.views) |*scalar, column|
            scalar.* = QM31.fromBase(column[row_index]);
        const program = try admitted.buildProgram(QM31, &scalars, QM31.one());
        try std.testing.expect(program.direct_constraints.allZero());
        try std.testing.expectEqual(authority.LOOKUP_COUNT, program.lookup_entries.len);
        for (program.lookup_entries.entries[9..17]) |request| {
            const product_byte = try request.values[0].tryIntoM31();
            const carry = try request.values[1].tryIntoM31();
            try std.testing.expect(product_byte.toU32() < 256);
            try std.testing.expect(carry.toU32() < 1 << 11);
        }
        for (program.lookup_entries.entries[17..19]) |request| {
            const high = try request.values[1].tryIntoM31();
            if (!request.numerator.isZero()) try std.testing.expect(high.toU32() < 128);
        }
        _ = row;
    }

    try std.testing.expectError(
        error.WrongMulhOpcode,
        admitted.retire(inst(.MUL, 1, 2, 3), 7, 9),
    );
    try std.testing.expectError(
        error.InvalidImmediate,
        admitted.retire(.{ .opcode = .MULH, .rd = 1, .rs1 = 2, .rs2 = 3, .imm = 1 }, 7, 9),
    );
}

test "MULH range tuples exhaust every byte product and exact carry" {
    const admitted = try authenticatedAuthority();
    for (0..256) |lhs| for (0..256) |rhs| {
        const product = lhs * rhs;
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 =
            .{QM31.zero()} ** authority.MAIN_COLUMN_COUNT;
        columns[0] = q(1);
        columns[1] = q(0x1000);
        columns[2] = q(3);
        columns[8] = q(0);
        columns[12] = q(1);
        columns[13] = q(lhs);
        columns[18] = q(lhs);
        columns[22] = q(2);
        columns[23] = q(rhs);
        columns[28] = q(rhs);
        columns[32] = q(product & 0xff);
        columns[33] = q(product >> 8);
        columns[40] = QM31.one();
        columns[45] = QM31.one();
        columns[46] = q(3).inv() catch unreachable;
        const program = try admitted.buildProgram(QM31, &columns, QM31.one());
        try std.testing.expect(program.direct_constraints.allZero());
        const first = program.lookup_entries.entries[9];
        try std.testing.expectEqual(
            @as(u32, @intCast(product & 0xff)),
            (try first.values[0].tryIntoM31()).toU32(),
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(product >> 8)),
            (try first.values[1].tryIntoM31()).toU32(),
        );
        for (program.lookup_entries.entries[10..17], 0..) |request, index| {
            const expected_byte: u32 = if (index == 0) @intCast(product >> 8) else 0;
            try std.testing.expectEqual(
                expected_byte,
                (try request.values[0].tryIntoM31()).toU32(),
            );
            try std.testing.expect((try request.values[1].tryIntoM31()).isZero());
        }
    };
}

test "MULH forged products and sign witnesses fail exact range evidence" {
    const admitted = try authenticatedAuthority();
    const cases = [_]struct { opcode: Opcode, lhs: u32, rhs: u32 }{
        .{ .opcode = .MULH, .lhs = 0x8000_0000, .rhs = 0x7fff_ffff },
        .{ .opcode = .MULH, .lhs = 0xffff_ffff, .rhs = 0xffff_ffff },
        .{ .opcode = .MULHSU, .lhs = 0x8000_0000, .rhs = 0xffff_ffff },
        .{ .opcode = .MULHU, .lhs = 0xffff_ffff, .rhs = 0xffff_ffff },
    };
    for (cases) |case| {
        const row = support.makeRow(
            case.opcode,
            3,
            1,
            2,
            case.lhs,
            case.rhs,
            9,
            0x1000,
            0x1122_3344,
            0,
            0,
            0,
        );
        var storage: [authority.MAIN_COLUMN_COUNT][1]M31 =
            .{.{M31.zero()}} ** authority.MAIN_COLUMN_COUNT;
        var views: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&storage, &views) |*owned, *view| view.* = owned;
        admitted.writeActiveRow(&views, 0, row);
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&columns, views) |*scalar, view| scalar.* = QM31.fromBase(view[0]);

        // Keep destination constraints satisfied while forging the high half;
        // the eight-byte carry relation must be what rejects the witness.
        columns[41] = columns[41].add(q(1 << 20));
        columns[8] = columns[41];
        const forged_product = try admitted.buildProgram(QM31, &columns, QM31.one());
        try std.testing.expect(forged_product.direct_constraints.allZero());
        var saw_out_of_range = false;
        for (forged_product.lookup_entries.entries[9..17]) |request| {
            const product_byte = try request.values[0].tryIntoM31();
            const carry = try request.values[1].tryIntoM31();
            saw_out_of_range = saw_out_of_range or product_byte.toU32() >= 256 or
                carry.toU32() >= 1 << 11;
        }
        try std.testing.expect(saw_out_of_range);
    }

    for ([_]Opcode{ .MULH, .MULHSU }) |opcode| {
        const row = support.makeRow(
            opcode,
            3,
            1,
            2,
            0x8000_0000,
            0x8000_0000,
            9,
            0x1000,
            0,
            0,
            0,
            0,
        );
        var storage: [authority.MAIN_COLUMN_COUNT][1]M31 =
            .{.{M31.zero()}} ** authority.MAIN_COLUMN_COUNT;
        var views: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&storage, &views) |*owned, *view| view.* = owned;
        admitted.writeActiveRow(&views, 0, row);
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&columns, views) |*scalar, view| scalar.* = QM31.fromBase(view[0]);
        columns[36] = QM31.zero();
        const forged_sign = try admitted.buildProgram(QM31, &columns, QM31.one());
        try std.testing.expect(forged_sign.direct_constraints.allZero());
        const request = forged_sign.lookup_entries.entries[17];
        try std.testing.expect((try request.values[1].tryIntoM31()).toU32() >= 128);
    }
}

test "MULH authority rejects malformed rows before any write" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = support.makeRow(
        .MULHSU,
        3,
        1,
        2,
        0x8000_1234,
        0xffff_ffff,
        2,
        0x1000,
        9,
        0,
        0,
        0,
    );

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
        if (std.mem.eql(u8, mutation, "source_1_gap")) forged.rs1_prev_clk = 5;
        if (std.mem.eql(u8, mutation, "source_2_gap")) forged.rs2_prev_clk = 6;
        if (std.mem.eql(u8, mutation, "destination_gap")) forged.rd_prev_clk = 7;
        if (std.mem.eql(u8, mutation, "load")) forged.is_load = true;
        if (std.mem.eql(u8, mutation, "store")) forged.is_store = true;
        if (std.mem.eql(u8, mutation, "branch")) forged.branch_taken = true;
        if (!std.mem.eql(u8, mutation, "word") and forged.opcode != .MUL)
            forged.inst_word = support.encode(
                forged.opcode,
                forged.rd,
                forged.rs1,
                forged.rs2,
            );
        try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    }
}

test "MULH authority construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "MULH fixed direct evaluator strictly preserves legacy throughput" {
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
        "\n  MULH fixed direct={d} ns legacy={d} ns speed={d:.4}x\n",
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
    for (lookups.sign_ranges) |request|
        e.rangeM31(&list, request.numerator, request.tuple.values());
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

fn inst(opcode: anytype, rd: u5, rs1: u5, rs2: u5) authority.DecodedInst {
    return .{ .opcode = opcode, .rd = rd, .rs1 = rs1, .rs2 = rs2, .imm = 0 };
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
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
