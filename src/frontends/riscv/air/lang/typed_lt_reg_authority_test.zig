const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/lt_reg_legacy_test_oracle.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_lt_reg_authority.zig");
const support = @import("typed_lt_reg_witness_test_support.zig");
const typed = @import("typed_lt_reg.zig");
const witness = @import("typed_lt_reg_witness.zig");

test "LT_REG fixed authority binding is source independent pointer-free and pinned" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/compare/lt_reg.air",
        .start = .{ .byte_offset = 17, .line = 2, .column = 3 },
        .end = .{ .byte_offset = 91, .line = 4, .column = 9 },
    } });
    defer relocated.deinit();

    const binding = try authority.Binding.canonical(&generated);
    const moved_binding = try authority.Binding.canonical(&relocated);
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
    const admitted = try authority.Authority.init(&generated, &binding);
    const moved = try authority.Authority.init(&relocated, &moved_binding);
    try std.testing.expectEqualDeep(admitted, authority.Authority.pinned());
    try std.testing.expectEqual(admitted.identityDigest(), moved.identityDigest());
    try std.testing.expectEqual(@as(usize, 36), authority.DIRECT_CONSTRAINT_COUNT);
    try std.testing.expectEqual(@as(usize, 14), authority.LOOKUP_COUNT);
    try std.testing.expectEqual(@as(usize, 2), authority.LOOKUP_BATCH_SIZE);
    try std.testing.expectEqual(@as(usize, 200), @sizeOf(authority.Binding));
    try std.testing.expectEqual(@as(usize, 232), @sizeOf(authority.Authority));
    try std.testing.expect(!containsPointer(authority.Binding));
    try std.testing.expect(!containsPointer(authority.Authority));
}

test "LT_REG authority rejects semantic witness execution direct and relation mutations" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = try authority.Binding.canonical(&definition);

    var malformed = canonical;
    malformed.format_version +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.witness_binding_digest[31] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.opcode_ids[1] +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(
        authority.DirectRecipe,
        &malformed.direct[16],
        &malformed.direct[17],
    );
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].role = .request;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[9].domain = .range_check_20;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[12].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);
}

test "LT_REG authority direct roots and ordered relations equal legacy polynomials" {
    const admitted = try authenticatedAuthority();
    var prng = std.Random.DefaultPrng.init(0x4c54_5245_475f_4155);
    const random = prng.random();
    const Legacy = legacy.Semantics(QM31);

    for (0..128) |_| {
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&columns) |*column| column.* = randomSecure(random);
        const active = randomSecure(random);
        const row = try Legacy.Row.fromOracleColumns(&columns);
        const expected_direct = Legacy.evaluate(row);
        const expected_placement = Legacy.placementConstraint(row, active);
        const expected_lookups = legacyLookups(QM31, row);
        const actual = try admitted.buildProgram(QM31, &columns, active);

        for (expected_direct.values, actual.direct_constraints.values[0..35]) |
            expected,
            got,
        | try std.testing.expect(expected.eql(got));
        try std.testing.expect(
            expected_placement.eql(actual.direct_constraints.values[35]),
        );
        try expectLookupListsEqual(QM31, expected_lookups, actual.lookup_entries);
    }
}

test "LT_REG authority direct and lookup programs are symbolically identical" {
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
    const node_count_before = arena.nodes.items.len;

    const actual = try authority.Authority.pinned().buildProgram(
        symbolic.Scalar,
        &columns,
        selector,
    );
    try std.testing.expectEqual(node_count_before, arena.nodes.items.len);
    try std.testing.expectEqual(row.active().id, actual.active_row.id);
    for (direct.values, actual.direct_constraints.values[0..35], 0..) |want, got, index| {
        if (want.id != got.id)
            std.debug.print("LT_REG symbolic root mismatch {d}: {d} != {d}\n", .{ index, want.id, got.id });
        try std.testing.expectEqual(want.id, got.id);
    }
    try std.testing.expectEqual(placement.id, actual.direct_constraints.values[35].id);
    try expectLookupListsEqual(symbolic.Scalar, lookups, actual.lookup_entries);
}

test "LT_REG authority owns signed unsigned extrema aliases witness and AIR" {
    const admitted = try authenticatedAuthority();
    const cases = [_]struct {
        opcode: @import("../../runner/decode.zig").Opcode,
        rd: u5,
        rs1: u5,
        rs2: u5,
        lhs: u32,
        rhs: u32,
    }{
        .{ .opcode = .SLT, .rd = 1, .rs1 = 2, .rs2 = 3, .lhs = 0xffff_ffff, .rhs = 0 },
        .{ .opcode = .SLTU, .rd = 4, .rs1 = 5, .rs2 = 6, .lhs = 0xffff_ffff, .rhs = 0 },
        .{ .opcode = .SLT, .rd = 7, .rs1 = 8, .rs2 = 9, .lhs = 0x8000_0000, .rhs = 0x7fff_ffff },
        .{ .opcode = .SLTU, .rd = 10, .rs1 = 11, .rs2 = 12, .lhs = 0, .rhs = 0xffff_ffff },
        .{ .opcode = .SLT, .rd = 13, .rs1 = 13, .rs2 = 14, .lhs = 0x0100_0000, .rhs = 0x0100_0001 },
        .{ .opcode = .SLTU, .rd = 15, .rs1 = 16, .rs2 = 15, .lhs = 7, .rhs = 8 },
        .{ .opcode = .SLTU, .rd = 17, .rs1 = 18, .rs2 = 18, .lhs = 9, .rhs = 0 },
        .{ .opcode = .SLT, .rd = 0, .rs1 = 0, .rs2 = 19, .lhs = 0, .rhs = 1 },
    };

    var rows: [cases.len]authority.TraceRow = undefined;
    for (&rows, cases, 0..) |*row, case, index| {
        const clock: u32 = @intCast(index + 2);
        row.* = support.makeRow(
            case.opcode,
            case.rd,
            case.rs1,
            case.rs2,
            case.lhs,
            case.rhs,
            clock,
            @intCast(0x1000 + index * 4),
            0x55aa_1234,
            0,
            0,
            0,
        );
        const retirement = try admitted.retire(.{
            .opcode = case.opcode,
            .rd = case.rd,
            .rs1 = case.rs1,
            .rs2 = case.rs2,
            .imm = 0,
        }, row.rs1_val, row.rs2_val);
        try std.testing.expectEqual(support.result(case.opcode, row.rs1_val, row.rs2_val), retirement.attempted_value);
        try std.testing.expectEqual(row.rd_val, retirement.visible_value);
        try std.testing.expectEqual(case.opcode == .SLT, retirement.signed);
    }

    var storage: [authority.MAIN_COLUMN_COUNT][cases.len]M31 = undefined;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    try admitted.generateMainInto(&columns, &rows, 3);
    for (rows, 0..) |_, row_index| {
        var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&scalars, columns) |*scalar, column|
            scalar.* = QM31.fromBase(column[row_index]);
        const result = try admitted.buildProgram(QM31, &scalars, QM31.one());
        try std.testing.expect(result.direct_constraints.allZero());
        try std.testing.expectEqual(authority.LOOKUP_COUNT, result.lookup_entries.len);
    }

    try std.testing.expectError(
        error.WrongLtRegOpcode,
        admitted.retire(.{ .opcode = .ADD, .rd = 1, .rs1 = 2, .rs2 = 3, .imm = 0 }, 1, 2),
    );
    try std.testing.expectError(
        error.InvalidImmediate,
        admitted.retire(.{ .opcode = .SLT, .rd = 1, .rs1 = 2, .rs2 = 3, .imm = 1 }, 1, 2),
    );
}

test "LT_REG authority rejects forged rows atomically and releases allocation failures" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = support.makeRow(.SLTU, 3, 1, 2, 1, 2, 2, 0x1000, 0, 0, 0, 0);

    var forged = honest;
    forged.rd_val ^= 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.rs1_prev_clk = 5;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.next_pc +%= 4;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.branch_taken = true;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "LT_REG fixed direct and lookup evaluators retain legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
    const admitted = try authenticatedAuthority();
    const row_count = 1 << 10;
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
    _ = try measureFixedDirect(&admitted, rows, active, 1 << 11);
    _ = try measureLegacyDirect(rows, active, 1 << 11);
    _ = try measureFixedLookups(&admitted, rows, 1 << 11);
    _ = try measureLegacyLookups(rows, 1 << 11);
    const samples = 15;
    const iterations = 1 << 16;
    var fixed_direct: [samples]u64 = undefined;
    var legacy_direct: [samples]u64 = undefined;
    var fixed_lookups: [samples]u64 = undefined;
    var legacy_lookups: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        fixed_direct[sample] = try measureFixedDirect(&admitted, rows, active, iterations);
        legacy_direct[sample] = try measureLegacyDirect(rows, active, iterations);
        fixed_lookups[sample] = try measureFixedLookups(&admitted, rows, iterations);
        legacy_lookups[sample] = try measureLegacyLookups(rows, iterations);
    } else {
        legacy_lookups[sample] = try measureLegacyLookups(rows, iterations);
        fixed_lookups[sample] = try measureFixedLookups(&admitted, rows, iterations);
        legacy_direct[sample] = try measureLegacyDirect(rows, active, iterations);
        fixed_direct[sample] = try measureFixedDirect(&admitted, rows, active, iterations);
    };
    const fixed_direct_median = median(&fixed_direct);
    const legacy_direct_median = median(&legacy_direct);
    const fixed_lookup_median = median(&fixed_lookups);
    const legacy_lookup_median = median(&legacy_lookups);
    std.debug.print(
        "\n  LT_REG fixed authority: direct={d} ns legacy={d} ns " ++
            "speed={d:.4}x; lookups={d} ns legacy={d} ns speed={d:.4}x\n",
        .{
            fixed_direct_median,
            legacy_direct_median,
            @as(f64, @floatFromInt(legacy_direct_median)) /
                @as(f64, @floatFromInt(fixed_direct_median)),
            fixed_lookup_median,
            legacy_lookup_median,
            @as(f64, @floatFromInt(legacy_lookup_median)) /
                @as(f64, @floatFromInt(fixed_lookup_median)),
        },
    );
    try std.testing.expect(@as(u128, fixed_direct_median) * 97 <=
        @as(u128, legacy_direct_median) * 100);
    try std.testing.expect(@as(u128, fixed_lookup_median) * 97 <=
        @as(u128, legacy_lookup_median) * 100);
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
    const active = row.active();
    const accesses = module.accessLookups(row);
    const positive = module.positiveDiffLookup(row);
    var list = e.List{};
    e.program(&list, active.neg(), module.programLookup(row));
    e.stateChain(&list, module.stateLookup(row), active);
    e.accessChainAt(&list, accesses.rs1, active, 1);
    e.accessChainAt(&list, accesses.rs2, active, 2);
    e.range88(&list, active.neg(), module.mslRangeLookup(row));
    e.range20(&list, positive.numerator.neg(), positive.value);
    e.accessChainAt(&list, accesses.rd, active, 3);
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
        if (S == symbolic.Scalar) {
            try std.testing.expectEqual(want.numerator.id, got.numerator.id);
            for (want.values[0..want.arity], got.values[0..got.arity]) |
                want_value,
                got_value,
            | try std.testing.expectEqual(want_value.id, got_value.id);
        } else {
            try std.testing.expect(want.numerator.eql(got.numerator));
            for (want.values[0..want.arity], got.values[0..got.arity]) |
                want_value,
                got_value,
            | try std.testing.expect(want_value.eql(got_value));
        }
    }
}

fn measureFixedDirect(
    admitted: *const authority.Authority,
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0x6a09_e667_f3bc_c909;
    for (0..iterations) |index| {
        const direct = try admitted.evaluateDirect(
            QM31,
            &rows[index & (rows.len - 1)],
            active,
        );
        for (direct.values) |value| absorbScalar(&checksum, value);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn measureLegacyDirect(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    const Legacy = legacy.Semantics(QM31);
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0x6a09_e667_f3bc_c909;
    for (0..iterations) |index| {
        const row = try Legacy.Row.fromOracleColumns(&rows[index & (rows.len - 1)]);
        const direct = Legacy.evaluate(row);
        for (direct.values) |value| absorbScalar(&checksum, value);
        absorbScalar(&checksum, Legacy.placementConstraint(row, active));
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn measureFixedLookups(
    admitted: *const authority.Authority,
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0xbb67_ae85_84ca_a73b;
    for (0..iterations) |index| {
        var result: entry.List = undefined;
        try admitted.buildLookupsInto(
            QM31,
            &rows[index & (rows.len - 1)],
            &result,
        );
        absorbLookups(&checksum, &result);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn measureLegacyLookups(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    iterations: usize,
) !u64 {
    const Legacy = legacy.Semantics(QM31);
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0xbb67_ae85_84ca_a73b;
    for (0..iterations) |index| {
        const row = try Legacy.Row.fromOracleColumns(
            &rows[index & (rows.len - 1)],
        );
        const result = legacyLookups(QM31, row);
        absorbLookups(&checksum, &result);
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

inline fn absorbScalar(checksum: *u64, value: QM31) void {
    const limbs = value.toM31Array();
    const low = @as(u64, limbs[0].v) | (@as(u64, limbs[1].v) << 32);
    const high = @as(u64, limbs[2].v) | (@as(u64, limbs[3].v) << 32);
    checksum.* = std.math.rotl(u64, checksum.* ^ low, 17) *%
        0x9e37_79b1_85eb_ca87 ^ high;
}

fn absorbLookups(checksum: *u64, result: *const entry.List) void {
    std.debug.assert(result.len == authority.LOOKUP_COUNT);
    for (result.entries[0..result.len]) |lookup| {
        absorbScalar(checksum, lookup.numerator);
        for (lookup.values[0..lookup.arity]) |value|
            absorbScalar(checksum, value);
    }
}

fn median(values: []u64) u64 {
    std.mem.sort(u64, values, {}, std.sort.asc(u64));
    return values[values.len / 2];
}

fn randomSecure(random: std.Random) QM31 {
    return QM31.fromM31(
        M31.fromU64(random.int(u32)),
        M31.fromU64(random.int(u32)),
        M31.fromU64(random.int(u32)),
        M31.fromU64(random.int(u32)),
    );
}

fn containsPointer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => true,
        .array => |array| containsPointer(array.child),
        .optional => |optional| containsPointer(optional.child),
        .@"struct" => |info| blk: {
            inline for (info.fields) |field|
                if (containsPointer(field.type)) break :blk true;
            break :blk false;
        },
        .@"union" => |info| blk: {
            inline for (info.fields) |field|
                if (containsPointer(field.type)) break :blk true;
            break :blk false;
        },
        else => false,
    };
}
