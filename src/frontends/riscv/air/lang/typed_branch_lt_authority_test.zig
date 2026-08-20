const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/branch_lt_legacy_test_oracle.zig");
const authority = @import("typed_branch_lt_authority.zig");
const typed = @import("typed_branch_lt.zig");
const witness = @import("typed_branch_lt_witness.zig");

const Production = @import("../constraint_program.zig").Builder(QM31);

test "BRANCH_LT fixed authority binding is source independent pointer-free and pinned" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/control/branch_lt.air",
        .start = .{ .byte_offset = 37, .line = 3, .column = 5 },
        .end = .{ .byte_offset = 89, .line = 3, .column = 57 },
    } });
    defer relocated.deinit();

    const binding = try authority.Binding.canonical(&generated);
    const relocated_binding = try authority.Binding.canonical(&relocated);
    try std.testing.expectEqualDeep(binding, relocated_binding);
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
    const moved = try authority.Authority.init(&relocated, &relocated_binding);
    try std.testing.expectEqualDeep(admitted, authority.Authority.pinned());
    try std.testing.expectEqual(admitted.identityDigest(), moved.identityDigest());
    try std.testing.expect(!@typeInfo(authority.Authority).@"struct".is_tuple);
}

test "BRANCH_LT authority rejects semantic witness execution direct and relation mutations" {
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
        &malformed.direct[10],
        &malformed.direct[11],
    );
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].role = .request;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[9].domain = .range_check_20;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[6].access_ordinal = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);
}

test "BRANCH_LT authority direct roots and ordered relations equal independent legacy polynomials" {
    const admitted = try authenticatedAuthority();
    var prng = std.Random.DefaultPrng.init(0x4252_4c54_4155_5431);
    const random = prng.random();

    for (0..96) |_| {
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&columns) |*column| column.* = randomSecure(random);
        const active = randomSecure(random);
        const Legacy = legacy.Semantics(QM31);
        const legacy_row = try Legacy.Row.fromMainColumns(&columns);
        const legacy_direct = Legacy.evaluate(legacy_row);
        const legacy_placement = Legacy.placementConstraint(legacy_row, active);
        const expected_lookups = legacyLookupProgram(QM31, legacy_row);
        const actual = try admitted.buildProgram(
            QM31,
            &columns,
            columns[1],
            columns[32],
            active,
        );

        for (legacy_direct.values, actual.direct_constraints.values[0..32]) |
            expected,
            got,
        | try std.testing.expect(expected.eql(got));
        try std.testing.expect(
            legacy_placement.eql(actual.direct_constraints.values[32]),
        );
        try expectLookupListsEqual(QM31, expected_lookups, actual.lookup_entries);
    }
}

test "BRANCH_LT authority owns signed unsigned decisions targets aliases witness and AIR" {
    const admitted = try authenticatedAuthority();
    const cases = [_]struct {
        opcode: authority.Opcode,
        lhs: u32,
        rhs: u32,
        immediate: i32,
        rs1: u5,
        rs2: u5,
    }{
        .{ .opcode = .BLT, .lhs = 0xffff_ffff, .rhs = 0, .immediate = -4, .rs1 = 1, .rs2 = 2 },
        .{ .opcode = .BLTU, .lhs = 0xffff_ffff, .rhs = 0, .immediate = 8, .rs1 = 3, .rs2 = 4 },
        .{ .opcode = .BGE, .lhs = 0x8000_0000, .rhs = 0x7fff_ffff, .immediate = 12, .rs1 = 5, .rs2 = 6 },
        .{ .opcode = .BGEU, .lhs = 9, .rhs = 9, .immediate = 4092, .rs1 = 7, .rs2 = 7 },
        .{ .opcode = .BLT, .lhs = 0, .rhs = 1, .immediate = -4096, .rs1 = 0, .rs2 = 8 },
        .{ .opcode = .BLTU, .lhs = 1, .rhs = 2, .immediate = 4, .rs1 = 9, .rs2 = 10 },
    };

    var rows: [cases.len]authority.TraceRow = undefined;
    for (&rows, cases, 0..) |*row, case, index| {
        const instruction = branchInstruction(
            case.opcode,
            case.rs1,
            case.rs2,
            case.immediate,
        );
        const source_1 = if (case.rs1 == 0) 0 else case.lhs;
        const source_2 = if (case.rs2 == 0) 0 else if (case.rs2 == case.rs1)
            source_1
        else
            case.rhs;
        const retirement = try admitted.retire(
            instruction,
            0x20_0000,
            source_1,
            source_2,
        );
        try std.testing.expectEqual(
            authority.branchCondition(
                case.opcode,
                source_1,
                source_2,
            ),
            retirement.taken,
        );
        row.* = try makeRow(
            &admitted,
            0x20_0000,
            case.opcode,
            source_1,
            source_2,
            case.immediate,
            case.rs1,
            case.rs2,
            @intCast(index + 1),
        );
    }

    var storage: [authority.MAIN_COLUMN_COUNT][8]M31 = undefined;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    try admitted.generateMainInto(&columns, &rows, 3);
    for (rows, 0..) |_, row_index| {
        var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&scalars, columns) |*scalar, column|
            scalar.* = QM31.fromBase(column[row_index]);
        const result = try admitted.buildProgram(
            QM31,
            &scalars,
            scalars[1],
            scalars[32],
            QM31.one(),
        );
        try std.testing.expect(result.direct_constraints.allZero());
        try std.testing.expectEqual(authority.LOOKUP_COUNT, result.lookup_entries.len);
    }

    try std.testing.expectError(
        error.WrongBranchLtOpcode,
        admitted.retire(branchInstruction(.BEQ, 1, 2, 0), 0, 0, 0),
    );
    try std.testing.expectError(
        error.InvalidImmediate,
        admitted.retire(branchInstruction(.BLT, 1, 2, 3), 0, 0, 1),
    );
    try std.testing.expectError(
        error.InstructionAddressMisaligned,
        admitted.retire(branchInstruction(.BLT, 1, 2, 0), 2, 0, 1),
    );
    try std.testing.expectError(
        error.TargetOutOfRange,
        admitted.retire(
            branchInstruction(.BGEU, 1, 2, 4),
            authority.PC_BOUND - 4,
            1,
            1,
        ),
    );
    try std.testing.expectError(
        error.InstructionAddressMisaligned,
        admitted.retire(branchInstruction(.BLTU, 1, 2, 2), 0, 0, 1),
    );
}

test "BRANCH_LT authority rejects forged rows atomically and releases allocation failures" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = try makeRow(&admitted, 0x1000, .BLTU, 1, 2, 8, 1, 2, 2);

    var forged = honest;
    forged.next_pc +%= 4;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.branch_taken = !forged.branch_taken;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.rs1_prev_clk = 5;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.rs2_prev_clk = 6;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.mem_addr = 4;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "BRANCH_LT production direct and lookup evaluators retain legacy throughput" {
    if (builtin.mode != .ReleaseFast) return;
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
    _ = try measureProductionDirect(rows, active, 1 << 11);
    _ = try measureLegacyDirect(rows, active, 1 << 11);
    _ = try measureProductionLookups(rows, 1 << 11);
    _ = try measureLegacyLookups(rows, 1 << 11);
    const samples = 15;
    const iterations = 1 << 16;
    var production_direct: [samples]u64 = undefined;
    var legacy_direct: [samples]u64 = undefined;
    var production_lookups: [samples]u64 = undefined;
    var legacy_lookups: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        production_direct[sample] = try measureProductionDirect(rows, active, iterations);
        legacy_direct[sample] = try measureLegacyDirect(rows, active, iterations);
        production_lookups[sample] = try measureProductionLookups(rows, iterations);
        legacy_lookups[sample] = try measureLegacyLookups(rows, iterations);
    } else {
        legacy_lookups[sample] = try measureLegacyLookups(rows, iterations);
        production_lookups[sample] = try measureProductionLookups(rows, iterations);
        legacy_direct[sample] = try measureLegacyDirect(rows, active, iterations);
        production_direct[sample] = try measureProductionDirect(rows, active, iterations);
    };
    const production_direct_median = median(&production_direct);
    const legacy_direct_median = median(&legacy_direct);
    const production_lookup_median = median(&production_lookups);
    const legacy_lookup_median = median(&legacy_lookups);
    std.debug.print(
        "\n  BRANCH_LT production authority: direct={d} ns legacy={d} ns " ++
            "speed={d:.4}x; lookups={d} ns legacy={d} ns speed={d:.4}x\n",
        .{
            production_direct_median,
            legacy_direct_median,
            @as(f64, @floatFromInt(legacy_direct_median)) /
                @as(f64, @floatFromInt(production_direct_median)),
            production_lookup_median,
            legacy_lookup_median,
            @as(f64, @floatFromInt(legacy_lookup_median)) /
                @as(f64, @floatFromInt(production_lookup_median)),
        },
    );
    try std.testing.expect(@as(u128, production_direct_median) * 97 <=
        @as(u128, legacy_direct_median) * 100);
    try std.testing.expect(@as(u128, production_lookup_median) * 97 <=
        @as(u128, legacy_lookup_median) * 100);
}

fn authenticatedAuthority() !authority.Authority {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try authority.Binding.canonical(&definition);
    return authority.Authority.init(&definition, &binding);
}

fn expectInvalidBinding(
    definition: *const typed.Definition,
    malformed: authority.Binding,
) !void {
    try std.testing.expectError(
        error.InvalidAuthorityBinding,
        authority.Authority.init(definition, &malformed),
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

fn branchInstruction(
    opcode: authority.Opcode,
    rs1: u5,
    rs2: u5,
    immediate: i32,
) authority.DecodedInst {
    return .{ .opcode = opcode, .rd = 0, .rs1 = rs1, .rs2 = rs2, .imm = immediate };
}

fn makeRow(
    admitted: *const authority.Authority,
    pc: u32,
    opcode: authority.Opcode,
    source_1_unadjusted: u32,
    source_2_unadjusted: u32,
    immediate: i32,
    rs1: u5,
    rs2: u5,
    clock: u32,
) !authority.TraceRow {
    const source_1 = if (rs1 == 0) 0 else source_1_unadjusted;
    const source_2 = if (rs2 == 0) 0 else if (rs2 == rs1)
        source_1
    else
        source_2_unadjusted;
    const retirement = try admitted.retire(
        branchInstruction(opcode, rs1, rs2, immediate),
        pc,
        source_1,
        source_2,
    );
    const source_1_clock = accessClock(clock, 1);
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = opcode,
        .rd = 0,
        .rs1 = rs1,
        .rs2 = rs2,
        .imm = immediate,
        .rs1_val = source_1,
        .rs2_val = source_2,
        .rs1_prev_clk = 0,
        .rs2_prev_clk = if (rs1 == rs2) source_1_clock else 0,
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
        .branch_taken = retirement.branch_taken,
        .next_pc = retirement.next_pc,
        .inst_word = 0,
    };
}

inline fn accessClock(clock: u32, phase: u32) u32 {
    return (clock - 1) * 4 + phase;
}

fn legacyLookupProgram(
    comptime S: type,
    row: legacy.Semantics(S).Row,
) entry.Builder(S).List {
    const e = entry.Builder(S);
    const requests = legacy.Semantics(S).lookups(row);
    var result = e.List{};
    e.program(&result, requests.program.numerator, requests.program.tuple);
    e.stateRequests(&result, requests.state);
    e.accessAt(&result, requests.rs1, 1);
    e.accessAt(&result, requests.rs2, 2);
    e.range88(
        &result,
        requests.ranges.shifted_msls.numerator,
        requests.ranges.shifted_msls.tuple.values(),
    );
    e.range20(
        &result,
        requests.ranges.positive_difference.numerator,
        requests.ranges.positive_difference.tuple.value,
    );
    return result;
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
        try std.testing.expect(want.numerator.eql(got.numerator));
        for (want.values[0..want.arity], got.values[0..got.arity]) |
            want_value,
            got_value,
        | try std.testing.expect(want_value.eql(got_value));
    }
}

fn measureProductionDirect(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0x6a09_e667_f3bc_c909;
    for (0..iterations) |index| {
        const row = &rows[index & (rows.len - 1)];
        var direct: Production.DirectConstraints = undefined;
        try Production.buildBranchLtDirectInto(
            row,
            active,
            &direct,
        );
        std.debug.assert(direct.len == authority.DIRECT_CONSTRAINT_COUNT);
        for (direct.values[0..direct.len]) |value|
            absorbScalar(&checksum, value);
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
        const row = try Legacy.Row.fromMainColumns(
            &rows[index & (rows.len - 1)],
        );
        const direct = Legacy.evaluate(row);
        for (direct.values) |value| absorbScalar(&checksum, value);
        absorbScalar(&checksum, Legacy.placementConstraint(row, active));
    }
    const elapsed = timer.read();
    std.mem.doNotOptimizeAway(checksum);
    return elapsed;
}

fn measureProductionLookups(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0xbb67_ae85_84ca_a73b;
    for (0..iterations) |index| {
        var result: entry.List = undefined;
        try Production.buildBranchLtLookupsInto(
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
        const row = try Legacy.Row.fromMainColumns(
            &rows[index & (rows.len - 1)],
        );
        const result = legacyLookupProgram(QM31, row);
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
