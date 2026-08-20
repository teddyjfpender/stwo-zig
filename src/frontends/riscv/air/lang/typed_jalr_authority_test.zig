const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/jalr_legacy_test_oracle.zig");
const authority = @import("typed_jalr_authority.zig");
const typed_jalr = @import("typed_jalr.zig");
const witness = @import("typed_jalr_witness.zig");

const Production = @import("../constraint_program.zig").Builder(QM31);

test "JALR fixed authority binding is source independent pointer-free and pinned" {
    var generated = try typed_jalr.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var relocated = try typed_jalr.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/control/jalr.air",
        .start = .{ .byte_offset = 91, .line = 7, .column = 3 },
        .end = .{ .byte_offset = 117, .line = 7, .column = 29 },
    } });
    defer relocated.deinit();

    const binding = try authority.Binding.canonical(&generated);
    const relocated_binding = try authority.Binding.canonical(&relocated);
    try std.testing.expectEqualDeep(binding, relocated_binding);
    try std.testing.expectEqual(typed_jalr.SEMANTIC_DIGEST, binding.semantic_digest);
    try std.testing.expectEqual(
        witness.WITNESS_BINDING_DIGEST,
        binding.witness_binding_digest,
    );
    try std.testing.expectEqual(
        authority.AUTHORITY_BINDING_DIGEST,
        binding.identityDigest(),
    );
    const admitted = try authority.Authority.init(&generated, &binding);
    const relocated_admitted = try authority.Authority.init(
        &relocated,
        &relocated_binding,
    );
    try std.testing.expectEqualDeep(admitted, authority.Authority.pinned());
    try std.testing.expectEqual(
        admitted.identityDigest(),
        relocated_admitted.identityDigest(),
    );
    try std.testing.expect(!@typeInfo(authority.Authority).@"struct".is_tuple);
}

test "JALR authority rejects semantic witness target direct and relation mutations" {
    var definition = try typed_jalr.build(std.testing.allocator, .generated);
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
    malformed.control_target.immediate_bits = 13;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.control_target.admitted_target_alignment = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.control_target.program_address_bits = 31;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.control_target.destination_access_ordinal = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(
        authority.DirectRecipe,
        &malformed.direct[5],
        &malformed.direct[6],
    );
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].role = .request;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[10].domain = .range_check_8_8;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[15].access_ordinal = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);
}

test "JALR authority direct roots and ordered relations equal independent legacy polynomials" {
    const admitted = try authenticatedAuthority();
    var prng = std.Random.DefaultPrng.init(0x4a41_4c52_4155_5431);
    const random = prng.random();

    for (0..96) |_| {
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&columns) |*column| column.* = randomSecure(random);
        const pc_polynomial = columns[2];
        const is_active = randomSecure(random);

        const Legacy = legacy.Semantics(QM31);
        const legacy_row = try Legacy.Row.fromMainColumns(&columns);
        const legacy_direct = Legacy.evaluate(legacy_row);
        const legacy_placement = Legacy.placementConstraint(
            legacy_row,
            is_active,
        );
        const expected_lookups = legacyLookupProgram(QM31, legacy_row);
        const actual = try admitted.buildProgram(
            QM31,
            &columns,
            pc_polynomial,
            is_active,
        );

        for (legacy_direct.values, actual.direct_constraints.values[0..22]) |
            expected,
            got,
        | try std.testing.expect(expected.eql(got));
        try std.testing.expect(
            legacy_placement.eql(actual.direct_constraints.values[22]),
        );
        try expectLookupListsEqual(QM31, expected_lookups, actual.lookup_entries);
    }
}

test "JALR authority owns target link x0 aliases witness and AIR boundaries" {
    const admitted = try authenticatedAuthority();
    const cases = [_]struct {
        pc: u32,
        source: u32,
        immediate: i32,
        rd: u5,
        rs1: u5,
    }{
        .{ .pc = 0, .source = 0, .immediate = 0, .rd = 0, .rs1 = 0 },
        .{ .pc = 0x1000, .source = 0x2001, .immediate = -1, .rd = 1, .rs1 = 2 },
        .{ .pc = 0x20_0000, .source = 0x10_0800, .immediate = -2048, .rd = 31, .rs1 = 31 },
        .{ .pc = 0x3fff_fffc, .source = 0x3fff_f800, .immediate = 2044, .rd = 7, .rs1 = 5 },
        .{ .pc = 0x100, .source = 0xffff_f804, .immediate = 2044, .rd = 9, .rs1 = 9 },
    };

    var rows: [cases.len]authority.TraceRow = undefined;
    for (&rows, cases, 0..) |*row, case, index| {
        const instruction = jalrInstruction(case.rd, case.rs1, case.immediate);
        const retirement = try admitted.retire(
            instruction,
            case.pc,
            if (case.rs1 == 0) 0 else case.source,
        );
        const target = ((if (case.rs1 == 0) 0 else case.source) +%
            @as(u32, @bitCast(case.immediate))) & ~@as(u32, 1);
        try std.testing.expectEqual(case.pc +% 4, retirement.attempted_value);
        try std.testing.expectEqual(
            if (case.rd == 0) 0 else case.pc +% 4,
            retirement.visible_value,
        );
        try std.testing.expectEqual(target, retirement.next_pc);
        row.* = makeRow(
            case.pc,
            case.source,
            case.immediate,
            case.rd,
            case.rs1,
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
            scalars[2],
            QM31.one(),
        );
        try std.testing.expect(result.direct_constraints.allZero());
        try std.testing.expectEqual(
            authority.LOOKUP_COUNT,
            result.lookup_entries.len,
        );
    }

    try std.testing.expectError(
        error.WrongJalrOpcode,
        admitted.retire(.{
            .opcode = .JAL,
            .rd = 1,
            .rs1 = 0,
            .rs2 = 0,
            .imm = 0,
        }, 0, 0),
    );
    try std.testing.expectError(
        error.InvalidJalrImmediate,
        admitted.retire(jalrInstruction(1, 2, 4096), 0, 0),
    );
    try std.testing.expectError(
        error.MisalignedProgramCounter,
        admitted.retire(jalrInstruction(1, 2, 0), 2, 0),
    );
    try std.testing.expectError(
        error.ProgramCounterOutOfRange,
        admitted.retire(jalrInstruction(1, 2, 0), 0x4000_0000, 0),
    );
    try std.testing.expectError(
        error.MisalignedJumpTarget,
        admitted.retire(jalrInstruction(1, 2, 0), 0, 2),
    );
    try std.testing.expectError(
        error.JumpTargetOutOfRange,
        admitted.retire(jalrInstruction(1, 2, 0), 0, 0x4000_0000),
    );
}

test "JALR authority rejects forged rows atomically and releases allocation failures" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = makeRow(0x1000, 0x2001, -1, 3, 2, 2);

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
    forged.rd_prev_clk = 6;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.is_store = true;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "JALR production direct and lookup evaluators retain legacy throughput" {
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
        "\n  JALR production authority: direct={d} ns legacy={d} ns " ++
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
    var definition = try typed_jalr.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try authority.Binding.canonical(&definition);
    return authority.Authority.init(&definition, &binding);
}

fn expectInvalidBinding(
    definition: *const typed_jalr.Definition,
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
    var definition = try typed_jalr.build(allocator, .generated);
    defer definition.deinit();
    const binding = try authority.Binding.canonical(&definition);
    _ = try authority.Authority.init(&definition, &binding);
}

fn jalrInstruction(rd: u5, rs1: u5, immediate: i32) authority.DecodedInst {
    return .{
        .opcode = .JALR,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = @truncate(@as(u32, @bitCast(immediate))),
        .imm = immediate,
    };
}

fn makeRow(
    pc: u32,
    source_unadjusted: u32,
    immediate: i32,
    rd: u5,
    rs1: u5,
    clock: u32,
) authority.TraceRow {
    const source = if (rs1 == 0) 0 else source_unadjusted;
    const target = (source +% @as(u32, @bitCast(immediate))) & ~@as(u32, 1);
    const source_clock = access_clock(clock, 0);
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = .JALR,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = @truncate(@as(u32, @bitCast(immediate))),
        .imm = immediate,
        .rs1_val = source,
        .rs2_val = 0,
        .rs1_prev_clk = 0,
        .rs2_prev_clk = 0,
        .rd_prev_val = if (rd == 0) 0 else if (rd == rs1) source else 0x1122_3344,
        .rd_prev_clk = if (rd == rs1) source_clock else 0,
        .rd_val = if (rd == 0) 0 else pc +% 4,
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

inline fn access_clock(clock: u32, phase: u32) u32 {
    return (clock - 1) * 4 + phase + 1;
}

fn legacyLookupProgram(
    comptime S: type,
    row: legacy.Semantics(S).Row,
) entry.Builder(S).List {
    const e = entry.Builder(S);
    const requests = legacy.Semantics(S).lookups(row);
    var result = e.List{};
    e.program(&result, requests.program.numerator, requests.program.tuple);
    e.accessAt(&result, requests.rs1, 1);
    e.range88(
        &result,
        requests.rs1_middle_bytes.numerator,
        requests.rs1_middle_bytes.tuple.values(),
    );
    e.range88(
        &result,
        requests.rs1_outer_bytes.numerator,
        requests.rs1_outer_bytes.tuple.values(),
    );
    e.range20(
        &result,
        requests.target_word_low_20.numerator,
        requests.target_word_low_20.tuple.value,
    );
    e.range88(
        &result,
        requests.target_word_high_8.numerator,
        requests.target_word_high_8.tuple.values(),
    );
    e.range88(
        &result,
        requests.target_middle_bytes.numerator,
        requests.target_middle_bytes.tuple.values(),
    );
    e.rangeM31(
        &result,
        requests.target_m31.numerator,
        requests.target_m31.tuple.values(),
    );
    e.range884(
        &result,
        requests.immediate_range.numerator,
        requests.immediate_range.tuple.values(),
    );
    e.stateRequests(&result, requests.state);
    e.range88(
        &result,
        requests.rd_middle_bytes.numerator,
        requests.rd_middle_bytes.tuple.values(),
    );
    e.rangeM31(
        &result,
        requests.rd_m31.numerator,
        requests.rd_m31.tuple.values(),
    );
    e.accessAt(&result, requests.rd, 2);
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
        try Production.buildDirectInto(
            .jalr,
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
        try Production.buildLookupsInto(
            .jalr,
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
