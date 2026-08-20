const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/lt_imm_legacy_test_oracle.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_lt_imm_authority.zig");
const typed = @import("typed_lt_imm.zig");
const witness = @import("typed_lt_imm_witness.zig");

const Production = @import("../constraint_program.zig").Builder(QM31);

const Opcode = @import("../../isa/decode.zig").Opcode;

test "LT_IMM fixed authority is pinned pointer-free and source independent" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/compare/lt_imm.air",
        .start = .{ .byte_offset = 171, .line = 9, .column = 4 },
        .end = .{ .byte_offset = 239, .line = 11, .column = 18 },
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
    try std.testing.expectEqual(@as(usize, 37), authority.MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 33), authority.DIRECT_CONSTRAINT_COUNT);
    try std.testing.expectEqual(@as(usize, 11), authority.LOOKUP_COUNT);
    try std.testing.expectEqual(@as(usize, 2), authority.LOOKUP_BATCH_SIZE);

    generated.deinit();
    const retired = try admitted.retire(
        instruction(.SLTI, 4, 3, -1),
        0xffff_fffe,
    );
    try std.testing.expect(retired.less);
    try std.testing.expectEqual(@as(u32, 1), retired.visible_value);
}

test "LT_IMM authority rejects every authenticated binding surface" {
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
    malformed.opcode_ids[1] +%= 1;
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
    std.mem.swap(authority.DirectRecipe, &malformed.direct[16], &malformed.direct[17]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[1].domain = .range_check_8_8;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[3].role = .consume;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[8].access_ordinal = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);
}

test "LT_IMM authority rejects forged typed roots and range evidence" {
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.model.roots[10] = malformed.model.roots[11];
        try std.testing.expectError(
            error.InvalidLtImmDefinition,
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

test "LT_IMM direct roots placement and ordered lookups equal legacy symbols" {
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
    | {
        try std.testing.expectEqual(expected.id, got.id);
    }
    try std.testing.expectEqual(
        placement.id,
        actual.direct_constraints.values[direct.values.len].id,
    );
    try expectLookupListsEqual(symbolic.Scalar, lookups, actual.lookup_entries);
}

test "LT_IMM authority owns signed unsigned extrema x0 aliases witness and AIR" {
    const admitted = try authenticatedAuthority();
    const cases = [_]struct {
        opcode: Opcode,
        rd: u5,
        rs1: u5,
        source: u32,
        immediate: i32,
    }{
        .{ .opcode = .SLTI, .rd = 1, .rs1 = 2, .source = 0xffff_ffff, .immediate = 0 },
        .{ .opcode = .SLTIU, .rd = 3, .rs1 = 4, .source = 0xffff_ffff, .immediate = 0 },
        .{ .opcode = .SLTI, .rd = 5, .rs1 = 6, .source = 0x8000_0000, .immediate = 2047 },
        .{ .opcode = .SLTI, .rd = 7, .rs1 = 8, .source = 0x7fff_ffff, .immediate = -2048 },
        .{ .opcode = .SLTIU, .rd = 9, .rs1 = 10, .source = 0, .immediate = -1 },
        .{ .opcode = .SLTIU, .rd = 11, .rs1 = 12, .source = 0xffff_ffff, .immediate = -1 },
        .{ .opcode = .SLTI, .rd = 13, .rs1 = 13, .source = 0xffff_f800, .immediate = -2048 },
        .{ .opcode = .SLTIU, .rd = 0, .rs1 = 0, .source = 0, .immediate = 1 },
    };
    var rows: [cases.len]authority.TraceRow = undefined;
    for (&rows, cases, 0..) |*row, case, index| {
        const inst = instruction(
            case.opcode,
            case.rd,
            case.rs1,
            case.immediate,
        );
        const retirement = try admitted.retire(inst, case.source);
        const expected = independentResult(case.opcode, case.source, case.immediate);
        try std.testing.expectEqual(expected, retirement.attempted_value);
        try std.testing.expectEqual(
            if (case.rd == 0) @as(u32, 0) else expected,
            retirement.visible_value,
        );
        try std.testing.expectEqual(case.opcode == .SLTI, retirement.signed);
        row.* = makeRow(inst, case.source, @intCast(index + 2));
    }

    var storage: [authority.MAIN_COLUMN_COUNT][cases.len]M31 = undefined;
    var views: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &views) |*column, *view| view.* = column;
    try admitted.generateMainInto(&views, &rows, 3);
    for (rows, 0..) |_, row_index| {
        var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&scalars, views) |*scalar, column|
            scalar.* = QM31.fromBase(column[row_index]);
        const program = try admitted.buildProgram(QM31, &scalars, QM31.one());
        try std.testing.expect(program.direct_constraints.allZero());
        try std.testing.expectEqual(authority.LOOKUP_COUNT, program.lookup_entries.len);
    }

    try std.testing.expectError(
        error.WrongLtImmOpcode,
        admitted.retire(instruction(.ADDI, 1, 2, 0), 7),
    );
    try std.testing.expectError(
        error.InvalidImmediate,
        admitted.retire(instruction(.SLTI, 1, 2, 2048), 7),
    );
}

test "LT_IMM fixed authority rejects malformed rows before any write" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = makeRow(instruction(.SLTIU, 3, 2, -4), 0x1234, 2);

    inline for (.{
        "opcode",
        "immediate",
        "clock",
        "next_pc",
        "result",
        "source_x0",
        "destination_x0",
        "alias_value",
        "alias_clock",
        "source_gap",
        "destination_gap",
        "load",
        "store",
        "branch",
    }) |mutation| {
        var forged = honest;
        if (std.mem.eql(u8, mutation, "opcode")) forged.opcode = .ADDI;
        if (std.mem.eql(u8, mutation, "immediate")) forged.imm = 2048;
        if (std.mem.eql(u8, mutation, "clock")) forged.clk = 0;
        if (std.mem.eql(u8, mutation, "next_pc")) forged.next_pc +%= 4;
        if (std.mem.eql(u8, mutation, "result")) forged.rd_val ^= 1;
        if (std.mem.eql(u8, mutation, "source_x0")) {
            forged.rs1 = 0;
            forged.rs1_val = 1;
        }
        if (std.mem.eql(u8, mutation, "destination_x0")) {
            forged.rd = 0;
            forged.rd_prev_val = 1;
            forged.rd_val = 0;
        }
        if (std.mem.eql(u8, mutation, "alias_value")) {
            forged.rd = forged.rs1;
            forged.rd_prev_val = forged.rs1_val ^ 1;
        }
        if (std.mem.eql(u8, mutation, "alias_clock")) {
            forged.rd = forged.rs1;
            forged.rd_prev_val = forged.rs1_val;
            forged.rd_prev_clk = 0;
        }
        if (std.mem.eql(u8, mutation, "source_gap")) forged.rs1_prev_clk = 5;
        if (std.mem.eql(u8, mutation, "destination_gap")) forged.rd_prev_clk = 6;
        if (std.mem.eql(u8, mutation, "load")) forged.is_load = true;
        if (std.mem.eql(u8, mutation, "store")) forged.is_store = true;
        if (std.mem.eql(u8, mutation, "branch")) forged.branch_taken = true;
        try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    }
}

test "LT_IMM authority construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "LT_IMM production direct and lookup paths strictly preserve legacy throughput" {
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
    _ = admitted;
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
        "\n  LT_IMM production authority: direct={d} ns legacy={d} ns " ++
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
    e.range884(&list, active.neg(), module.immediateRangeLookup(row));
    e.stateChain(&list, module.stateLookup(row), active);
    e.accessChainAt(&list, accesses.rs1, active, 1);
    e.range20(&list, positive.numerator.neg(), positive.value);
    e.accessChainAt(&list, accesses.rd, active, 2);
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

fn instruction(
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    immediate: i32,
) authority.DecodedInst {
    return .{
        .opcode = opcode,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = @truncate(@as(u32, @bitCast(immediate))),
        .imm = immediate,
    };
}

fn independentResult(opcode: Opcode, source: u32, immediate: i32) u32 {
    return @intFromBool(switch (opcode) {
        .SLTI => @as(i32, @bitCast(source)) < immediate,
        .SLTIU => source < @as(u32, @bitCast(immediate)),
        else => unreachable,
    });
}

fn makeRow(inst: authority.DecodedInst, raw_source: u32, clock: u32) authority.TraceRow {
    const source = if (inst.rs1 == 0) 0 else raw_source;
    const source_clock = (clock - 1) * 4 + 1;
    const result = independentResult(inst.opcode, source, inst.imm);
    return .{
        .clk = clock,
        .pc = 0x2000,
        .opcode = inst.opcode,
        .rd = inst.rd,
        .rs1 = inst.rs1,
        .rs2 = inst.rs2,
        .imm = inst.imm,
        .rs1_val = source,
        .rs2_val = 0,
        .rs1_prev_clk = source_clock - 1,
        .rs2_prev_clk = 0,
        .rd_prev_val = if (inst.rd == 0)
            0
        else if (inst.rd == inst.rs1)
            source
        else
            0x55aa_1234,
        .rd_prev_clk = source_clock,
        .rd_val = if (inst.rd == 0) 0 else result,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x2004,
        .inst_word = 0,
    };
}

fn measureProductionDirect(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0x6a09_e667_f3bc_c909;
    for (0..iterations) |index| {
        var direct: Production.DirectConstraints = undefined;
        try Production.buildLtImmDirectInto(
            &rows[index & (rows.len - 1)],
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
        const row = try Legacy.Row.fromOracleColumns(
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
        try Production.buildLtImmLookupsInto(
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
