const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/shifts_imm_legacy_test_oracle.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_shifts_imm_authority.zig");
const support = @import("typed_shifts_imm_witness_test_support.zig");
const typed = @import("typed_shifts_imm.zig");
const witness = @import("typed_shifts_imm_witness.zig");

const Opcode = @import("../../isa/decode.zig").Opcode;
const operations = [_]Opcode{ .SLLI, .SRLI, .SRAI };

test "SHIFTS_IMM fixed authority is pinned pointer-free and source independent" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/shift/shifts_imm.air",
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
    try std.testing.expectEqual(@as(usize, 51), authority.MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 67), authority.DIRECT_CONSTRAINT_COUNT);
    try std.testing.expectEqual(@as(usize, 16), authority.LOOKUP_COUNT);
    try std.testing.expectEqual(@as(usize, 2), authority.LOOKUP_BATCH_SIZE);
    try std.testing.expectEqual(@as(usize, 248), @sizeOf(authority.Binding));
    try std.testing.expectEqual(@as(usize, 280), @sizeOf(authority.Authority));

    generated.deinit();
    const retired = try admitted.retire(instruction(.SRAI, 4, 3, 31), 0x8000_0000);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), retired.visible_value);
}

test "SHIFTS_IMM authority rejects every authenticated binding surface" {
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
    malformed.opcode_ids[2] +%= 1;
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
    std.mem.swap(authority.DirectRecipe, &malformed.direct[36], &malformed.direct[37]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[6].domain = .range_check_20;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[2].role = .consume;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[12].access_ordinal = 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);
}

test "SHIFTS_IMM authority rejects forged typed roots and range evidence" {
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.constraint_roots[22] = malformed.constraint_roots[23];
        try std.testing.expectError(
            error.InvalidShiftsImmDefinition,
            authority.Authority.init(&malformed, &binding),
        );
    }
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.arena.range_refinements.items[0].source = malformed.columns.pc;
        try std.testing.expectError(
            error.InvalidNodeShape,
            authority.Authority.init(&malformed, &binding),
        );
    }
}

test "SHIFTS_IMM roots placement and ordered lookups exactly equal legacy symbols" {
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

test "SHIFTS_IMM authority owns all amounts directions extrema x0 aliases witness and AIR" {
    const admitted = try authenticatedAuthority();
    const values = [_]u32{
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x0102_0304,
    };
    const row_count = operations.len * 32 * values.len;
    var rows: [row_count]authority.TraceRow = undefined;
    var count: usize = 0;
    for (operations) |opcode| for (0..32) |amount_raw| for (values) |value| {
        const amount: u5 = @intCast(amount_raw);
        const rd: u5 = if (count % 19 == 0)
            0
        else
            @intCast(1 + count % 31);
        const rs1: u5 = if (count % 7 == 0)
            rd
        else
            @intCast(1 + (count * 11) % 31);
        const inst = instruction(opcode, rd, rs1, amount);
        const source = if (rs1 == 0) 0 else value;
        const retirement = try admitted.retire(inst, source);
        try std.testing.expectEqual(
            support.result(opcode, source, amount),
            retirement.attempted_value,
        );
        try std.testing.expectEqual(
            if (rd == 0) @as(u32, 0) else retirement.attempted_value,
            retirement.visible_value,
        );
        rows[count] = support.makeRow(
            opcode,
            rd,
            rs1,
            value,
            amount,
            @intCast(count + 100),
            @intCast(0x4000 + count * 4),
            @truncate(0x1122_3344 +% count),
            @intCast(count % 32),
            @intCast((count + 1) % 32),
        );
        count += 1;
    };
    try std.testing.expectEqual(row_count, count);

    var columns = try support.OwnedColumns.init(
        std.testing.allocator,
        1024,
        M31.zero(),
    );
    defer columns.deinit();
    try admitted.generateMainInto(&columns.views, &rows, 10);
    try support.expectLegacyColumns(&rows, 10, &columns.views);
    for (rows, 0..) |_, row_index| {
        var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&scalars, columns.views) |*scalar, column|
            scalar.* = QM31.fromBase(column[row_index]);
        const program = try admitted.buildProgram(QM31, &scalars, QM31.one());
        try std.testing.expect(program.direct_constraints.allZero());
        try std.testing.expectEqual(authority.LOOKUP_COUNT, program.lookup_entries.len);
    }

    try std.testing.expectError(
        error.WrongShiftsImmOpcode,
        admitted.retire(instruction(.ADDI, 1, 2, 0), 7),
    );
    try std.testing.expectError(
        error.InvalidShiftAmount,
        admitted.retire(.{ .opcode = .SLLI, .rd = 1, .rs1 = 2, .rs2 = 0, .imm = 32 }, 7),
    );
}

test "SHIFTS_IMM authority rejects malformed rows before any write" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = support.makeRow(.SRAI, 3, 2, 0x8000_1234, 7, 2, 0x1000, 9, 0, 1);

    inline for (.{
        "opcode",
        "amount",
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
        if (std.mem.eql(u8, mutation, "amount")) forged.imm = 32;
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

test "SHIFTS_IMM authority construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "SHIFTS_IMM fixed direct and lookup evaluators preserve legacy throughput" {
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
    _ = try measureFixedDirect(&admitted, rows, active, 1 << 9);
    _ = try measureLegacyDirect(rows, active, 1 << 9);
    _ = try measureFixedLookups(&admitted, rows, 1 << 9);
    _ = try measureLegacyLookups(rows, 1 << 9);
    const samples = 13;
    const iterations = 1 << 14;
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
        "\n  SHIFTS_IMM fixed authority: direct={d} ns legacy={d} ns " ++
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
    const active = row.semantic.active();
    const accesses = module.accessLookups(row);
    const carries = module.carryRangePairs(row.semantic);
    const results = module.rdRangePairs(row.semantic);
    var list = e.List{};
    e.program(&list, active.neg(), module.programLookup(row));
    e.stateChain(&list, module.stateLookup(row), active);
    e.accessChainAt(&list, accesses.rs1, active, 1);
    for (carries) |pair| e.range88(&list, active.neg(), pair);
    for (results) |pair| e.range88(&list, active.neg(), pair);
    e.accessChainAt(&list, accesses.rd, active, 2);
    e.rangeM31(
        &list,
        row.semantic.is_sra.neg(),
        module.signRangeLookup(row.semantic),
    );
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
    amount: u5,
) authority.DecodedInst {
    return .{
        .opcode = opcode,
        .rd = rd,
        .rs1 = rs1,
        .rs2 = amount,
        .imm = amount,
    };
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
