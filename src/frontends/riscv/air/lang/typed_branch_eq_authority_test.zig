const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/branch_eq_legacy_test_oracle.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_branch_eq_authority.zig");
const typed = @import("typed_branch_eq.zig");
const witness = @import("typed_branch_eq_witness.zig");

const Opcode = @import("../../isa/decode.zig").Opcode;
const Production = @import("../constraint_program.zig").Builder(QM31);

test "BRANCH_EQ fixed authority is exact pointer-free and source independent" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/control/branch_eq.air",
        .start = .{ .byte_offset = 271, .line = 13, .column = 5 },
        .end = .{ .byte_offset = 319, .line = 13, .column = 53 },
    } });
    defer relocated.deinit();

    const binding = try authority.Binding.canonical(&generated);
    const admitted = try authority.Authority.init(&generated, &binding);
    const relocated_binding = try authority.Binding.canonical(&relocated);
    const relocated_admitted = try authority.Authority.init(
        &relocated,
        &relocated_binding,
    );
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
    try std.testing.expectEqual(
        admitted.identityDigest(),
        relocated_admitted.identityDigest(),
    );
    try std.testing.expectEqualDeep(admitted, authority.Authority.pinned());
    try std.testing.expect(!containsPointer(authority.Binding));
    try std.testing.expect(!containsPointer(authority.Authority));

    generated.deinit();
    const retired = try admitted.retire(
        instruction(.BNE, 3, 4, -4),
        0x2000,
        0x1234,
        0x5678,
    );
    try std.testing.expect(retired.taken);
    try std.testing.expectEqual(@as(u32, 0x1ffc), retired.next_pc);
}

test "BRANCH_EQ authority rejects every binding surface" {
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
    malformed.opcode_ids[0] +%= 1;
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
    std.mem.swap(authority.DirectRecipe, &malformed.direct[6], &malformed.direct[7]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[0].arity = 4;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[3].domain = .range_check_8_8;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[5].role = .consume;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[8].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);
}

test "BRANCH_EQ authority rejects forged typed roots and control proof" {
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.model.roots[0] = malformed.model.roots[1];
        try std.testing.expectError(
            error.InvalidBranchEqDefinition,
            authority.Authority.init(&malformed, &binding),
        );
    }
    {
        var malformed = try typed.build(std.testing.allocator, .generated);
        defer malformed.deinit();
        const binding = try authority.Binding.canonical(&malformed);
        malformed.arena.range_refinements.items[1]
            .premise.program_control_target.offset = malformed.columns.rs1.addr;
        try std.testing.expectError(
            error.InvalidNodeShape,
            authority.Authority.init(&malformed, &binding),
        );
    }
}

test "BRANCH_EQ direct roots and ordered relations equal independent legacy polynomials" {
    const admitted = try authenticatedAuthority();
    var arena = symbolic.Arena.init(std.testing.allocator);
    defer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    var columns: [authority.MAIN_COLUMN_COUNT]symbolic.Scalar = undefined;
    for (&columns) |*column| column.* = arena.column("");
    const selector = arena.column("is_active");
    const Legacy = legacy.Semantics(symbolic.Scalar);
    const row = try Legacy.Row.fromMainColumns(&columns);
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

test "BRANCH_EQ authority owns decisions x0 aliases witness and AIR rows" {
    const admitted = try authenticatedAuthority();
    const values = [_]u32{
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1357_9bdf,
    };
    const aliases = [_]struct { rs1: u5, rs2: u5 }{
        .{ .rs1 = 0, .rs2 = 0 },
        .{ .rs1 = 0, .rs2 = 9 },
        .{ .rs1 = 7, .rs2 = 0 },
        .{ .rs1 = 7, .rs2 = 7 },
        .{ .rs1 = 7, .rs2 = 9 },
        .{ .rs1 = 31, .rs2 = 30 },
    };
    const immediates = [_]i32{ -4096, -4, 0, 4, 4092 };
    var clock: u32 = 100;
    for ([_]Opcode{ .BEQ, .BNE }) |opcode| for (values) |raw_lhs| {
        for (values) |raw_rhs| for (aliases) |registers| for (immediates) |immediate| {
            const lhs = if (registers.rs1 == 0) 0 else raw_lhs;
            const rhs = if (registers.rs2 == 0)
                0
            else if (registers.rs2 == registers.rs1)
                lhs
            else
                raw_rhs;
            const inst = instruction(opcode, registers.rs1, registers.rs2, immediate);
            const retirement = try admitted.retire(inst, 0x2000, lhs, rhs);
            const expected_taken = independentTaken(opcode, lhs, rhs);
            const expected_pc = if (expected_taken)
                0x2000 +% @as(u32, @bitCast(immediate))
            else
                0x2004;
            try std.testing.expectEqual(expected_taken, retirement.taken);
            try std.testing.expectEqual(lhs == rhs, retirement.equal);
            try std.testing.expectEqual(expected_pc, retirement.next_pc);
            try std.testing.expectEqual(expected_pc != 0x2004, retirement.branch_taken);

            const row = makeRow(inst, lhs, rhs, retirement, clock);
            var storage: [authority.MAIN_COLUMN_COUNT][1]M31 = undefined;
            var views: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
            var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
            for (&storage, &views) |*cell, *view| view.* = cell;
            admitted.writeActiveRow(&views, 0, row);
            for (storage, &scalars) |cell, *scalar|
                scalar.* = QM31.fromBase(cell[0]);
            const program = try admitted.buildProgram(QM31, &scalars, QM31.one());
            try std.testing.expect(program.direct_constraints.allZero());
            try std.testing.expectEqual(authority.LOOKUP_COUNT, program.lookup_entries.len);
            clock += 1;
        };
    };

    // An encoded halfword offset is legal when the branch falls through, but
    // a selected target must obey this frontend's four-byte PC alignment.
    const legal_fallthrough = try admitted.retire(
        instruction(.BEQ, 1, 2, 4094),
        0x2000,
        1,
        2,
    );
    try std.testing.expectEqual(@as(u32, 0x2004), legal_fallthrough.next_pc);
    try std.testing.expectError(
        error.InstructionAddressMisaligned,
        admitted.retire(instruction(.BEQ, 1, 2, 4094), 0x2000, 7, 7),
    );
    try std.testing.expectError(
        error.WrongBranchEqOpcode,
        admitted.retire(instruction(.BLT, 1, 2, 0), 0x2000, 7, 9),
    );
    try std.testing.expectError(
        error.InvalidImmediate,
        admitted.retire(instruction(.BEQ, 1, 2, 1), 0x2000, 7, 9),
    );
    try std.testing.expectError(
        error.InvalidImmediate,
        admitted.retire(instruction(.BEQ, 1, 2, -4098), 0x2000, 7, 9),
    );
    try std.testing.expectError(
        error.InvalidProgramCounter,
        admitted.retire(instruction(.BEQ, 1, 2, 0), authority.PC_BOUND, 7, 9),
    );
    try std.testing.expectError(
        error.InstructionAddressMisaligned,
        admitted.retire(instruction(.BEQ, 1, 2, 0), 2, 7, 9),
    );
    try std.testing.expectError(
        error.TargetOutOfRange,
        admitted.retire(
            instruction(.BEQ, 1, 2, 0),
            authority.PC_BOUND - 4,
            7,
            9,
        ),
    );
}

test "BRANCH_EQ authority rejects malformed rows without a partial write" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const inst = instruction(.BNE, 3, 4, -4);
    const retirement = try admitted.retire(inst, 0x2000, 7, 9);
    const honest = makeRow(inst, 7, 9, retirement, 11);

    var forged = honest;
    forged.next_pc +%= 4;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.branch_taken = !forged.branch_taken;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.rs2_val = forged.rs1_val;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.rs1_prev_clk = (forged.clk - 1) * 4 + 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.mem_addr = 4;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
}

test "BRANCH_EQ authority construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "BRANCH_EQ production direct and lookup evaluators retain legacy throughput" {
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
        "\n  BRANCH_EQ production authority: direct={d} ns legacy={d} ns " ++
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
    const e = entry.Builder(S);
    const requests = legacy.Semantics(S).lookups(row);
    var result = e.List{};
    e.program(&result, requests.program.numerator, requests.program.tuple);
    e.accessAt(&result, requests.rs1, 1);
    e.accessAt(&result, requests.rs2, 2);
    e.stateRequests(&result, requests.state);
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
        try std.testing.expectEqual(want.numerator.id, got.numerator.id);
        for (want.values[0..want.arity], got.values[0..got.arity]) |
            want_value,
            got_value,
        | try std.testing.expectEqual(want_value.id, got_value.id);
    }
}

fn instruction(opcode: Opcode, rs1: u5, rs2: u5, immediate: i32) authority.DecodedInst {
    return .{ .opcode = opcode, .rd = 0, .rs1 = rs1, .rs2 = rs2, .imm = immediate };
}

fn independentTaken(opcode: Opcode, lhs: u32, rhs: u32) bool {
    return switch (opcode) {
        .BEQ => lhs == rhs,
        .BNE => lhs != rhs,
        else => unreachable,
    };
}

fn makeRow(
    inst: authority.DecodedInst,
    lhs: u32,
    rhs: u32,
    retirement: authority.Retirement,
    clock: u32,
) authority.TraceRow {
    const source_1_clock = (clock - 1) * 4 + 1;
    return .{
        .clk = clock,
        .pc = 0x2000,
        .opcode = inst.opcode,
        .rd = inst.rd,
        .rs1 = inst.rs1,
        .rs2 = inst.rs2,
        .imm = inst.imm,
        .rs1_val = lhs,
        .rs2_val = rhs,
        .rs1_prev_clk = source_1_clock - 1,
        .rs2_prev_clk = if (inst.rs2 == inst.rs1)
            source_1_clock
        else
            source_1_clock,
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

fn measureProductionDirect(
    rows: []const [authority.MAIN_COLUMN_COUNT]QM31,
    active: QM31,
    iterations: usize,
) !u64 {
    var timer = try std.time.Timer.start();
    var checksum: u64 = 0x6a09_e667_f3bc_c909;
    for (0..iterations) |index| {
        var direct: Production.DirectConstraints = undefined;
        try Production.buildBranchEqDirectInto(
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
        const row = try Legacy.Row.fromMainColumns(&rows[index & (rows.len - 1)]);
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
        try Production.buildBranchEqLookupsInto(
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
