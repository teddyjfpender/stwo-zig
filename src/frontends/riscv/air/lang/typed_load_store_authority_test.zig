const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../lookups/entry.zig");
const legacy = @import("../semantics/load_store_legacy_test_oracle.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_load_store_authority.zig");
const decode = @import("../../runner/decode.zig");
const typed = @import("typed_load_store.zig");
const witness = @import("typed_load_store_witness.zig");

test "LOAD_STORE fixed authority binding is source independent pointer-free and pinned" {
    var generated = try typed.build(std.testing.allocator, .generated);
    defer generated.deinit();
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/memory/load_store.air",
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
    try std.testing.expectEqual(@as(usize, 48), authority.MAIN_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 63), authority.DIRECT_CONSTRAINT_COUNT);
    try std.testing.expectEqual(@as(usize, 16), authority.LOOKUP_COUNT);
    try std.testing.expectEqual(@as(usize, 2), authority.LOOKUP_BATCH_SIZE);
    try std.testing.expect(!containsPointer(authority.Binding));
    try std.testing.expect(!containsPointer(authority.Authority));
}

test "LOAD_STORE authority rejects semantic witness direct and relation mutations" {
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
    malformed.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.witness_binding_digest[31] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.opcode_ids[7] +%= 1;
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
    malformed.lookups[7].domain = .range_check_20;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[13].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);
}

test "LOAD_STORE authority direct roots and ordered relations equal legacy polynomials" {
    const admitted = try authenticatedAuthority();
    var prng = std.Random.DefaultPrng.init(0x4c4f_4144_5354_4f52);
    const random = prng.random();
    const Legacy = legacy.Semantics(QM31);

    for (0..128) |_| {
        var columns: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
        for (&columns) |*column| column.* = randomSecure(random);
        const selector = randomSecure(random);
        const row = try Legacy.Row.fromOracleColumns(&columns);
        const expected_direct = Legacy.evaluate(row);
        const expected_placement = Legacy.placementConstraint(row, selector);
        const expected_lookups = legacyLookups(QM31, row);
        const actual = try admitted.buildProgram(QM31, &columns, selector);

        for (expected_direct.values, actual.direct_constraints.values[0..62]) |
            expected,
            got,
        | try std.testing.expect(expected.eql(got));
        try std.testing.expect(
            expected_placement.eql(actual.direct_constraints.values[62]),
        );
        try expectLookupListsEqual(QM31, expected_lookups, actual.lookup_entries);
    }
}

test "LOAD_STORE authority direct and lookup programs are symbolically identical" {
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
    for (direct.values, actual.direct_constraints.values[0..62]) |want, got|
        try std.testing.expectEqual(want.id, got.id);
    try std.testing.expectEqual(
        placement.id,
        actual.direct_constraints.values[62].id,
    );
    try expectLookupListsEqual(symbolic.Scalar, lookups, actual.lookup_entries);
}

test "LOAD_STORE authority owns alignment sign extension partial writes x0 witness and AIR" {
    const admitted = try authenticatedAuthority();
    const cases = [_]struct {
        opcode: decode.Opcode,
        rd: u5,
        rs1: u5,
        rs2: u5,
        base: u32,
        source: u32,
        previous_word: u32,
        imm: i32,
    }{
        .{ .opcode = .LB, .rd = 1, .rs1 = 2, .rs2 = 0, .base = 0x2000, .source = 0, .previous_word = 0x1122_8033, .imm = 1 },
        .{ .opcode = .LH, .rd = 3, .rs1 = 3, .rs2 = 0, .base = 0x2000, .source = 0, .previous_word = 0x8001_1234, .imm = 2 },
        .{ .opcode = .LBU, .rd = 0, .rs1 = 4, .rs2 = 0, .base = 0x2100, .source = 0, .previous_word = 0xfe12_3456, .imm = 3 },
        .{ .opcode = .LHU, .rd = 5, .rs1 = 6, .rs2 = 0, .base = 0x2200, .source = 0, .previous_word = 0xfedc_5678, .imm = 2 },
        .{ .opcode = .LW, .rd = 7, .rs1 = 8, .rs2 = 0, .base = 0x2304, .source = 0, .previous_word = 0xdead_beef, .imm = -4 },
        .{ .opcode = .SB, .rd = 0, .rs1 = 9, .rs2 = 10, .base = 0x2400, .source = 0xa1b2_c3d4, .previous_word = 0x1122_3344, .imm = 2 },
        .{ .opcode = .SH, .rd = 0, .rs1 = 11, .rs2 = 11, .base = 0x2500, .source = 0x2500, .previous_word = 0x5566_7788, .imm = 2 },
        .{ .opcode = .SW, .rd = 0, .rs1 = 12, .rs2 = 13, .base = 0x2604, .source = 0xcafe_babe, .previous_word = 0x0102_0304, .imm = -4 },
    };

    var rows: [cases.len]authority.TraceRow = undefined;
    for (&rows, cases, 0..) |*row, case, index| {
        row.* = try makeRow(
            case.opcode,
            case.rd,
            case.rs1,
            case.rs2,
            case.base,
            case.source,
            case.previous_word,
            case.imm,
            @intCast(index + 2),
            @intCast(0x1000 + index * 4),
        );
        const retired = try admitted.retire(
            .{
                .opcode = case.opcode,
                .rd = case.rd,
                .rs1 = case.rs1,
                .rs2 = case.rs2,
                .imm = case.imm,
            },
            row.rs1_val,
            row.rs2_val,
            row.mem_prev_word,
        );
        try std.testing.expectEqual(row.mem_addr, retired.address);
        try std.testing.expectEqual(row.mem_next_word, retired.memory_next_word);
        try std.testing.expectEqual(row.is_load, retired.is_load);
        if (row.is_load) try std.testing.expectEqual(row.rd_val, retired.register_value);
    }

    var storage: [authority.MAIN_COLUMN_COUNT][8]M31 = undefined;
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
        error.MisalignedMemoryAccess,
        admitted.retire(.{ .opcode = .LW, .rd = 1, .rs1 = 2, .rs2 = 0, .imm = 2 }, 0x2000, 0, 0),
    );
    try std.testing.expectError(
        error.AddressOutOfRange,
        admitted.retire(.{ .opcode = .LW, .rd = 1, .rs1 = 2, .rs2 = 0, .imm = 8 }, 0x7fff_fffc, 0, 0),
    );
    try std.testing.expectError(
        error.WrongLoadStoreOpcode,
        admitted.retire(.{ .opcode = .ADD, .rd = 1, .rs1 = 2, .rs2 = 3, .imm = 0 }, 0, 0, 0),
    );
}

test "LOAD_STORE authority exhausts byte and halfword values offsets and preservation masks" {
    const base: u32 = 0x20_000;
    const original: u32 = 0xa17c_3e95;
    for (0..4) |offset| {
        const amount: u5 = @intCast(offset * 8);
        for (0..256) |raw| {
            const byte: u8 = @intCast(raw);
            const word = (original & ~(@as(u32, 0xff) << amount)) |
                (@as(u32, byte) << amount);
            const signed = try authority.canonicalRetirement(
                .{ .opcode = .LB, .rd = 1, .rs1 = 2, .rs2 = 0, .imm = @intCast(offset) },
                base,
                0,
                word,
            );
            const unsigned = try authority.canonicalRetirement(
                .{ .opcode = .LBU, .rd = 1, .rs1 = 2, .rs2 = 0, .imm = @intCast(offset) },
                base,
                0,
                word,
            );
            const expected_signed: u32 = @bitCast(
                @as(i32, @as(i8, @bitCast(byte))),
            );
            try std.testing.expectEqual(expected_signed, signed.register_value);
            try std.testing.expectEqual(@as(u32, byte), unsigned.register_value);
            try std.testing.expectEqual(word, signed.memory_next_word);
            try std.testing.expectEqual(word, unsigned.memory_next_word);

            for (0..256) |source_raw| {
                const source: u8 = @intCast(source_raw);
                const stored = try authority.canonicalRetirement(
                    .{ .opcode = .SB, .rd = 0, .rs1 = 2, .rs2 = 3, .imm = @intCast(offset) },
                    base,
                    source,
                    word,
                );
                const expected = (word & ~(@as(u32, 0xff) << amount)) |
                    (@as(u32, source) << amount);
                try std.testing.expectEqual(expected, stored.memory_next_word);
            }
        }
    }

    for ([_]u32{ 0, 2 }) |offset| {
        const amount: u5 = @intCast(offset * 8);
        for (0..65_536) |raw| {
            const half: u16 = @intCast(raw);
            const word = (original & ~(@as(u32, 0xffff) << amount)) |
                (@as(u32, half) << amount);
            const signed = try authority.canonicalRetirement(
                .{ .opcode = .LH, .rd = 1, .rs1 = 2, .rs2 = 0, .imm = @intCast(offset) },
                base,
                0,
                word,
            );
            const unsigned = try authority.canonicalRetirement(
                .{ .opcode = .LHU, .rd = 1, .rs1 = 2, .rs2 = 0, .imm = @intCast(offset) },
                base,
                0,
                word,
            );
            const stored = try authority.canonicalRetirement(
                .{ .opcode = .SH, .rd = 0, .rs1 = 2, .rs2 = 3, .imm = @intCast(offset) },
                base,
                half,
                original,
            );
            const expected_signed: u32 = @bitCast(
                @as(i32, @as(i16, @bitCast(half))),
            );
            const expected_store = (original &
                ~(@as(u32, 0xffff) << amount)) |
                (@as(u32, half) << amount);
            try std.testing.expectEqual(expected_signed, signed.register_value);
            try std.testing.expectEqual(@as(u32, half), unsigned.register_value);
            try std.testing.expectEqual(expected_store, stored.memory_next_word);
        }
    }
}

test "LOAD_STORE authority rejects forged rows atomically and releases allocation failures" {
    const admitted = try authenticatedAuthority();
    const sentinel = M31.fromCanonical(0x1ace);
    var storage: [authority.MAIN_COLUMN_COUNT][4]M31 =
        .{.{sentinel} ** 4} ** authority.MAIN_COLUMN_COUNT;
    var columns: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*owned, *view| view.* = owned;
    const honest = try makeRow(.LH, 3, 1, 0, 0x2000, 0, 0x8001_1234, 2, 2, 0x1000);

    var forged = honest;
    forged.rd_val ^= 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.mem_val ^= 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.mem_next_word ^= 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.mem_addr +%= 2;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.mem_prev_clk = 8;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.next_pc +%= 4;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.inst_word ^= 1 << 20;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.rs2 +%= 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest;
    forged.rs2_val = 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);

    const honest_store = try makeRow(
        .SB,
        0,
        1,
        2,
        0x2000,
        0xaabb_ccdd,
        0x1122_3344,
        1,
        2,
        0x1000,
    );
    forged = honest_store;
    forged.rd +%= 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest_store;
    forged.rd_prev_val = 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);
    forged = honest_store;
    forged.rd_val = 1;
    try expectInvalidRowAtomic(&admitted, &columns, &storage, forged, sentinel);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "LOAD_STORE fixed direct and lookup evaluators strictly preserve legacy throughput" {
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
    const iterations = 1 << 16;
    var fixed_direct: [samples]u64 = undefined;
    var old_direct: [samples]u64 = undefined;
    var fixed_lookups: [samples]u64 = undefined;
    var old_lookups: [samples]u64 = undefined;
    for (0..samples) |sample| if ((sample & 1) == 0) {
        fixed_direct[sample] = try measureFixedDirect(&admitted, rows, active, iterations);
        old_direct[sample] = try measureLegacyDirect(rows, active, iterations);
        fixed_lookups[sample] = try measureFixedLookups(&admitted, rows, iterations);
        old_lookups[sample] = try measureLegacyLookups(rows, iterations);
    } else {
        old_lookups[sample] = try measureLegacyLookups(rows, iterations);
        fixed_lookups[sample] = try measureFixedLookups(&admitted, rows, iterations);
        old_direct[sample] = try measureLegacyDirect(rows, active, iterations);
        fixed_direct[sample] = try measureFixedDirect(&admitted, rows, active, iterations);
    };
    const fixed_direct_median = median(&fixed_direct);
    const old_direct_median = median(&old_direct);
    const fixed_lookup_median = median(&fixed_lookups);
    const old_lookup_median = median(&old_lookups);
    std.debug.print(
        "\n  LOAD_STORE direct={d} ns legacy={d} ns speed={d:.4}x" ++
            " lookups={d} ns legacy={d} ns speed={d:.4}x\n",
        .{
            fixed_direct_median,
            old_direct_median,
            @as(f64, @floatFromInt(old_direct_median)) /
                @as(f64, @floatFromInt(fixed_direct_median)),
            fixed_lookup_median,
            old_lookup_median,
            @as(f64, @floatFromInt(old_lookup_median)) /
                @as(f64, @floatFromInt(fixed_lookup_median)),
        },
    );
    try std.testing.expect(
        @as(u128, fixed_direct_median) * 97 <=
            @as(u128, old_direct_median) * 100,
    );
    try std.testing.expect(
        @as(u128, fixed_lookup_median) * 97 <=
            @as(u128, old_lookup_median) * 100,
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

fn makeRow(
    opcode: decode.Opcode,
    rd: u5,
    rs1: u5,
    rs2: u5,
    raw_base: u32,
    raw_source: u32,
    previous_word: u32,
    imm: i32,
    clock: u32,
    pc: u32,
) !authority.TraceRow {
    const is_load = authority.isLoadOpcode(opcode);
    const inst_word = if (is_load)
        encodeLoad(opcode, rd, rs1, imm)
    else
        encodeStore(opcode, rs1, rs2, imm);
    const instruction = try authority.DecodedInst.decode(inst_word);
    const base = if (instruction.rs1 == 0) 0 else raw_base;
    const source = if (is_load)
        0
    else if (instruction.rs2 == 0)
        0
    else if (instruction.rs2 == instruction.rs1)
        base
    else
        raw_source;
    const retirement = try authority.canonicalRetirement(
        instruction,
        base,
        source,
        previous_word,
    );
    const first = (clock - 1) * 4 + 1;
    const raw_memory = rawLoadValue(opcode, previous_word, retirement.address);
    const previous_rd = if (!is_load or instruction.rd == 0)
        0
    else if (instruction.rd == instruction.rs1)
        base
    else
        0x5566_7788;
    return .{
        .clk = clock,
        .pc = pc,
        .opcode = opcode,
        .rd = instruction.rd,
        .rs1 = instruction.rs1,
        .rs2 = instruction.rs2,
        .imm = imm,
        .rs1_val = base,
        .rs2_val = source,
        .rs1_prev_clk = 0,
        .rs2_prev_clk = if (!is_load and rs2 == rs1) first else 0,
        .rd_prev_val = previous_rd,
        .rd_prev_clk = if (is_load and rd == rs1) first else 0,
        .rd_val = if (is_load) retirement.register_value else previous_rd,
        .mem_addr = retirement.address,
        .mem_val = if (is_load) raw_memory else source,
        .mem_prev_word = previous_word,
        .mem_next_word = retirement.memory_next_word,
        .mem_prev_clk = 0,
        .is_load = is_load,
        .is_store = !is_load,
        .branch_taken = false,
        .next_pc = pc +% 4,
        .inst_word = inst_word,
    };
}

fn encodeLoad(opcode: decode.Opcode, rd: u5, rs1: u5, immediate: i32) u32 {
    const funct3: u32 = switch (opcode) {
        .LB => 0,
        .LH => 1,
        .LW => 2,
        .LBU => 4,
        .LHU => 5,
        else => unreachable,
    };
    const immediate_12 = @as(u32, @bitCast(immediate)) & 0xfff;
    return (immediate_12 << 20) | (@as(u32, rs1) << 15) |
        (funct3 << 12) | (@as(u32, rd) << 7) | 0x03;
}

fn encodeStore(opcode: decode.Opcode, rs1: u5, rs2: u5, immediate: i32) u32 {
    const funct3: u32 = switch (opcode) {
        .SB => 0,
        .SH => 1,
        .SW => 2,
        else => unreachable,
    };
    const immediate_12 = @as(u32, @bitCast(immediate)) & 0xfff;
    return ((immediate_12 & 0xfe0) << 20) | (@as(u32, rs2) << 20) |
        (@as(u32, rs1) << 15) | (funct3 << 12) |
        ((immediate_12 & 0x1f) << 7) | 0x23;
}

fn rawLoadValue(opcode: decode.Opcode, word: u32, address: u32) u32 {
    const amount: u5 = @intCast((address & 3) * 8);
    return switch (opcode) {
        .LB, .LBU => @as(u8, @truncate(word >> amount)),
        .LH, .LHU => @as(u16, @truncate(word >> amount)),
        .LW => word,
        else => 0,
    };
}

fn legacyLookups(
    comptime S: type,
    row: legacy.Semantics(S).Row,
) entry.Builder(S).List {
    const module = legacy.Semantics(S);
    const e = entry.Builder(S);
    const active = row.active();
    const accesses = module.accessLookups(row);
    const signs = module.signRangeLookups(row);
    var list = e.List{};
    e.program(&list, active.neg(), module.programLookup(row));
    e.stateChain(&list, module.stateLookup(row), active);
    e.accessChainAt(&list, accesses.rs1, active, 1);
    e.range20(&list, active.neg(), module.alignedAddressRangeLookup(row));
    e.rangeM31(&list, active.neg(), module.baseAddressM31Lookup(row));
    e.accessChainAt(&list, accesses.src, active, 2);
    e.accessChainAt(&list, accesses.dst, active, 3);
    e.rangeM31(&list, row.is_lb.neg(), signs[0]);
    e.rangeM31(&list, row.is_lh.neg(), signs[1]);
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

fn randomSecure(random: std.Random) QM31 {
    return QM31.fromM31(
        M31.fromU64(random.int(u32)),
        M31.fromU64(random.int(u32)),
        M31.fromU64(random.int(u32)),
        M31.fromU64(random.int(u32)),
    );
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
        var result: entry.Builder(QM31).List = undefined;
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

fn absorbLookups(
    checksum: *u64,
    result: *const entry.Builder(QM31).List,
) void {
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
