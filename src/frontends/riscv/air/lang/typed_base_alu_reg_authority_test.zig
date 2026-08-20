const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const lookup_entry = @import("../lookups/entry.zig");
const semantic_common = @import("../semantics/common.zig");
const legacy = @import("../semantics/base_alu_reg.zig");
const symbolic = @import("../extract/symbolic.zig");
const authority = @import("typed_base_alu_reg_authority.zig");
const typed = @import("typed_base_alu_reg.zig");
const witness = @import("typed_base_alu_reg_witness.zig");

const Opcode = @import("../../isa/decode.zig").Opcode;
const operations = [_]Opcode{ .ADD, .SUB, .XOR, .OR, .AND };

test "E-020 BASE_ALU_REG authority binding is exact pointer-free and source independent" {
    var generated = try typed.build(std.testing.allocator, .generated);
    var relocated = try typed.build(std.testing.allocator, .{ .file = .{
        .path = "relocated/base_alu_reg.air",
        .start = .{ .byte_offset = 100, .line = 9, .column = 2 },
        .end = .{ .byte_offset = 123, .line = 9, .column = 25 },
    } });
    defer relocated.deinit();
    const binding = try authority.Binding.canonical(&generated);
    const actual = try authority.Authority.init(&generated, &binding);
    const relocated_binding = try authority.Binding.canonical(&relocated);
    const relocated_authority = try authority.Authority.init(
        &relocated,
        &relocated_binding,
    );
    try std.testing.expectEqual(typed.SEMANTIC_DIGEST, binding.semantic_digest);
    try std.testing.expectEqual(
        witness.WITNESS_BINDING_DIGEST,
        binding.witness_binding_digest,
    );
    try std.testing.expectEqual(
        authority.AUTHORITY_BINDING_DIGEST,
        binding.identityDigest(),
    );
    try std.testing.expectEqualDeep(binding, relocated_binding);
    try std.testing.expectEqual(
        actual.identityDigest(),
        relocated_authority.identityDigest(),
    );
    try std.testing.expectEqualDeep(actual, authority.Authority.pinned());

    generated.deinit();
    const retired = try actual.retire(instruction(.SUB, 31, 7, 9), 0, 1);
    try std.testing.expectEqual(@as(u32, 0xffff_ffff), retired.visible_value);
}

test "E-020 BASE_ALU_REG authority rejects every binding surface" {
    var definition = try typed.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const canonical = try authority.Binding.canonical(&definition);
    var malformed = canonical;
    malformed.semantic_digest[0] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.witness_binding_digest[31] ^= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.opcode_ids[2] +%= 1;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    std.mem.swap(authority.DirectRecipe, &malformed.direct[6], &malformed.direct[7]);
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[9].domain = .range_check_8_8;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookups[15].access_ordinal = 2;
    try expectInvalidBinding(&definition, malformed);
    malformed = canonical;
    malformed.lookup_batch_size = 1;
    try expectInvalidBinding(&definition, malformed);
}

test "E-020 BASE_ALU_REG direct roots and ordered relations equal independent legacy polynomials" {
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
    for (direct.values, actual.direct_constraints.values[0..direct.values.len]) |want, got|
        try std.testing.expectEqual(want.id, got.id);
    try std.testing.expectEqual(
        placement.id,
        actual.direct_constraints.values[direct.values.len].id,
    );
    try expectLookupListsEqual(symbolic.Scalar, lookups, actual.lookup_entries);
}

test "E-020 BASE_ALU_REG one authority owns every result x0 witness and AIR row" {
    const admitted = try authenticatedAuthority();
    const values = [_]u32{
        0,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_ffff,
        0x1357_9bdf,
    };
    const Alias = struct { rd: u5, rs1: u5, rs2: u5 };
    const aliases = [_]Alias{
        .{ .rd = 0, .rs1 = 0, .rs2 = 0 },
        .{ .rd = 7, .rs1 = 7, .rs2 = 7 },
        .{ .rd = 7, .rs1 = 7, .rs2 = 9 },
        .{ .rd = 9, .rs1 = 7, .rs2 = 9 },
        .{ .rd = 31, .rs1 = 7, .rs2 = 7 },
        .{ .rd = 31, .rs1 = 7, .rs2 = 9 },
    };
    var clock: u32 = 100;
    for (operations) |opcode| for (values) |lhs| for (values) |rhs| {
        for (aliases) |registers| {
            const source_1 = if (registers.rs1 == 0) 0 else lhs;
            const source_2 = if (registers.rs2 == 0)
                0
            else if (registers.rs2 == registers.rs1)
                source_1
            else
                rhs;
            const inst = instruction(
                opcode,
                registers.rd,
                registers.rs1,
                registers.rs2,
            );
            const retirement = try admitted.retire(inst, source_1, source_2);
            const expected = independentResult(opcode, source_1, source_2);
            try std.testing.expectEqual(expected, retirement.attempted_value);
            try std.testing.expectEqual(
                if (registers.rd == 0) 0 else expected,
                retirement.visible_value,
            );

            const row = makeRow(inst, source_1, source_2, retirement.visible_value, clock);
            var storage: [authority.MAIN_COLUMN_COUNT][1]M31 = undefined;
            var views: [authority.MAIN_COLUMN_COUNT][]M31 = undefined;
            var scalars: [authority.MAIN_COLUMN_COUNT]QM31 = undefined;
            for (&storage, &views) |*cell, *view| view.* = cell;
            admitted.writeActiveRow(&views, 0, row);
            for (storage, &scalars) |cell, *scalar| scalar.* = QM31.fromBase(cell[0]);
            const program = try admitted.buildProgram(QM31, &scalars, QM31.one());
            try std.testing.expect(program.direct_constraints.allZero());
            try std.testing.expectEqual(authority.LOOKUP_COUNT, program.lookup_entries.len);
            clock += 1;
        }
    };
    try std.testing.expectError(
        error.WrongBaseAluRegOpcode,
        admitted.retire(instruction(.ADDI, 1, 2, 3), 7, 9),
    );
    var invalid = instruction(.ADD, 1, 2, 3);
    invalid.imm = 1;
    try std.testing.expectError(error.InvalidImmediate, admitted.retire(invalid, 7, 9));
}

test "E-020 BASE_ALU_REG fixed direct evaluator retains at least 0.97x legacy throughput" {
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
    // Fault in code/data pages before paired measurement and use enough work
    // per sample to keep timer quantization and scheduler jitter immaterial.
    _ = try measureFixed(&admitted, rows, active, 1 << 11);
    _ = try measureLegacy(rows, active, 1 << 11);
    const samples = 15;
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
        "\n  E-020 BASE_ALU_REG fixed direct={d} ns legacy={d} ns speed={d:.4}x\n",
        .{ fixed_median, old_median, @as(f64, @floatFromInt(old_median)) /
            @as(f64, @floatFromInt(fixed_median)) },
    );
    try std.testing.expect(@as(u128, fixed_median) * 97 <=
        @as(u128, old_median) * 100);
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

fn legacyLookups(
    comptime S: type,
    row: legacy.Semantics(S).Row,
) lookup_entry.Builder(S).List {
    const module = legacy.Semantics(S);
    const e = lookup_entry.Builder(S);
    const active = row.active();
    const accesses = module.accessLookups(row);
    var list = e.List{};
    e.program(&list, active.neg(), module.programLookup(row));
    e.stateChain(&list, semantic_common.Ops(S).registersStateChain(row.pc, row.clk), active);
    e.accessChainAt(&list, accesses.rs1, active, 1);
    e.accessChainAt(&list, accesses.rs2, active, 2);
    const bitwise_active = module.bitwiseLookupEnabler(row);
    for (module.bitwiseLookups(row)) |tuple| e.bitwise(&list, bitwise_active.neg(), tuple);
    e.range88(&list, active.neg(), .{ row.result[0], row.result[1] });
    e.range88(&list, active.neg(), .{ row.result[2], row.result[3] });
    e.accessChainAt(&list, accesses.rd, active, 3);
    return list;
}

fn expectLookupListsEqual(
    comptime S: type,
    expected: lookup_entry.Builder(S).List,
    actual: lookup_entry.Builder(S).List,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    try std.testing.expectEqual(expected.batch_size, actual.batch_size);
    for (expected.entries[0..expected.len], actual.entries[0..actual.len]) |want, got| {
        try std.testing.expectEqual(want.domain, got.domain);
        try std.testing.expectEqual(want.role, got.role);
        try std.testing.expectEqual(want.arity, got.arity);
        try std.testing.expectEqual(want.access_ordinal, got.access_ordinal);
        try std.testing.expectEqual(want.numerator.id, got.numerator.id);
        for (want.values[0..want.arity], got.values[0..got.arity]) |want_value, got_value|
            try std.testing.expectEqual(want_value.id, got_value.id);
    }
}

fn instruction(opcode: Opcode, rd: u5, rs1: u5, rs2: u5) authority.DecodedInst {
    return .{ .opcode = opcode, .rd = rd, .rs1 = rs1, .rs2 = rs2, .imm = 0 };
}

fn independentResult(opcode: Opcode, lhs: u32, rhs: u32) u32 {
    return switch (opcode) {
        .ADD => lhs +% rhs,
        .SUB => lhs -% rhs,
        .XOR => lhs ^ rhs,
        .OR => lhs | rhs,
        .AND => lhs & rhs,
        else => unreachable,
    };
}

fn makeRow(
    inst: authority.DecodedInst,
    source_1: u32,
    source_2: u32,
    result: u32,
    clock: u32,
) authority.TraceRow {
    const source_1_clock = (clock - 1) * 4 + 1;
    const source_2_clock = source_1_clock + 1;
    const destination_clock = source_2_clock + 1;
    const rd_previous = if (inst.rd == 0)
        0
    else if (inst.rd == inst.rs2)
        source_2
    else if (inst.rd == inst.rs1)
        source_1
    else
        0x55aa_1234;
    const rd_previous_clock = if (inst.rd == inst.rs2)
        source_2_clock
    else if (inst.rd == inst.rs1)
        source_1_clock
    else
        destination_clock - 1;
    return .{
        .clk = clock,
        .pc = 0x1000 +% (clock - 1) *% 4,
        .opcode = inst.opcode,
        .rd = inst.rd,
        .rs1 = inst.rs1,
        .rs2 = inst.rs2,
        .imm = 0,
        .rs1_val = source_1,
        .rs2_val = source_2,
        .rs1_prev_clk = source_1_clock - 1,
        .rs2_prev_clk = if (inst.rs2 == inst.rs1)
            source_1_clock
        else
            source_2_clock - 1,
        .rd_prev_val = rd_previous,
        .rd_prev_clk = rd_previous_clock,
        .rd_val = result,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004 +% (clock - 1) *% 4,
        .inst_word = 0,
    };
}

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
