//! Parity, geometry, prefix-scan, and allocation-failure tests for the
//! production opcode interaction generator.

const std = @import("std");
const fields = @import("stwo_core").fields;
const work_pool = @import("stwo_prover_engine").work_pool;
const m31 = fields.m31;
const M31 = m31.M31;
const QM31 = fields.qm31.QM31;
const PackedM31 = m31.PackedM31;
const infra = @import("../../infra_trace.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const BaseScalar = @import("base_scalar.zig").Scalar;
const opcode_entries = @import("opcode_entries.zig");
const subject = @import("opcode_interaction.zig");

const MAX_BATCHES = subject.MAX_BATCHES;
const CHUNK_ROWS = subject.CHUNK_ROWS;
const Plan = subject.Plan;
const generate = subject.generate;
const generateParallel = subject.generateParallel;
const nColumns = subject.nColumns;
const base_opcode_entries = subject.TestHooks.baseOpcodeEntries;
const pairBase = subject.TestHooks.pairBaseForTest;
const pairPlanned = subject.TestHooks.pairPlannedForTest;
const PackedRelationProgram = subject.TestHooks.PackedRelationProgram;

fn testRow() trace.TraceRow {
    return .{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 1,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x00100093,
    };
}

const TestColumns = struct {
    storage: [trace.MAX_FAMILY_COLUMNS][]M31,
    len: usize,
};

fn testColumns(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    log_size: u32,
    rows: []const trace.TraceRow,
) !TestColumns {
    const len = trace.nColumnsForFamily(family);
    const size = @as(usize, 1) << @intCast(log_size);
    var result = TestColumns{ .storage = undefined, .len = len };
    var initialized: usize = 0;
    errdefer for (result.storage[0..initialized]) |column| allocator.free(column);
    for (result.storage[0..len]) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    if (rows.len > size) return error.InvalidTraceShape;
    for (rows, 0..) |row, index| {
        trace.validateFamilyRow(row, family) catch |err| {
            std.debug.print(
                "invalid opcode interaction fixture: family={s} row={d}\n",
                .{ @tagName(family), index },
            );
            return err;
        };
        trace.fillFamilyColumns(&result.storage, placement.map(index), row, family);
    }
    return result;
}

fn freeTestColumns(
    allocator: std.mem.Allocator,
    columns: anytype,
) void {
    for (columns.storage[0..columns.len]) |column| allocator.free(column);
}

fn pairTerm(pair: logup.RowPair) !QM31 {
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return numerator.mul(try denominator.inv());
}

fn expectBaseEntryParity(
    family: trace.OpcodeFamily,
    main: []const []const M31,
    committed_row: usize,
    relations: *const relations_mod.Relations,
) !void {
    var base: [trace.MAX_FAMILY_COLUMNS]BaseScalar = undefined;
    var secure: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    for (main, base[0..main.len], secure[0..main.len]) |column, *base_value, *secure_value| {
        const value = column[committed_row];
        base_value.* = BaseScalar.fromBase(value);
        secure_value.* = QM31.fromBase(value);
    }
    const actual = try base_opcode_entries.fromMain(family, base[0..main.len]);
    const oracle = try opcode_entries.fromMain(family, secure[0..main.len]);
    try std.testing.expectEqual(oracle.len, actual.len);
    try std.testing.expectEqual(oracle.batch_size, actual.batch_size);
    for (actual.entries[0..actual.len], oracle.entries[0..oracle.len]) |got, want| {
        try std.testing.expectEqual(want.domain, got.domain);
        try std.testing.expectEqual(want.arity, got.arity);
        try std.testing.expectEqual(want.role, got.role);
        try std.testing.expectEqual(want.access_ordinal, got.access_ordinal);
        try std.testing.expect(QM31.fromBase(got.numerator.value).eql(want.numerator));
        for (got.values[0..got.arity], want.values[0..want.arity]) |got_value, want_value| {
            try std.testing.expect(QM31.fromBase(got_value.value).eql(want_value));
        }
    }
    try std.testing.expectEqual(oracle.batchCount(), actual.batchCount());
    for (0..actual.batchCount()) |batch| {
        const got = try pairBase(&actual, batch, relations);
        const want = try oracle.pair(batch, relations);
        try std.testing.expect(got.n1.eql(want.n1));
        try std.testing.expect(got.d1.eql(want.d1));
        try std.testing.expect(got.n2.eql(want.n2));
        try std.testing.expect(got.d2.eql(want.d2));
    }
}

fn expectPlanPairParity(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    main: []const []const M31,
    committed_active_row: usize,
    committed_padding_row: usize,
    relations: *const relations_mod.Relations,
) !void {
    var plan = try Plan.init(allocator, family);
    defer plan.deinit();
    var packed_relations = try PackedRelationProgram.init(
        allocator,
        plan.program.entries,
        plan.domains[0..plan.program.entries.len],
        relations,
    );
    defer packed_relations.deinit();
    const node_values = try allocator.alloc(PackedM31, plan.program.nodes.len);
    defer allocator.free(node_values);
    var packed_columns: [trace.MAX_FAMILY_COLUMNS]PackedM31 = undefined;
    for (main, packed_columns[0..main.len]) |column, *packed_column| {
        inline for (0..m31.PACK_WIDTH) |lane| {
            const row = if (lane % 2 == 0) committed_active_row else committed_padding_row;
            packed_column[lane] = column[row].v;
        }
    }
    plan.evaluation.evaluate(
        plan.program.nodes,
        node_values,
        packed_columns[0..main.len],
    );

    inline for (0..m31.PACK_WIDTH) |lane| {
        const row = if (lane % 2 == 0) committed_active_row else committed_padding_row;
        var scalar_columns: [trace.MAX_FAMILY_COLUMNS]BaseScalar = undefined;
        for (main, scalar_columns[0..main.len]) |column, *value| {
            value.* = BaseScalar.fromBase(column[row]);
        }
        const typed = try base_opcode_entries.fromMain(family, scalar_columns[0..main.len]);
        for (0..typed.batchCount()) |batch| {
            const expected = try pairBase(&typed, batch, relations);
            const actual = try pairPlanned(&plan, node_values, batch, &packed_relations);
            try std.testing.expect(QM31.fromBase(M31.fromCanonical(actual.n1[lane])).eql(expected.n1));
            try std.testing.expect(actual.d1.lane(lane).eql(expected.d1));
            try std.testing.expect(QM31.fromBase(M31.fromCanonical(actual.n2[lane])).eql(expected.n2));
            try std.testing.expect(actual.d2.lane(lane).eql(expected.d2));
        }
    }
}

fn testRowForFamily(family: trace.OpcodeFamily, row_index: usize) trace.TraceRow {
    var row = testRow();
    row.clk = @intCast(row_index + 1);
    row.pc = @intCast(0x1000 + 4 * row_index);
    row.next_pc = row.pc + 4;
    row.rs1_prev_clk = row.clk - 1;
    row.rs2_prev_clk = row.clk - 1;
    row.rd_prev_clk = row.clk - 1;
    row.rd_prev_val = 0;
    row.rd = 1;
    row.rs1 = 2;
    row.rs2 = 3;
    row.imm = 0;
    switch (family) {
        .base_alu_reg => {
            row.opcode = .ADD;
            row.rs1_val = 1;
            row.rs2_val = 2;
            row.rd_val = 3;
        },
        .base_alu_imm => {
            row.opcode = .ADDI;
            row.rs1_val = 2;
            row.imm = 1;
            row.rd_val = 3;
        },
        .shifts_reg => {
            row.opcode = .SLL;
            row.rs1_val = 3;
            row.rs2_val = 1;
            row.rd_val = 6;
        },
        .shifts_imm => {
            row.opcode = .SLLI;
            row.rs1_val = 3;
            row.imm = 1;
            row.rd_val = 6;
        },
        .lt_reg => {
            row.opcode = .SLTU;
            row.rs1_val = 1;
            row.rs2_val = 2;
            row.rd_val = 1;
        },
        .lt_imm => {
            row.opcode = .SLTIU;
            row.rs1_val = 1;
            row.imm = 2;
            row.rd_val = 1;
        },
        .branch_eq => {
            row.opcode = .BNE;
            row.rs1_val = 1;
            row.rs2_val = 2;
            row.imm = 8;
            row.branch_taken = true;
            row.next_pc = row.pc + 8;
        },
        .branch_lt => {
            row.opcode = .BLTU;
            row.rs1_val = 1;
            row.rs2_val = 2;
            row.imm = 8;
            row.branch_taken = true;
            row.next_pc = row.pc + 8;
        },
        .lui => {
            row.opcode = .LUI;
            row.imm = 0x1234_5000;
            row.rd_val = 0x1234_5000;
        },
        .auipc => {
            row.opcode = .AUIPC;
            row.imm = 0x1000;
            row.rd_val = row.pc + 0x1000;
        },
        .jalr => {
            row.opcode = .JALR;
            row.rs1_val = 0x2000;
            row.rs2 = 0;
            row.rs2_val = 0;
            row.rs2_prev_clk = 0;
            row.imm = 4;
            row.rd_val = row.pc + 4;
            row.next_pc = 0x2004;
            row.branch_taken = true;
        },
        .jal => {
            row.opcode = .JAL;
            row.imm = 8;
            row.rd_val = row.pc + 4;
            row.next_pc = row.pc + 8;
            row.branch_taken = true;
        },
        .load_store => {
            row.opcode = .LW;
            row.rs2 = 0;
            row.rs2_val = 0;
            row.rs2_prev_clk = 0;
            row.rs1_val = 0x2000;
            row.imm = 0;
            row.mem_addr = 0x2000;
            row.mem_val = 0x1122_3344;
            row.mem_prev_word = 0x1122_3344;
            row.mem_next_word = 0x1122_3344;
            row.rd_val = 0x1122_3344;
            row.is_load = true;
            row.inst_word = 0x0001_2083;
        },
        .mul => {
            row.opcode = .MUL;
            row.rs1_val = 2;
            row.rs2_val = 3;
            row.rd_val = 6;
            row.inst_word = 0x0231_00b3;
        },
        .mulh => {
            row.opcode = .MULHU;
            row.rs1_val = 0x1_0000;
            row.rs2_val = 0x1_0000;
            row.rd_val = 1;
            row.inst_word = 0x0231_30b3;
        },
        .div => {
            row.opcode = .DIVU;
            row.rs1_val = 7;
            row.rs2_val = 3;
            row.rd_val = 2;
            row.inst_word = 0x0231_50b3;
        },
        .fence => {
            row.opcode = .FENCE;
            row.rd = 0;
            row.rs1 = 0;
            row.rs2 = 0;
            row.rs1_prev_clk = 0;
            row.rs2_prev_clk = 0;
            row.rd_prev_clk = 0;
            row.rd_val = 0;
            row.imm = 0x0ff;
            row.inst_word = 0x0ff0000f;
        },
    }
    return row;
}

fn secureAt(columns: []const []const M31, offset: usize, row: usize) QM31 {
    return QM31.fromM31(
        columns[offset][row],
        columns[offset + 1][row],
        columns[offset + 2][row],
        columns[offset + 3][row],
    );
}

fn expectScalarParity(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    row: trace.TraceRow,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !void {
    var main = try testColumns(allocator, family, log_size, &.{row});
    defer freeTestColumns(allocator, main);
    var generated = try generate(
        allocator,
        family,
        main.storage[0..main.len],
        log_size,
        relations,
    );
    defer generated.deinit(allocator);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    const size = @as(usize, 1) << @intCast(log_size);
    const oracle = try opcode_entries.fromTraceRow(row, family);
    var accumulators = [_]QM31{QM31.zero()} ** MAX_BATCHES;
    var secure_row: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;

    for (0..size) |logical_row| {
        const committed_row = placement.map(logical_row);
        for (main.storage[0..main.len], secure_row[0..main.len]) |column, *value| {
            value.* = QM31.fromBase(column[committed_row]);
        }
        const actual_entries = try opcode_entries.fromMain(family, secure_row[0..main.len]);
        try std.testing.expectEqual(generated.n_batches, actual_entries.batchCount());
        for (0..generated.n_batches) |batch| {
            const term = try pairTerm(try actual_entries.pair(batch, relations));
            if (logical_row == 0) {
                const oracle_term = try pairTerm(try oracle.pair(batch, relations));
                try std.testing.expect(term.eql(oracle_term));
            } else {
                try std.testing.expect(term.isZero());
            }
            const expected_previous = if (logical_row == 0)
                generated.claims[batch]
            else
                accumulators[batch];
            accumulators[batch] = accumulators[batch].add(term);
            try std.testing.expect(
                secureAt(&generated.columns, 4 * batch, committed_row)
                    .eql(accumulators[batch]),
            );
            const previous_row = placement.map((logical_row + size - 1) % size);
            try std.testing.expect(
                secureAt(&generated.columns, 4 * batch, previous_row)
                    .eql(expected_previous),
            );
        }
    }
    for (accumulators[0..generated.n_batches], generated.claims[0..generated.n_batches]) |expected, actual| {
        try std.testing.expect(actual.eql(expected));
    }
}

test "opcode interaction derives exact claims from committed main columns" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const relations = relations_mod.Relations.dummy();
    var main = try testColumns(allocator, family, 4, &.{testRow()});
    defer freeTestColumns(allocator, main);
    var generated = try generate(
        allocator,
        family,
        main.storage[0..main.len],
        4,
        &relations,
    );
    defer generated.deinit(allocator);

    try std.testing.expectEqual(opcode_entries.batchCount(family), generated.n_batches);
    try std.testing.expectEqual(nColumns(family), generated.nColumns());
    const list = try opcode_entries.fromTraceRow(testRow(), family);
    var expected = QM31.zero();
    for (0..list.batchCount()) |batch| expected = expected.add(try pairTerm(
        try list.pair(batch, &relations),
    ));
    try std.testing.expect(generated.total().eql(expected));

    const column_count = generated.nColumns();
    const owned_columns = generated.takeColumns();
    defer for (owned_columns[0..column_count]) |column| allocator.free(column);
    for (generated.columns[0..column_count]) |column| {
        try std.testing.expectEqual(@as(usize, 0), column.len);
    }
    for (owned_columns[0..column_count]) |column| {
        try std.testing.expectEqual(@as(usize, 16), column.len);
    }
    try std.testing.expect(generated.total().eql(expected));
}

test "opcode interaction is padding invariant and shard additive" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const relations = relations_mod.Relations.dummy();
    var compact_main = try testColumns(allocator, family, 4, &.{testRow()});
    defer freeTestColumns(allocator, compact_main);
    var padded_main = try testColumns(allocator, family, 5, &.{testRow()});
    defer freeTestColumns(allocator, padded_main);
    var compact = try generate(
        allocator,
        family,
        compact_main.storage[0..compact_main.len],
        4,
        &relations,
    );
    defer compact.deinit(allocator);
    var padded = try generate(
        allocator,
        family,
        padded_main.storage[0..padded_main.len],
        5,
        &relations,
    );
    defer padded.deinit(allocator);
    try std.testing.expect(compact.total().eql(padded.total()));
    try std.testing.expectEqual(compact.n_batches, padded.n_batches);
    for (compact.claims[0..compact.n_batches], padded.claims[0..padded.n_batches]) |compact_claim, padded_claim| {
        try std.testing.expect(compact_claim.eql(padded_claim));
    }

    var combined_main = try testColumns(
        allocator,
        family,
        4,
        &.{ testRow(), testRow() },
    );
    defer freeTestColumns(allocator, combined_main);
    var combined = try generate(
        allocator,
        family,
        combined_main.storage[0..combined_main.len],
        4,
        &relations,
    );
    defer combined.deinit(allocator);
    try std.testing.expect(combined.total().eql(
        compact.total().add(padded.total()),
    ));
    try std.testing.expectEqual(compact.n_batches, combined.n_batches);
    for (
        combined.claims[0..combined.n_batches],
        compact.claims[0..compact.n_batches],
        padded.claims[0..padded.n_batches],
    ) |combined_claim, compact_claim, padded_claim| {
        try std.testing.expect(combined_claim.eql(compact_claim.add(padded_claim)));
    }
}

test "opcode interaction rejects malformed committed geometry" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const relations = relations_mod.Relations.dummy();
    var main = try testColumns(allocator, family, 4, &.{testRow()});
    defer freeTestColumns(allocator, main);
    try std.testing.expectError(
        error.InvalidColumnCount,
        generate(allocator, family, main.storage[0 .. main.len - 1], 4, &relations),
    );
    const saved = main.storage[0];
    main.storage[0] = saved[0 .. saved.len - 1];
    defer main.storage[0] = saved;
    try std.testing.expectError(
        error.InvalidColumnLength,
        generate(allocator, family, main.storage[0..main.len], 4, &relations),
    );
}

test "opcode interaction matches scalar prefixes for every family" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    // The batch geometry itself is pinned once, by `opcode_entries.zig`. This
    // test owns scalar parity of the generated interaction columns.
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        try expectScalarParity(
            allocator,
            family,
            testRowForFamily(family, index),
            4,
            &relations,
        );
    }
}

fn expectParallelParity(family: trace.OpcodeFamily) !void {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const log_size: u32 = 13;
    var main = try testColumns(
        allocator,
        family,
        log_size,
        &.{testRowForFamily(family, 0)},
    );
    defer freeTestColumns(allocator, main);
    var expected = try generate(
        allocator,
        family,
        main.storage[0..main.len],
        log_size,
        &relations,
    );
    defer expected.deinit(allocator);

    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = 512 * 1024,
        .backing_allocator = allocator,
    });
    defer pool.deinit();
    var actual = try generateParallel(
        allocator,
        family,
        main.storage[0..main.len],
        log_size,
        &relations,
        &pool,
    );
    defer actual.deinit(allocator);

    try std.testing.expectEqual(expected.n_batches, actual.n_batches);
    for (expected.claims[0..expected.n_batches], actual.claims[0..actual.n_batches]) |
        expected_claim,
        actual_claim,
    | try std.testing.expect(actual_claim.eql(expected_claim));
    for (expected.columns[0..expected.nColumns()], actual.columns[0..actual.nColumns()]) |
        expected_column,
        actual_column,
    | try std.testing.expectEqualSlices(M31, expected_column, actual_column);
}

test "packed parallel paired opcode interaction matches scalar generation" {
    try expectParallelParity(.base_alu_reg);
}

test "packed parallel singleton opcode interaction matches scalar generation" {
    try expectParallelParity(.mul);
}

test "packed parallel wide opcode interaction matches scalar generation" {
    try expectParallelParity(.load_store);
}

test "base-field opcode entries match secure reconstruction for every family and padding" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        var main = try testColumns(
            allocator,
            family,
            4,
            &.{testRowForFamily(family, index)},
        );
        defer freeTestColumns(allocator, main);
        const placement = try infra.BitReversalTable.init(allocator, 4);
        defer placement.deinit(allocator);
        try expectBaseEntryParity(
            family,
            main.storage[0..main.len],
            placement.map(0),
            &relations,
        );
        try expectBaseEntryParity(
            family,
            main.storage[0..main.len],
            placement.map(15),
            &relations,
        );
        try expectPlanPairParity(
            allocator,
            family,
            main.storage[0..main.len],
            placement.map(0),
            placement.map(15),
            &relations,
        );
    }
}

test "opcode interaction carries cumulative state across inversion chunks" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const relations = relations_mod.Relations.dummy();
    const n_rows = CHUNK_ROWS + 2;
    const log_size: u32 = 13;
    const rows = try allocator.alloc(trace.TraceRow, n_rows);
    defer allocator.free(rows);
    for (rows, 0..) |*row, index| row.* = testRowForFamily(family, index);
    var main = try testColumns(allocator, family, log_size, rows);
    defer freeTestColumns(allocator, main);
    var generated = try generate(
        allocator,
        family,
        main.storage[0..main.len],
        log_size,
        &relations,
    );
    defer generated.deinit(allocator);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    var accumulators = [_]QM31{QM31.zero()} ** MAX_BATCHES;
    var secure_row: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;

    for (0..n_rows) |logical_row| {
        const committed_row = placement.map(logical_row);
        for (main.storage[0..main.len], secure_row[0..main.len]) |column, *value| {
            value.* = QM31.fromBase(column[committed_row]);
        }
        const list = try opcode_entries.fromMain(family, secure_row[0..main.len]);
        for (0..generated.n_batches) |batch| {
            accumulators[batch] = accumulators[batch].add(
                try pairTerm(try list.pair(batch, &relations)),
            );
            if (logical_row + 1 >= CHUNK_ROWS) {
                try std.testing.expect(
                    secureAt(&generated.columns, 4 * batch, committed_row)
                        .eql(accumulators[batch]),
                );
            }
        }
    }
    for (accumulators[0..generated.n_batches], generated.claims[0..generated.n_batches]) |expected, actual| {
        try std.testing.expect(actual.eql(expected));
    }
    const final_padding_row = placement.map((@as(usize, 1) << @intCast(log_size)) - 1);
    for (0..generated.n_batches) |batch| {
        try std.testing.expect(
            secureAt(&generated.columns, 4 * batch, final_padding_row)
                .eql(generated.claims[batch]),
        );
    }
}

fn generateForAllocationTest(
    allocator: std.mem.Allocator,
    columns: []const []const M31,
    relations: *const relations_mod.Relations,
) !void {
    var generated = try generate(
        allocator,
        .base_alu_imm,
        columns,
        4,
        relations,
    );
    defer generated.deinit(allocator);
}

test "opcode interaction rolls back every allocation failure" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var main = try testColumns(allocator, .base_alu_imm, 4, &.{testRow()});
    defer freeTestColumns(allocator, main);
    try std.testing.checkAllAllocationFailures(
        allocator,
        generateForAllocationTest,
        .{ main.storage[0..main.len], &relations },
    );
}

fn prepareRelationsForAllocationTest(
    allocator: std.mem.Allocator,
    plan: *const Plan,
    relations: *const relations_mod.Relations,
) !void {
    var prepared = try PackedRelationProgram.init(
        allocator,
        plan.program.entries,
        plan.domains[0..plan.program.entries.len],
        relations,
    );
    defer prepared.deinit();
}

test "packed opcode relation program is fail-closed and allocation-safe" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var plan = try Plan.init(allocator, .load_store);
    defer plan.deinit();

    try std.testing.expectError(
        error.InvalidLookupPolynomialProgram,
        PackedRelationProgram.init(
            allocator,
            plan.program.entries,
            plan.domains[0 .. plan.program.entries.len - 1],
            &relations,
        ),
    );
    try std.testing.checkAllAllocationFailures(
        allocator,
        prepareRelationsForAllocationTest,
        .{ &plan, &relations },
    );
}
