//! Exact interaction columns for the pinned Stark-V opcode lookup matrices.
//!
//! Inputs are the padded, bit-reversed M31 columns committed in the main tree.
//! Every logical row is parsed once through `opcode_entries.fromMain`; relation
//! denominators are then batch-inverted in bounded chunks for all of the
//! family's declaration-order batches.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../infra_trace.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const entry = @import("entry.zig");
const opcode_entries = @import("opcode_entries.zig");

pub const MAX_BATCHES: usize = entry.MAX_BATCHES;
pub const MAX_COLUMNS: usize = 4 * MAX_BATCHES;
pub const CHUNK_ROWS: usize = 4096;

pub const Result = struct {
    columns: [MAX_COLUMNS][]M31 = .{&.{}} ** MAX_COLUMNS,
    previous: [MAX_BATCHES][4][]M31 = .{.{ &.{}, &.{}, &.{}, &.{} }} ** MAX_BATCHES,
    claims: [MAX_BATCHES]QM31 = .{QM31.zero()} ** MAX_BATCHES,
    n_batches: usize,

    pub fn nColumns(self: *const Result) usize {
        return 4 * self.n_batches;
    }

    pub fn total(self: *const Result) QM31 {
        var result = QM31.zero();
        for (self.claims[0..self.n_batches]) |claim| result = result.add(claim);
        return result;
    }

    /// Moves the current cumulative columns out for commitment. The returned
    /// active prefix is caller-owned; claims and previous-row masks remain
    /// valid until `deinit` so composition can borrow them after the commit.
    pub fn takeColumns(self: *Result) [MAX_COLUMNS][]M31 {
        const result = self.columns;
        for (self.columns[0..self.nColumns()]) |*column| column.* = &.{};
        return result;
    }

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        for (self.columns[0..self.nColumns()]) |column| {
            if (column.len != 0) allocator.free(column);
        }
        for (self.previous[0..self.n_batches]) |set| {
            for (set) |column| allocator.free(column);
        }
        self.* = undefined;
    }
};

pub fn nColumns(family: trace.OpcodeFamily) usize {
    return opcode_entries.interactionColumnCount(family);
}

/// Generate all declaration-order cumulative columns for one opcode shard.
/// `main_columns` contains only the canonical family witness columns; derived
/// host-side bus columns are neither accepted nor needed.
pub fn generate(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
    main_columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Result {
    const size = @as(usize, 1) << @intCast(log_size);
    try validateColumns(family, main_columns, size);
    const n_batches = opcode_entries.batchCount(family);
    var result = Result{ .n_batches = n_batches };
    var allocated_columns: usize = 0;
    var allocated_previous: usize = 0;
    errdefer {
        for (result.columns[0..allocated_columns]) |column| allocator.free(column);
        for (0..allocated_previous) |flat_index| {
            allocator.free(result.previous[flat_index / 4][flat_index % 4]);
        }
    }
    for (result.columns[0 .. 4 * n_batches]) |*column| {
        column.* = try allocator.alloc(M31, size);
        allocated_columns += 1;
    }
    for (result.previous[0..n_batches]) |*set| {
        for (set) |*column| {
            column.* = try allocator.alloc(M31, size);
            allocated_previous += 1;
        }
    }

    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    const chunk_capacity = @min(size, CHUNK_ROWS);
    const term_capacity = n_batches * chunk_capacity;
    const numerators = try allocator.alloc(QM31, term_capacity);
    defer allocator.free(numerators);
    const denominators = try allocator.alloc(QM31, term_capacity);
    defer allocator.free(denominators);
    const inverses = try allocator.alloc(QM31, term_capacity);
    defer allocator.free(inverses);

    var secure: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    var row_start: usize = 0;
    while (row_start < size) {
        const chunk_len = @min(CHUNK_ROWS, size - row_start);
        const term_len = n_batches * chunk_len;
        for (0..chunk_len) |local_row| {
            const row = row_start + local_row;
            const committed_row = placement.map(row);
            for (main_columns, secure[0..main_columns.len]) |column, *value| {
                value.* = QM31.fromBase(column[committed_row]);
            }
            const list = try opcode_entries.fromMain(
                family,
                secure[0..main_columns.len],
            );
            if (list.batchCount() != n_batches) return error.InvalidBatchCount;
            for (0..n_batches) |batch| {
                const pair = try list.pair(batch, relations);
                const index = batch * chunk_len + local_row;
                denominators[index] = pair.d1.mul(pair.d2);
                numerators[index] = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
            }
        }
        try fields.batchInverseInPlace(
            QM31,
            denominators[0..term_len],
            inverses[0..term_len],
        );
        for (0..n_batches) |batch| {
            for (0..chunk_len) |local_row| {
                const row = row_start + local_row;
                const term_index = batch * chunk_len + local_row;
                result.claims[batch] = result.claims[batch].add(
                    numerators[term_index].mul(inverses[term_index]),
                );
                const coordinates = result.claims[batch].toM31Array();
                const dst = placement.map(row);
                for (coordinates, 0..) |coordinate, index| {
                    result.columns[4 * batch + index][dst] = coordinate;
                }
            }
        }
        row_start += chunk_len;
    }

    // Previous masks are trace-order rotations, stored in the same committed
    // bit-reversed order as the current cumulative columns.
    for (0..size) |row| {
        const dst = placement.map(row);
        const previous_dst = placement.map((row + size - 1) % size);
        for (0..n_batches) |batch| {
            for (0..4) |coordinate| {
                result.previous[batch][coordinate][dst] =
                    result.columns[4 * batch + coordinate][previous_dst];
            }
        }
    }
    return result;
}

fn validateColumns(
    family: trace.OpcodeFamily,
    columns: []const []const M31,
    size: usize,
) !void {
    if (columns.len != trace.nColumnsForFamily(family))
        return error.InvalidColumnCount;
    for (columns) |column| {
        if (column.len != size) return error.InvalidColumnLength;
    }
}

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
            row.imm = 4;
            row.rd_val = row.pc + 4;
            row.next_pc = 0x2004;
        },
        .jal => {
            row.opcode = .JAL;
            row.imm = 8;
            row.rd_val = row.pc + 4;
            row.next_pc = row.pc + 8;
        },
        .load_store => {
            row.opcode = .LW;
            row.rs1_val = 0x2000;
            row.imm = 0;
            row.mem_addr = 0x2000;
            row.mem_val = 0x1122_3344;
            row.mem_prev_word = 0x1122_3344;
            row.mem_next_word = 0x1122_3344;
            row.rd_val = 0x1122_3344;
            row.is_load = true;
        },
        .mul => {
            row.opcode = .MUL;
            row.rs1_val = 2;
            row.rs2_val = 3;
            row.rd_val = 6;
        },
        .mulh => {
            row.opcode = .MULHU;
            row.rs1_val = 0x1_0000;
            row.rs2_val = 0x1_0000;
            row.rd_val = 1;
        },
        .div => {
            row.opcode = .DIVU;
            row.rs1_val = 7;
            row.rs2_val = 3;
            row.rd_val = 2;
        },
        .fence => {
            row.opcode = .FENCE;
            row.rd = 0;
            row.rs1 = 0;
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
            try std.testing.expect(
                secureAt(&generated.previous[batch], 0, committed_row)
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
    for (generated.previous[0..generated.n_batches]) |set| {
        for (set) |column| try std.testing.expectEqual(@as(usize, 16), column.len);
    }
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
            const expected_previous = accumulators[batch];
            accumulators[batch] = accumulators[batch].add(
                try pairTerm(try list.pair(batch, &relations)),
            );
            if (logical_row + 1 >= CHUNK_ROWS) {
                try std.testing.expect(
                    secureAt(&generated.columns, 4 * batch, committed_row)
                        .eql(accumulators[batch]),
                );
                if (logical_row != 0) {
                    try std.testing.expect(
                        secureAt(&generated.previous[batch], 0, committed_row)
                            .eql(expected_previous),
                    );
                }
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
