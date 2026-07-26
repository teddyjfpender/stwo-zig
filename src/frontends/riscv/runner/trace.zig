//! RISC-V execution capture and pinned Stark-V family trace generation.

const std = @import("std");
const decode = @import("decode.zig");
const opcode_manifest = @import("../opcode_manifest.zig");
const M31 = @import("stwo_core").fields.m31.M31;
const layouts = @import("../air/trace_columns.zig");
const base_witness = @import("witness/base.zig");
const compare_witness = @import("witness/compare.zig");
const control_witness = @import("witness/control.zig");
const shift_witness = @import("witness/shift.zig");
const load_store_witness = @import("witness/load_store.zig");
const m_extension_witness = @import("witness/m_extension.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const semantics = @import("../air/semantics/mod.zig");

const Opcode = decode.Opcode;

pub const TraceRow = struct {
    clk: u32,
    pc: u32,
    opcode: Opcode,
    rd: u5,
    rs1: u5,
    rs2: u5,
    imm: i32,
    rs1_val: u32,
    rs2_val: u32,
    rs1_prev_clk: u32 = 0,
    rs2_prev_clk: u32 = 0,
    rd_prev_val: u32 = 0,
    rd_prev_clk: u32 = 0,
    rd_val: u32,
    mem_addr: u32,
    mem_val: u32,
    mem_prev_word: u32 = 0,
    mem_next_word: u32 = 0,
    mem_prev_clk: u32 = 0,
    is_load: bool,
    is_store: bool,
    branch_taken: bool,
    next_pc: u32,
    inst_word: u32 = 0,
};

pub const Trace = struct {
    rows: std.ArrayList(TraceRow),
    allocator: std.mem.Allocator,
    initial_pc: u32,
    final_pc: u32,
    step_count: usize,

    pub fn init(allocator: std.mem.Allocator) Trace {
        return .{ .rows = .{}, .allocator = allocator, .initial_pc = 0, .final_pc = 0, .step_count = 0 };
    }

    pub fn deinit(self: *Trace) void {
        self.rows.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn append(self: *Trace, row: TraceRow) !void {
        try self.rows.append(self.allocator, row);
        self.step_count = self.rows.items.len;
    }

    pub fn groupByOpcodeFamily(self: *const Trace, _: std.mem.Allocator) !OpcodeFamilyCounts {
        var counts = OpcodeFamilyCounts{};
        for (self.rows.items) |row| counts.increment(try proofOpcodeFamily(row.opcode));
        return counts;
    }

    pub fn columnsForFamily(
        self: *const Trace,
        allocator: std.mem.Allocator,
        family: OpcodeFamily,
        log_size: u32,
    ) !TraceColumns {
        const size = @as(usize, 1) << @intCast(log_size);
        const count = nColumnsForFamily(family);
        var columns: [MAX_FAMILY_COLUMNS][]M31 = undefined;
        var initialized: usize = 0;
        errdefer for (columns[0..initialized]) |column| allocator.free(column);
        for (0..count) |column| {
            columns[column] = try allocator.alloc(M31, size);
            @memset(columns[column], M31.zero());
            initialized += 1;
        }
        var index: usize = 0;
        for (self.rows.items) |row| {
            if (try proofOpcodeFamily(row.opcode) != family) continue;
            if (index == size) break;
            fillFamilyColumns(&columns, index, row, family);
            index += 1;
        }
        return .{ .columns = columns, .n_columns = count, .n_real_rows = index };
    }
};

pub const MAX_FAMILY_COLUMNS: usize = 67;

pub const TraceColumns = struct {
    columns: [MAX_FAMILY_COLUMNS][]M31,
    n_columns: usize,
    n_real_rows: usize,

    pub fn deinit(self: *TraceColumns, allocator: std.mem.Allocator) void {
        for (self.columns[0..self.n_columns]) |column| allocator.free(column);
        self.* = undefined;
    }
};

pub fn nColumnsForFamily(family: OpcodeFamily) u32 {
    return switch (family) {
        .base_alu_reg => layouts.BaseAluRegColumns.N_COLUMNS,
        .base_alu_imm => layouts.BaseAluImmColumns.N_COLUMNS,
        .shifts_reg => layouts.ShiftsRegColumns.N_COLUMNS,
        .shifts_imm => layouts.ShiftsImmColumns.N_COLUMNS,
        .lt_reg => layouts.LtRegColumns.N_COLUMNS,
        .lt_imm => layouts.LtImmColumns.N_COLUMNS,
        .branch_eq => layouts.BranchEqColumns.N_COLUMNS,
        .branch_lt => layouts.BranchLtColumns.N_COLUMNS,
        .lui => layouts.LuiColumns.N_COLUMNS,
        .auipc => layouts.AuipcColumns.N_COLUMNS,
        .jalr => layouts.JalrColumns.N_COLUMNS,
        .jal => layouts.JalColumns.N_COLUMNS,
        .load_store => layouts.LoadStoreColumns.N_COLUMNS,
        .mul => layouts.MulColumns.N_COLUMNS,
        .mulh => layouts.MulhColumns.N_COLUMNS,
        .div => layouts.DivColumns.N_COLUMNS,
        .fence => layouts.FenceColumns.N_COLUMNS,
    };
}

pub fn fillFamilyColumns(
    columns: *[MAX_FAMILY_COLUMNS][]M31,
    index: usize,
    row: TraceRow,
    family: OpcodeFamily,
) void {
    switch (family) {
        .base_alu_reg => base_witness.reg(columns, index, row),
        .base_alu_imm => base_witness.immediate(columns, index, row),
        .shifts_reg => shift_witness.reg(columns, index, row),
        .shifts_imm => shift_witness.immediate(columns, index, row),
        .lt_reg => compare_witness.reg(columns, index, row),
        .lt_imm => compare_witness.immediate(columns, index, row),
        .branch_eq => compare_witness.branchEqual(columns, index, row),
        .branch_lt => compare_witness.branchLess(columns, index, row),
        .lui => control_witness.lui(columns, index, row),
        .auipc => control_witness.auipc(columns, index, row),
        .jalr => control_witness.jalr(columns, index, row),
        .jal => control_witness.jal(columns, index, row),
        .load_store => load_store_witness.fill(columns, index, row),
        .mul => m_extension_witness.mul(columns, index, row),
        .mulh => m_extension_witness.mulh(columns, index, row),
        .div => m_extension_witness.div(columns, index, row),
        .fence => control_witness.fence(columns, index, row),
    }
}

pub const OpcodeFamily = opcode_manifest.Family;

pub const N_FAMILIES: usize = @typeInfo(OpcodeFamily).@"enum".fields.len;

pub fn proofOpcodeFamily(opcode: Opcode) decode.ProofOpcodeError!OpcodeFamily {
    return opcode_manifest.family(try decode.proofOpcode(opcode));
}

/// Compatibility for prover internals that run only after `groupByOpcodeFamily`
/// has rejected unsupported execution opcodes.
pub fn opcodeFamily(opcode: Opcode) OpcodeFamily {
    return proofOpcodeFamily(opcode) catch unreachable;
}

pub const OpcodeFamilyCounts = struct {
    counts: [N_FAMILIES]usize = .{0} ** N_FAMILIES,

    pub fn increment(self: *OpcodeFamilyCounts, family: OpcodeFamily) void {
        self.counts[@intFromEnum(family)] += 1;
    }

    pub fn get(self: *const OpcodeFamilyCounts, family: OpcodeFamily) usize {
        return self.counts[@intFromEnum(family)];
    }

    pub fn total(self: *const OpcodeFamilyCounts) usize {
        var result: usize = 0;
        for (self.counts) |count| result += count;
        return result;
    }
};

test "trace groups opcode families" {
    try std.testing.expectEqual(OpcodeFamily.base_alu_reg, try proofOpcodeFamily(.ADD));
    try std.testing.expectEqual(OpcodeFamily.shifts_imm, try proofOpcodeFamily(.SRAI));
    try std.testing.expectEqual(OpcodeFamily.branch_lt, try proofOpcodeFamily(.BGEU));
    try std.testing.expectEqual(OpcodeFamily.load_store, try proofOpcodeFamily(.SW));
    try std.testing.expectEqual(OpcodeFamily.div, try proofOpcodeFamily(.REMU));
    try std.testing.expectEqual(OpcodeFamily.fence, try proofOpcodeFamily(.FENCE));
    try std.testing.expectError(error.UnsupportedForProof, proofOpcodeFamily(.ECALL));
}

test "trace rejects execution-only opcodes before family witness generation" {
    var trace = Trace.init(std.testing.allocator);
    defer trace.deinit();
    try trace.append(testRow(.ECALL));
    try std.testing.expectError(error.UnsupportedForProof, trace.groupByOpcodeFamily(std.testing.allocator));
    try std.testing.expectError(
        error.UnsupportedForProof,
        trace.columnsForFamily(std.testing.allocator, .base_alu_reg, 0),
    );
}

fn testRow(opcode: Opcode) TraceRow {
    return .{
        .clk = 1,
        .pc = 100,
        .opcode = opcode,
        .rd = 1,
        .rs1 = 2,
        .rs2 = 3,
        .imm = 0,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 104,
    };
}

fn filledRow(comptime n: usize, row: TraceRow, family: OpcodeFamily) [n]QM31 {
    var storage: [MAX_FAMILY_COLUMNS][1]M31 = .{.{M31.zero()}} ** MAX_FAMILY_COLUMNS;
    var columns: [MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (&columns, &storage) |*column, *values| column.* = values;
    fillFamilyColumns(&columns, 0, row, family);
    var result: [n]QM31 = undefined;
    for (&result, columns[0..n]) |*value, column| value.* = QM31.fromBase(column[0]);
    return result;
}

test "witness rows satisfy base and shift semantic evaluators" {
    var row = testRow(.ADD);
    row.rs1_val = 1;
    row.rs2_val = 2;
    row.rd_val = 3;
    var base_reg_columns = filledRow(semantics.base_alu_reg.N_ORACLE_COLUMNS, row, .base_alu_reg);
    const base_reg = try semantics.base_alu_reg.Row.fromOracleColumns(&base_reg_columns);
    try std.testing.expect(semantics.base_alu_reg.evaluate(base_reg).allZero());

    row = testRow(.ADDI);
    row.imm = -1;
    row.rs1_val = 1;
    row.rd_val = 0;
    var base_imm_columns = filledRow(semantics.base_alu_imm.N_ORACLE_COLUMNS, row, .base_alu_imm);
    const base_imm = try semantics.base_alu_imm.Row.fromOracleColumns(&base_imm_columns);
    try std.testing.expect(semantics.base_alu_imm.evaluate(base_imm).allZero());

    row = testRow(.SLL);
    row.rs1_val = 1;
    row.rs2_val = 1;
    row.rd_val = 2;
    var shift_reg_columns = filledRow(semantics.shifts_reg.N_ORACLE_COLUMNS, row, .shifts_reg);
    const shift_reg = try semantics.shifts_reg.Row.fromOracleColumns(&shift_reg_columns);
    try std.testing.expect(semantics.shifts_reg.evaluate(shift_reg).allZero());

    row = testRow(.SRAI);
    row.imm = 1;
    row.rs1_val = 0x80000000;
    row.rd_val = 0xc0000000;
    var shift_imm_columns = filledRow(semantics.shifts_imm.N_ORACLE_COLUMNS, row, .shifts_imm);
    const shift_imm = try semantics.shifts_imm.Row.fromOracleColumns(&shift_imm_columns);
    try std.testing.expect(semantics.shifts_imm.evaluate(shift_imm).allZero());
}

test "witness rows satisfy comparison and branch semantic evaluators" {
    var row = testRow(.SLTU);
    row.rs1_val = 1;
    row.rs2_val = 2;
    row.rd_val = 1;
    var lt_reg_columns = filledRow(semantics.lt_reg.N_ORACLE_COLUMNS, row, .lt_reg);
    const lt_reg = try semantics.lt_reg.Row.fromOracleColumns(&lt_reg_columns);
    try std.testing.expect(semantics.lt_reg.evaluate(lt_reg).allZero());

    row = testRow(.SLTI);
    row.imm = 2;
    row.rs1_val = 1;
    row.rd_val = 1;
    var lt_imm_columns = filledRow(semantics.lt_imm.N_ORACLE_COLUMNS, row, .lt_imm);
    const lt_imm = try semantics.lt_imm.Row.fromOracleColumns(&lt_imm_columns);
    try std.testing.expect(semantics.lt_imm.evaluate(lt_imm).allZero());

    row = testRow(.BEQ);
    row.rs1_val = 7;
    row.rs2_val = 7;
    row.imm = 8;
    row.next_pc = 108;
    var branch_eq_columns = filledRow(semantics.branch_eq.N_MAIN_COLUMNS, row, .branch_eq);
    const branch_eq = try semantics.branch_eq.Row.fromMainColumns(&branch_eq_columns);
    try std.testing.expect(semantics.branch_eq.evaluate(branch_eq).allZero());

    row = testRow(.BLTU);
    row.rs1_val = 1;
    row.rs2_val = 2;
    row.imm = 8;
    row.next_pc = 108;
    var branch_lt_columns = filledRow(semantics.branch_lt.N_MAIN_COLUMNS, row, .branch_lt);
    const branch_lt = try semantics.branch_lt.Row.fromMainColumns(&branch_lt_columns);
    try std.testing.expect(semantics.branch_lt.evaluate(branch_lt).allZero());
}

test "witness rows satisfy upper jump and memory semantic evaluators" {
    var row = testRow(.LUI);
    row.imm = @bitCast(@as(u32, 0x12345000));
    row.rd_val = 0x12345000;
    var lui_columns = filledRow(semantics.lui.N_MAIN_COLUMNS, row, .lui);
    const lui = try semantics.lui.Row.fromMainColumns(&lui_columns);
    try std.testing.expect(semantics.lui.evaluate(lui).allZero());

    row = testRow(.AUIPC);
    row.imm = 20;
    row.rd_val = 120;
    var auipc_columns = filledRow(semantics.auipc.N_MAIN_COLUMNS, row, .auipc);
    const auipc = try semantics.auipc.Row.fromMainColumns(&auipc_columns);
    try std.testing.expect(semantics.auipc.evaluate(auipc).allZero());

    row = testRow(.JAL);
    row.imm = 8;
    row.rd_val = 104;
    row.next_pc = 108;
    var jal_columns = filledRow(semantics.jal.N_MAIN_COLUMNS, row, .jal);
    const jal = try semantics.jal.Row.fromMainColumns(&jal_columns);
    try std.testing.expect(semantics.jal.evaluate(jal).allZero());

    row = testRow(.JALR);
    row.imm = 3;
    row.rs1_val = 100;
    row.rd_val = 104;
    row.next_pc = 102;
    var jalr_columns = filledRow(semantics.jalr.N_MAIN_COLUMNS, row, .jalr);
    const jalr = try semantics.jalr.Row.fromMainColumns(&jalr_columns);
    try std.testing.expect(semantics.jalr.evaluate(jalr).allZero());

    row = testRow(.LW);
    row.rd = 4;
    row.rs1_val = 100;
    row.rd_val = 0x04030201;
    row.mem_addr = 100;
    row.mem_val = row.rd_val;
    row.mem_prev_word = row.rd_val;
    row.mem_next_word = row.rd_val;
    row.is_load = true;
    var memory_columns = filledRow(semantics.load_store.N_ORACLE_COLUMNS, row, .load_store);
    const memory = try semantics.load_store.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(semantics.load_store.evaluate(memory).allZero());

    row = testRow(.LB);
    row.rd = 4;
    row.rs1_val = 101;
    row.rd_val = 0xffffff80;
    row.mem_addr = 101;
    row.mem_val = 0x80;
    row.mem_prev_word = 0x00008000;
    row.mem_next_word = 0x00008000;
    row.is_load = true;
    memory_columns = filledRow(semantics.load_store.N_ORACLE_COLUMNS, row, .load_store);
    const byte_load = try semantics.load_store.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(semantics.load_store.evaluate(byte_load).allZero());

    row = testRow(.SH);
    row.rs1_val = 102;
    row.rs2_val = 0xbeef;
    row.mem_addr = 102;
    row.mem_val = 0xbeef;
    row.mem_prev_word = 0;
    row.mem_next_word = 0xbeef0000;
    row.is_store = true;
    memory_columns = filledRow(semantics.load_store.N_ORACLE_COLUMNS, row, .load_store);
    const half_store = try semantics.load_store.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(semantics.load_store.evaluate(half_store).allZero());
}

test "padding rows remain inactive for flag and explicit-enabler families" {
    const zero = [_]QM31{QM31.zero()} ** semantics.base_alu_reg.N_ORACLE_COLUMNS;
    const base = try semantics.base_alu_reg.Row.fromOracleColumns(&zero);
    try std.testing.expect(base.active().isZero());
    try std.testing.expect(semantics.base_alu_reg.evaluate(base).allZero());

    const control_zero = [_]QM31{QM31.zero()} ** semantics.jal.N_MAIN_COLUMNS;
    const control = try semantics.jal.Row.fromMainColumns(&control_zero);
    try std.testing.expect(control.enabler.isZero());
    try std.testing.expect(semantics.jal.evaluate(control).allZero());
}
