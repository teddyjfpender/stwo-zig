//! Trace admission and independent retired-evaluator differential tests.
const std = @import("std");
const trace_mod = @import("trace.zig");
const opcode_manifest = @import("../opcode_manifest.zig");
const Opcode = @import("decode.zig").Opcode;
const M31 = @import("stwo_core").fields.m31.M31;
const Trace = trace_mod.Trace;
const TraceRow = trace_mod.TraceRow;
const OpcodeFamily = trace_mod.OpcodeFamily;
const ProofOpcode = trace_mod.ProofOpcode;
const MAX_FAMILY_COLUMNS = trace_mod.MAX_FAMILY_COLUMNS;
const proofOpcodeFamily = trace_mod.proofOpcodeFamily;
const opcodeFamily = trace_mod.opcodeFamily;
const fillFamilyColumns = trace_mod.fillFamilyColumns;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const base_alu_imm_test_oracle = @import("../air/semantics/base_alu_imm_legacy_test_oracle.zig").Semantics(QM31);
const base_alu_reg_test_oracle =
    @import("../air/semantics/base_alu_reg_legacy_test_oracle.zig").Semantics(QM31);
const jal_test_oracle =
    @import("../air/semantics/jal_legacy_test_oracle.zig").Semantics(QM31);
const jalr_test_oracle =
    @import("../air/semantics/jalr_legacy_test_oracle.zig").Semantics(QM31);
const branch_eq_test_oracle =
    @import("../air/semantics/branch_eq_legacy_test_oracle.zig").Semantics(QM31);
const branch_lt_test_oracle =
    @import("../air/semantics/branch_lt_legacy_test_oracle.zig").Semantics(QM31);
const lt_imm_test_oracle =
    @import("../air/semantics/lt_imm_legacy_test_oracle.zig").Semantics(QM31);
const lt_reg_test_oracle =
    @import("../air/semantics/lt_reg_legacy_test_oracle.zig").Semantics(QM31);
const shifts_imm_test_oracle =
    @import("../air/semantics/shifts_imm_legacy_test_oracle.zig").Semantics(QM31);
const shifts_reg_test_oracle =
    @import("../air/semantics/shifts_reg_legacy_test_oracle.zig").Semantics(QM31);
const load_store_test_oracle =
    @import("../air/semantics/load_store_legacy_test_oracle.zig").Semantics(QM31);

test "trace groups opcode families" {
    try std.testing.expectEqual(OpcodeFamily.base_alu_reg, try proofOpcodeFamily(.ADD));
    try std.testing.expectEqual(OpcodeFamily.shifts_imm, try proofOpcodeFamily(.SRAI));
    try std.testing.expectEqual(OpcodeFamily.branch_lt, try proofOpcodeFamily(.BGEU));
    try std.testing.expectEqual(OpcodeFamily.load_store, try proofOpcodeFamily(.SW));
    try std.testing.expectEqual(OpcodeFamily.div, try proofOpcodeFamily(.REMU));
    try std.testing.expectEqual(OpcodeFamily.fence, try proofOpcodeFamily(.FENCE));
    try std.testing.expectError(error.UnsupportedForProof, proofOpcodeFamily(.ECALL));
    try std.testing.expectError(error.UnsupportedForProof, proofOpcodeFamily(.EBREAK));
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
    try std.testing.expectError(
        error.UnsupportedForProof,
        trace.proofOpcodes(std.testing.allocator),
    );
}

test "trace hands out filtered opcodes index-parallel to its rows" {
    const allocator = std.testing.allocator;
    var trace = Trace.init(allocator);
    defer trace.deinit();
    var add = testRow(.ADD);
    add.clk = 1;
    var store = testRow(.SW);
    store.clk = 2;
    var fence = testRow(.FENCE);
    fence.clk = 3;
    try trace.append(add);
    try trace.append(store);
    try trace.append(fence);

    const filtered = try trace.proofOpcodes(allocator);
    defer allocator.free(filtered);
    try std.testing.expectEqual(trace.rows.items.len, filtered.len);
    try std.testing.expectEqual(OpcodeFamily.base_alu_reg, opcodeFamily(filtered[0]));
    try std.testing.expectEqual(OpcodeFamily.load_store, opcodeFamily(filtered[1]));
    try std.testing.expectEqual(OpcodeFamily.fence, opcodeFamily(filtered[2]));
}

test "the total family map is reachable only through the filter" {
    // The structural half of the fix, and the half a revert cannot survive.
    //
    // This contract is covered by the focused trace-authority test root.
    //
    // The defect was not that `opcodeFamily` mishandled ECALL -- it was that
    // `opcodeFamily` *accepted* ECALL's type at all, so "the filter has already
    // run" was a claim in prose that one of four call sites did not honour.
    // Restoring the raw-`Opcode` signature restores exactly that hazard, and
    // fails here at compile time rather than in whichever caller is next to
    // forget.
    const total = @typeInfo(@TypeOf(opcodeFamily)).@"fn";
    try std.testing.expectEqual(@as(usize, 1), total.params.len);
    try std.testing.expectEqual(ProofOpcode, total.params[0].type.?);
    // Total: no error union, so no caller is invited to decide what to do with
    // an opcode that has no family. There is no such value of this type.
    try std.testing.expectEqual(OpcodeFamily, total.return_type.?);

    // And the only constructor from a raw opcode is fallible, so the type
    // cannot be entered without discharging the admission question.
    const filter = @typeInfo(@TypeOf(ProofOpcode.classify)).@"fn";
    try std.testing.expectEqual(Opcode, filter.params[0].type.?);
    const returns = @typeInfo(filter.return_type.?);
    try std.testing.expect(returns == .error_union);
    try std.testing.expectEqual(ProofOpcode, returns.error_union.payload);

    // The filtered type is a newtype over the proof opcode set, not over the
    // architectural one: a `ProofOpcode` written as a struct literal still
    // cannot name ECALL, because `opcode_manifest.Opcode` has no such tag.
    const fields = @typeInfo(ProofOpcode).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    try std.testing.expectEqual(opcode_manifest.Opcode, fields[0].type);
    for (std.enums.values(opcode_manifest.Opcode)) |id| {
        // Total on every inhabitant; this loop is the totality proof.
        _ = opcodeFamily(.{ .id = id });
    }
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
    var base_reg_columns = filledRow(base_alu_reg_test_oracle.N_ORACLE_COLUMNS, row, .base_alu_reg);
    const base_reg = try base_alu_reg_test_oracle.Row.fromOracleColumns(&base_reg_columns);
    try std.testing.expect(base_alu_reg_test_oracle.evaluate(base_reg).allZero());

    row = testRow(.ADDI);
    row.imm = -1;
    row.rs1_val = 1;
    row.rd_val = 0;
    var base_imm_columns = filledRow(base_alu_imm_test_oracle.N_ORACLE_COLUMNS, row, .base_alu_imm);
    const base_imm = try base_alu_imm_test_oracle.Row.fromOracleColumns(&base_imm_columns);
    try std.testing.expect(base_alu_imm_test_oracle.evaluate(base_imm).allZero());

    row = testRow(.SLL);
    row.rs1_val = 1;
    row.rs2_val = 1;
    row.rd_val = 2;
    var shift_reg_columns = filledRow(shifts_reg_test_oracle.N_ORACLE_COLUMNS, row, .shifts_reg);
    const shift_reg = try shifts_reg_test_oracle.Row.fromOracleColumns(&shift_reg_columns);
    try std.testing.expect(shifts_reg_test_oracle.evaluate(shift_reg).allZero());

    row = testRow(.SRAI);
    row.imm = 1;
    row.rs1_val = 0x80000000;
    row.rd_val = 0xc0000000;
    var shift_imm_columns = filledRow(shifts_imm_test_oracle.N_ORACLE_COLUMNS, row, .shifts_imm);
    const shift_imm = try shifts_imm_test_oracle.Row.fromOracleColumns(&shift_imm_columns);
    try std.testing.expect(shifts_imm_test_oracle.evaluate(shift_imm).allZero());
}

test "witness rows satisfy comparison and branch semantic evaluators" {
    var row = testRow(.SLTU);
    row.rs1_val = 1;
    row.rs2_val = 2;
    row.rd_val = 1;
    var lt_reg_columns = filledRow(lt_reg_test_oracle.N_ORACLE_COLUMNS, row, .lt_reg);
    const lt_reg = try lt_reg_test_oracle.Row.fromOracleColumns(&lt_reg_columns);
    try std.testing.expect(lt_reg_test_oracle.evaluate(lt_reg).allZero());

    row = testRow(.SLTI);
    row.imm = 2;
    row.rs1_val = 1;
    row.rd_val = 1;
    var lt_imm_columns = filledRow(lt_imm_test_oracle.N_ORACLE_COLUMNS, row, .lt_imm);
    const lt_imm = try lt_imm_test_oracle.Row.fromOracleColumns(&lt_imm_columns);
    try std.testing.expect(lt_imm_test_oracle.evaluate(lt_imm).allZero());

    row = testRow(.BEQ);
    row.rs1_val = 7;
    row.rs2_val = 7;
    row.imm = 8;
    row.next_pc = 108;
    row.branch_taken = true;
    var branch_eq_columns = filledRow(branch_eq_test_oracle.N_MAIN_COLUMNS, row, .branch_eq);
    const branch_eq = try branch_eq_test_oracle.Row.fromMainColumns(&branch_eq_columns);
    try std.testing.expect(branch_eq_test_oracle.evaluate(branch_eq).allZero());

    row = testRow(.BLTU);
    row.rs1_val = 1;
    row.rs2_val = 2;
    row.imm = 8;
    row.next_pc = 108;
    row.branch_taken = true;
    var branch_lt_columns = filledRow(branch_lt_test_oracle.N_MAIN_COLUMNS, row, .branch_lt);
    const branch_lt = try branch_lt_test_oracle.Row.fromMainColumns(&branch_lt_columns);
    try std.testing.expect(branch_lt_test_oracle.evaluate(branch_lt).allZero());
}

test "witness rows satisfy upper jump and memory semantic evaluators" {
    const legacy_lui = @import("../air/semantics/lui_legacy_test_oracle.zig")
        .Semantics(QM31);
    const legacy_auipc = @import("../air/semantics/auipc_legacy_test_oracle.zig")
        .Semantics(QM31);
    var row = testRow(.LUI);
    row.imm = @bitCast(@as(u32, 0x12345000));
    row.rd_val = 0x12345000;
    var lui_columns = filledRow(legacy_lui.N_MAIN_COLUMNS, row, .lui);
    const lui = try legacy_lui.Row.fromMainColumns(&lui_columns);
    try std.testing.expect(legacy_lui.evaluate(lui).allZero());

    row = testRow(.AUIPC);
    // U-type immediates are 4096-aligned; the decoder can never emit 20.
    // The AIR now pins imm_limbs[0] == 0 (anti-aliasing), so the fixture must
    // use an architecturally reachable immediate.
    row.imm = @bitCast(@as(u32, 0x5000));
    row.rd_val = 100 + 0x5000;
    var auipc_columns = filledRow(legacy_auipc.N_MAIN_COLUMNS, row, .auipc);
    const auipc = try legacy_auipc.Row.fromMainColumns(&auipc_columns);
    try std.testing.expect(legacy_auipc.evaluate(auipc).allZero());

    row = testRow(.JAL);
    row.imm = 8;
    row.rd_val = 104;
    row.next_pc = 108;
    row.branch_taken = true;
    var jal_columns = filledRow(jal_test_oracle.N_MAIN_COLUMNS, row, .jal);
    const jal = try jal_test_oracle.Row.fromMainColumns(&jal_columns);
    try std.testing.expect(jal_test_oracle.evaluate(jal).allZero());

    row = testRow(.JALR);
    row.imm = 4;
    row.rs1_val = 101;
    row.rd_val = 104;
    row.next_pc = 104;
    var jalr_columns = filledRow(jalr_test_oracle.N_MAIN_COLUMNS, row, .jalr);
    const jalr = try jalr_test_oracle.Row.fromMainColumns(&jalr_columns);
    try std.testing.expect(jalr_test_oracle.evaluate(jalr).allZero());

    row = testRow(.LW);
    row.rd = 4;
    // I-type decode retains immediate[4:0] in `rs2`; the authority binds both
    // that metadata and every instruction bit to the committed program word.
    row.rs2 = 0;
    row.inst_word = 0x0001_2203; // LW x4, 0(x2)
    row.rs1_val = 100;
    row.rd_val = 0x04030201;
    row.mem_addr = 100;
    row.mem_val = row.rd_val;
    row.mem_prev_word = row.rd_val;
    row.mem_next_word = row.rd_val;
    row.is_load = true;
    var memory_columns = filledRow(load_store_test_oracle.N_ORACLE_COLUMNS, row, .load_store);
    const memory = try load_store_test_oracle.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(load_store_test_oracle.evaluate(memory).allZero());

    row = testRow(.LB);
    row.rd = 4;
    row.rs2 = 0;
    row.inst_word = 0x0001_0203; // LB x4, 0(x2)
    row.rs1_val = 101;
    row.rd_val = 0xffffff80;
    row.mem_addr = 101;
    row.mem_val = 0x80;
    row.mem_prev_word = 0x00008000;
    row.mem_next_word = 0x00008000;
    row.is_load = true;
    memory_columns = filledRow(load_store_test_oracle.N_ORACLE_COLUMNS, row, .load_store);
    const byte_load = try load_store_test_oracle.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(load_store_test_oracle.evaluate(byte_load).allZero());

    row = testRow(.SH);
    // S-type decode retains immediate[4:0] in `rd`.
    row.rd = 0;
    row.inst_word = 0x0031_1023; // SH x3, 0(x2)
    row.rs1_val = 102;
    row.rs2_val = 0xbeef;
    row.mem_addr = 102;
    row.mem_val = 0xbeef;
    row.mem_prev_word = 0;
    row.mem_next_word = 0xbeef0000;
    row.is_store = true;
    memory_columns = filledRow(load_store_test_oracle.N_ORACLE_COLUMNS, row, .load_store);
    const half_store = try load_store_test_oracle.Row.fromOracleColumns(&memory_columns);
    try std.testing.expect(load_store_test_oracle.evaluate(half_store).allZero());
}

test "padding rows remain inactive for flag and explicit-enabler families" {
    const zero = [_]QM31{QM31.zero()} ** base_alu_reg_test_oracle.N_ORACLE_COLUMNS;
    const base = try base_alu_reg_test_oracle.Row.fromOracleColumns(&zero);
    try std.testing.expect(base.active().isZero());
    try std.testing.expect(base_alu_reg_test_oracle.evaluate(base).allZero());

    const control_zero = [_]QM31{QM31.zero()} ** jal_test_oracle.N_MAIN_COLUMNS;
    const control = try jal_test_oracle.Row.fromMainColumns(&control_zero);
    try std.testing.expect(control.enabler.isZero());
    try std.testing.expect(jal_test_oracle.evaluate(control).allZero());
}
