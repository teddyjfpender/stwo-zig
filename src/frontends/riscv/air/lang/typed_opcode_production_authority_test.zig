//! Source-level retirement receipts for production typed witness cutovers.
//!
//! Row/proof differentials establish value equivalence. These guards establish
//! singular authority: production dispatch cannot silently return to a retired
//! handwritten writer while the typed tests continue to pass in isolation.

const std = @import("std");

const trace_source = @embedFile("../../runner/trace.zig");
const generated_retirement_source = @embedFile("../../runner/generated_retirement.zig");
const execute_source = @embedFile("../../runner/execute.zig");
const constraint_program_source =
    @embedFile("../constraint_program.zig") ++
    @embedFile("../constraint_program_constructors.zig");
const semantics_registry_source = @embedFile("../semantics/mod.zig");

test "typed AUIPC execution and AIR are singular production authorities" {
    try expectContains(
        generated_retirement_source,
        ".auipc => try auipc.retireAtomic",
    );
    try expectContains(
        execute_source,
        ".AUIPC => return error.GeneratedRetirementRequired",
    );
    try expectAbsent(execute_source, ".AUIPC => cpu.writeReg");
    try expectContains(
        constraint_program_source,
        ".auipc => constructAuipc(section, columns, is_active)",
    );
    try expectContains(
        constraint_program_source,
        "try typed_auipc_eval.lookupsInto(columns, result)",
    );
    try expectAbsent(semantics_registry_source, "pub const auipc =");
}

test "typed BASE_ALU_IMM execution and AIR are singular production authorities" {
    try expectContains(
        generated_retirement_source,
        ".addi, .xori, .ori, .andi => try base_alu_imm.retireAtomic",
    );
    try expectContains(
        execute_source,
        ".ADDI, .XORI, .ORI, .ANDI => return error.GeneratedRetirementRequired",
    );
    try expectAbsent(execute_source, ".ADDI => cpu.writeReg");
    try expectContains(
        constraint_program_source,
        ".base_alu_imm => constructBaseAluImm(section, columns, is_active)",
    );
    try expectContains(
        constraint_program_source,
        "try typed_base_alu_imm_eval.lookupsInto(columns, result)",
    );
}

test "typed BASE_ALU_REG execution witness and AIR are singular production authorities" {
    try expectContains(
        generated_retirement_source,
        ".add, .sub, .xor, .or_reg, .and_reg => try base_alu_reg.retireAtomic",
    );
    try expectContains(
        execute_source,
        ".ADD, .SUB, .XOR, .OR, .AND => return error.GeneratedRetirementRequired",
    );
    try expectAbsent(execute_source, ".ADD => cpu.writeReg");
    try expectContains(
        trace_source,
        ".base_alu_reg => BASE_ALU_REG_AUTHORITY.writeActiveRow",
    );
    try expectAbsent(
        trace_source,
        ".base_alu_reg => typed_base_alu_reg_witness.writeActiveRow",
    );
    try expectContains(
        constraint_program_source,
        ".base_alu_reg => constructBaseAluReg(section, columns, is_active)",
    );
    try expectContains(
        constraint_program_source,
        "try typed_base_alu_reg_eval.lookupsInto(columns, result)",
    );
    try expectAbsent(semantics_registry_source, "pub const base_alu_reg =");
}

test "typed JAL execution witness and AIR are singular production authorities" {
    try expectContains(
        generated_retirement_source,
        ".jal => try jal.retireAtomic",
    );
    try expectContains(
        execute_source,
        ".JAL => return error.GeneratedRetirementRequired",
    );
    try expectAbsent(execute_source, ".JAL => {");
    try expectContains(
        trace_source,
        ".jal => JAL_AUTHORITY.writeActiveRow",
    );
    try expectAbsent(
        trace_source,
        ".jal => typed_jal_witness.writeActiveRow",
    );
    try expectContains(
        constraint_program_source,
        ".jal => constructJal(section, columns, is_active)",
    );
    try expectContains(
        constraint_program_source,
        "try typed_jal_eval.lookupsInto(columns, result)",
    );
    try expectAbsent(semantics_registry_source, "pub const jal =");
}

test "typed JALR execution witness and AIR are singular production authorities" {
    try expectContains(
        generated_retirement_source,
        ".jalr => try jalr.retireAtomic",
    );
    try expectContains(
        execute_source,
        ".JALR => return error.GeneratedRetirementRequired",
    );
    try expectAbsent(execute_source, ".JALR => {");
    try expectContains(
        trace_source,
        ".jalr => JALR_AUTHORITY.writeActiveRow",
    );
    try expectAbsent(
        trace_source,
        ".jalr => typed_jalr_witness.writeActiveRow",
    );
    try expectContains(
        constraint_program_source,
        ".jalr => constructJalr(section, columns, is_active)",
    );
    try expectContains(
        constraint_program_source,
        "try typed_jalr_eval.lookupsInto(columns, result)",
    );
    try expectAbsent(semantics_registry_source, "pub const jalr =");
}

test "typed LT_IMM execution witness and AIR are singular production authorities" {
    try expectContains(
        generated_retirement_source,
        ".slti, .sltiu => try lt_imm.retireAtomic",
    );
    try expectContains(
        execute_source,
        ".SLTI, .SLTIU => return error.GeneratedRetirementRequired",
    );
    try expectAbsent(execute_source, ".SLTI => {");
    try expectAbsent(execute_source, ".SLTIU => {");
    try expectContains(
        trace_source,
        ".lt_imm => LT_IMM_AUTHORITY.writeActiveRow",
    );
    try expectAbsent(
        trace_source,
        ".lt_imm => typed_lt_imm_witness.writeActiveRow",
    );
    try expectAbsent(trace_source, ".lt_imm => compare_witness.immediate");
    try expectContains(
        constraint_program_source,
        ".lt_imm => constructLtImm(section, columns, is_active)",
    );
    try expectContains(
        constraint_program_source,
        "try typed_lt_imm_eval.lookupsInto(columns, result)",
    );
    try expectAbsent(semantics_registry_source, "pub const lt_imm =");
}

test "typed SHIFTS_IMM execution witness and AIR are singular production authorities" {
    try expectContains(generated_retirement_source, ".slli, .srli, .srai => try shifts_imm.retireAtomic");
    try expectContains(execute_source, ".SLLI, .SRLI, .SRAI => return error.GeneratedRetirementRequired");
    try expectContains(
        trace_source,
        ".shifts_imm => SHIFTS_IMM_AUTHORITY.writeActiveRow",
    );
    try expectContains(constraint_program_source, ".shifts_imm => constructTyped(typed_shifts_imm_eval, section, columns, is_active)");
    try expectAbsent(semantics_registry_source, "pub const shifts_imm =");
}

test "typed MUL execution witness and AIR are singular production authorities" {
    try expectContains(generated_retirement_source, ".mul => try mul.retireAtomic");
    try expectContains(trace_source, ".mul => MUL_AUTHORITY.writeActiveRow");
    try expectContains(constraint_program_source, ".mul => constructTyped(typed_mul_eval, section, columns, is_active)");
    try expectAbsent(semantics_registry_source, "pub const mul =");
}

test "typed MULH execution witness and AIR are singular production authorities" {
    try expectContains(generated_retirement_source, ".mulh, .mulhsu, .mulhu => try mulh.retireAtomic");
    try expectContains(trace_source, ".mulh => MULH_AUTHORITY.writeActiveRow");
    try expectContains(constraint_program_source, ".mulh => constructTyped(typed_mulh_eval, section, columns, is_active)");
    try expectAbsent(semantics_registry_source, "pub const mulh =");
}

test "typed LT_REG execution witness and AIR are singular production authorities" {
    try expectContains(generated_retirement_source, ".slt, .sltu => try lt_reg.retireAtomic");
    try expectContains(execute_source, ".SLL, .SRL, .SRA, .SLT, .SLTU => return error.GeneratedRetirementRequired");
    try expectContains(trace_source, ".lt_reg => LT_REG_AUTHORITY.writeActiveRow");
    try expectContains(constraint_program_source, ".lt_reg => constructTyped(typed_lt_reg_eval, section, columns, is_active)");
    try expectAbsent(semantics_registry_source, "pub const lt_reg =");
}

test "typed BRANCH_EQ execution witness and AIR are singular production authorities" {
    try expectContains(
        generated_retirement_source,
        ".beq, .bne => try branch_eq.retireAtomic",
    );
    try expectContains(
        execute_source,
        ".BEQ, .BNE => return error.GeneratedRetirementRequired",
    );
    try expectAbsent(execute_source, ".BEQ => {");
    try expectAbsent(execute_source, ".BNE => {");
    try expectContains(
        trace_source,
        ".branch_eq => BRANCH_EQ_AUTHORITY.writeActiveRow",
    );
    try expectAbsent(
        trace_source,
        ".branch_eq => typed_branch_eq_witness.writeActiveRow",
    );
    try expectAbsent(trace_source, ".branch_eq => compare_witness.branchEqual");
    try expectContains(
        constraint_program_source,
        ".branch_eq => constructBranchEq(section, columns, is_active)",
    );
    try expectContains(
        constraint_program_source,
        "try typed_branch_eq_eval.lookupsInto(columns, result)",
    );
    try expectAbsent(semantics_registry_source, "pub const branch_eq =");
}

test "typed BRANCH_LT execution witness and AIR are singular production authorities" {
    try expectContains(
        generated_retirement_source,
        ".blt, .bltu, .bge, .bgeu => try branch_lt.retireAtomic",
    );
    try expectContains(
        execute_source,
        ".BLT, .BLTU, .BGE, .BGEU => return error.GeneratedRetirementRequired",
    );
    try expectAbsent(execute_source, ".BLT => {");
    try expectAbsent(execute_source, ".BLTU => {");
    try expectAbsent(execute_source, ".BGE => {");
    try expectAbsent(execute_source, ".BGEU => {");
    try expectContains(
        trace_source,
        ".branch_lt => BRANCH_LT_AUTHORITY.writeActiveRow",
    );
    try expectAbsent(
        trace_source,
        ".branch_lt => typed_branch_lt_witness.writeActiveRow",
    );
    try expectAbsent(trace_source, ".branch_lt => compare_witness.branchLess");
    try expectContains(
        constraint_program_source,
        ".branch_lt => constructBranchLt(section, columns, is_active)",
    );
    try expectContains(
        constraint_program_source,
        "try typed_branch_lt_eval.lookupsInto(columns, result)",
    );
    try expectAbsent(semantics_registry_source, "pub const branch_lt =");
}

test "typed SHIFTS_REG execution witness and AIR are singular production authorities" {
    try expectContains(generated_retirement_source, ".sll, .srl, .sra => try shifts_reg.retireAtomic");
    try expectContains(
        trace_source,
        ".shifts_reg => SHIFTS_REG_AUTHORITY.writeActiveRow",
    );
    try expectContains(constraint_program_source, ".shifts_reg => constructTyped(typed_shifts_reg_eval, section, columns, is_active)");
    try expectAbsent(semantics_registry_source, "pub const shifts_reg =");
}

test "typed DIV execution witness and AIR are singular production authorities" {
    try expectContains(generated_retirement_source, ".div, .divu, .rem, .remu => try div.retireAtomic");
    try expectContains(trace_source, ".div => DIV_AUTHORITY.writeActiveRow");
    try expectContains(constraint_program_source, ".div => constructTyped(typed_div_eval, section, columns, is_active)");
    try expectAbsent(semantics_registry_source, "pub const div =");
}

test "typed LOAD_STORE execution witness and AIR are singular production authorities" {
    try expectContains(generated_retirement_source, ".lb, .lh, .lbu, .lhu, .lw, .sb, .sh, .sw => try load_store.retireAtomic");
    try expectContains(trace_source, ".load_store => LOAD_STORE_AUTHORITY.writeActiveRow");
    try expectContains(constraint_program_source, ".load_store => constructTyped(typed_load_store_eval, section, columns, is_active)");
    try expectAbsent(semantics_registry_source, "pub const load_store =");
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
}

fn expectAbsent(haystack: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, haystack, needle) == null);
}
