//! One concrete classification used by fixed preprocessing and witness recipes.
const O = @import("../decode.zig").Opcode;
const L = @import("layout.zig");
pub fn add(op: O) bool {
    return switch (op) {
        .ADD, .ADDI, .ADDW, .ADDIW => true,
        else => false,
    };
}
pub fn sub(op: O) bool {
    return op == .SUB or op == .SUBW;
}
pub fn word(op: O) bool {
    return switch (op) {
        .ADDW, .SUBW, .ADDIW, .SLLW, .SRLW, .SRAW, .SLLIW, .SRLIW, .SRAIW, .MULW, .DIVW, .DIVUW, .REMW, .REMUW => true,
        else => false,
    };
}
pub fn shift(op: O) bool {
    return switch (op) {
        .SLL, .SRL, .SRA, .SLLI, .SRLI, .SRAI, .SLLW, .SRLW, .SRAW, .SLLIW, .SRLIW, .SRAIW => true,
        else => false,
    };
}
pub fn left(op: O) bool {
    return switch (op) {
        .SLL, .SLLI, .SLLW, .SLLIW => true,
        else => false,
    };
}
pub fn arithmeticRight(op: O) bool {
    return switch (op) {
        .SRA, .SRAI, .SRAW, .SRAIW => true,
        else => false,
    };
}
pub fn compare(op: O) bool {
    return switch (op) {
        .SLT, .SLTU, .SLTI, .SLTIU, .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU => true,
        else => false,
    };
}
pub fn branch(op: O) bool {
    return switch (op) {
        .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU => true,
        else => false,
    };
}
pub fn mul(op: O) bool {
    return switch (op) {
        .MUL, .MULH, .MULHSU, .MULHU, .MULW => true,
        else => false,
    };
}
pub fn div(op: O) bool {
    return switch (op) {
        .DIV, .DIVU, .REM, .REMU, .DIVW, .DIVUW, .REMW, .REMUW => true,
        else => false,
    };
}
pub fn signedDiv(op: O) bool {
    return switch (op) {
        .DIV, .REM, .DIVW, .REMW => true,
        else => false,
    };
}
pub fn remainder(op: O) bool {
    return switch (op) {
        .REM, .REMU, .REMW, .REMUW => true,
        else => false,
    };
}
pub fn load(op: O) bool {
    return switch (op) {
        .LB, .LBU, .LH, .LHU, .LW, .LWU, .LD => true,
        else => false,
    };
}
pub fn store(op: O) bool {
    return switch (op) {
        .SB, .SH, .SW, .SD => true,
        else => false,
    };
}
pub fn address(op: O) bool {
    return load(op) or store(op) or op == .JALR;
}
pub fn immediate(op: O) bool {
    return switch (op) {
        .ADDI, .ADDIW, .SLTI, .SLTIU, .XORI, .ORI, .ANDI, .SLLI, .SRLI, .SRAI, .SLLIW, .SRLIW, .SRAIW => true,
        else => false,
    };
}
pub fn rhs(op: O) bool {
    return add(op) or sub(op) or shift(op) or compare(op) or switch (op) {
        .XOR, .XORI, .OR, .ORI, .AND, .ANDI => true,
        else => false,
    };
}
pub fn wordActive(which: L.Word, op: O, slots: [4]bool) bool {
    return switch (which) {
        .a => slots[0],
        .b => slots[1],
        .previous_rd => slots[2],
        .result => @import("../decode.zig").effects(op).writes_rd,
        .memory_before, .memory_after => slots[3],
        .address => address(op),
        .rhs => rhs(op),
        .difference => compare(op),
        .product_low, .product_high, .product_x, .product_y => mul(op) or div(op),
        .high_sub_a, .high_sub_b => mul(op),
        .abs_a, .abs_b, .quotient, .remainder, .remainder_gap, .raw_result, .out_abs => div(op),
    };
}
pub fn carryActive(kind: L.Carry, index: usize, op: O) bool {
    return switch (kind) {
        .alu => (add(op) or sub(op)) and (!word(op) or index < 4),
        .compare => compare(op),
        .address => address(op),
        .high_a, .high_b => mul(op),
        .abs_a, .abs_b, .negate, .remainder => div(op) and (!word(op) or index < 4),
        .div_sum_low, .div_sum_high => div(op),
    };
}
