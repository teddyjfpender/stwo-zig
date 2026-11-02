//! Versioned operation authority for the experimental Word16 family bus.
//! Local selectors are family-local; busId maps them to disjoint function IDs.
const Opcode = @import("../../decode.zig").Opcode;
const std = @import("std");

pub const Family = enum(u8) { alu = 1, binary = 2, shift = 3 };
pub const Alu = enum(u8) { add = 0, sub = 1, addw = 2, subw = 3, slt = 4, sltu = 5, eq = 6, ne = 7, ge = 8, geu = 9 };
/// Canonical native request ABI shared by capture projection and ALU source.
pub const AluFact = struct { op: Alu, a: u64, b: u64, c: u64 };
pub const Binary = enum(u8) { and_ = 0, or_ = 1, xor = 2 };
pub const Shift = enum(u8) { sll = 0, srl = 1, sra = 2, sllw = 3, srlw = 4, sraw = 5 };
/// Canonical native request ABI shared by capture projection and SHIFT source.
pub const ShiftFact = struct { op: Shift, a: u64, b: u64, c: u64 };
pub const Operation = struct {
    family: Family,
    op_id: u8,
    use_immediate: bool = false,
    /// Predicate result C is [taken,0,0,0], never a fabricated RD write.
    branch_predicate: bool = false,
    pub fn busId(self: Operation) u8 {
        return busIdFor(self.family, self.op_id);
    }
};

/// Payload coordinate0 is GLOBAL, unlike the local selector ID. Manifest
/// roles never substitute for relation domain separation: add(0,0)=0 must
/// not authorize AND(0,0)=0 or a shift merely because local IDs coincide.
pub fn busIdFor(family: Family, local_id: u8) u8 {
    const limit: u8 = switch (family) {
        .alu => 10,
        .binary => 3,
        .shift => 6,
    };
    std.debug.assert(local_id < limit);
    return switch (family) {
        .alu => local_id,
        .binary => 16 + local_id,
        .shift => 32 + local_id,
    };
}

fn alu(op: Alu, immediate: bool, branch: bool) Operation {
    return .{ .family = .alu, .op_id = @intFromEnum(op), .use_immediate = immediate, .branch_predicate = branch };
}
fn binary(op: Binary, immediate: bool) Operation {
    return .{ .family = .binary, .op_id = @intFromEnum(op), .use_immediate = immediate };
}
fn shift(op: Shift, immediate: bool) Operation {
    return .{ .family = .shift, .op_id = @intFromEnum(op), .use_immediate = immediate };
}

/// Null requires a different proved authority. It never means "accept locally".
pub fn classify(op: Opcode) ?Operation {
    return switch (op) {
        .ADD => alu(.add, false, false),
        .ADDI => alu(.add, true, false),
        .SUB => alu(.sub, false, false),
        .ADDW => alu(.addw, false, false),
        .ADDIW => alu(.addw, true, false),
        .SUBW => alu(.subw, false, false),
        .SLT => alu(.slt, false, false),
        .SLTI => alu(.slt, true, false),
        .SLTU => alu(.sltu, false, false),
        .SLTIU => alu(.sltu, true, false),
        .BEQ => alu(.eq, false, true),
        .BNE => alu(.ne, false, true),
        .BLT => alu(.slt, false, true),
        .BGE => alu(.ge, false, true),
        .BLTU => alu(.sltu, false, true),
        .BGEU => alu(.geu, false, true),
        .AND => binary(.and_, false),
        .ANDI => binary(.and_, true),
        .OR => binary(.or_, false),
        .ORI => binary(.or_, true),
        .XOR => binary(.xor, false),
        .XORI => binary(.xor, true),
        .SLL => shift(.sll, false),
        .SLLI => shift(.sll, true),
        .SRL => shift(.srl, false),
        .SRLI => shift(.srl, true),
        .SRA => shift(.sra, false),
        .SRAI => shift(.sra, true),
        .SLLW => shift(.sllw, false),
        .SLLIW => shift(.sllw, true),
        .SRLW => shift(.srlw, false),
        .SRLIW => shift(.srlw, true),
        .SRAW => shift(.sraw, false),
        .SRAIW => shift(.sraw, true),
        else => null,
    };
}
