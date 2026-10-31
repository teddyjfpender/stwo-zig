//! Immutable decode/effect authority; operation normalization computes no ISA result.
const isa = @import("../../decode.zig");
const execution = @import("../../execution_profile.zig");
const Old = @import("../word16_v1/operations.zig");
const M = @import("stwo_core").fields.m31.M31;
const L = @import("layout.zig");
pub const PROFILE = execution.Profile.ethereum_services_v2;
pub const JALR = 10;
pub const Entry = struct {
    raw: u32,
    pc: u64,
    instruction: isa.Instruction,
    valid: bool = false,
    operation: u8 = 0,
    ids: [3]u5 = @splat(0),
    immediate: u64 = 0,
    use_immediate: bool = false,
    branch: bool = false,
    use_pc: bool = false,
    dynamic_next: bool = false,
    function: bool = true,
    pub fn fromDecoded(raw: u32, pc: u64) Entry {
        const instruction = execution.decode(PROFILE, raw) catch return .{ .raw = raw, .pc = pc, .instruction = .{ .opcode = .FENCE, .rd = 0, .rs1 = 0, .rs2 = 0 } };
        return fromInstruction(raw, pc, instruction);
    }
    /// Existing independently decoded immutable metadata may be reused. Caller
    /// must supply the instruction belonging to raw under PROFILE; this is not
    /// a receiver admission API for arbitrary producer-supplied decode records.
    pub fn fromInstruction(raw: u32, pc: u64, decoded: isa.Instruction) Entry {
        var instruction = decoded;
        if (instruction.opcode == .ECALL) {
            instruction.rs1 = execution.POINTER_REGISTER;
            instruction.rs2 = execution.TAG_REGISTER;
        }
        var self = Entry{ .raw = raw, .pc = pc, .instruction = instruction };
        if (pc & 3 != 0 or !execution.admitted(PROFILE, instruction.opcode)) return self;
        self.valid = true;
        const effects = execution.effects(PROFILE, instruction.opcode);
        self.ids = .{ if (effects.reads_rs1) instruction.rs1 else 0, if (effects.reads_rs2) instruction.rs2 else 0, if (effects.writes_rd) instruction.rd else 0 };
        if (Old.classify(instruction.opcode)) |operation| {
            self.operation = operation.busId();
            self.use_immediate = operation.use_immediate;
            self.branch = operation.branch_predicate;
            if (self.use_immediate) self.immediate = @bitCast(instruction.imm);
            return self;
        }
        switch (instruction.opcode) {
            .LUI => {
                self.operation = 0;
                self.use_immediate = true;
                self.immediate = @bitCast(instruction.imm);
            },
            .AUIPC => {
                self.operation = 0;
                self.use_pc = true;
                self.use_immediate = true;
                self.immediate = @bitCast(instruction.imm);
            },
            .JAL => {
                self.operation = 0;
                self.use_pc = true;
                self.use_immediate = true;
                self.immediate = 4;
                if (self.staticNext(false) & 3 != 0) self.valid = false;
            },
            .JALR => {
                self.operation = if (instruction.imm == 0) 16 else JALR;
                self.use_immediate = true;
                self.dynamic_next = true;
                self.immediate = if (instruction.imm == 0) ~@as(u64, 1) else @bitCast(instruction.imm);
            },
            .FENCE => self.operation = 0,
            .LB, .LH, .LW, .LD, .LBU, .LHU, .LWU, .SB, .SH, .SW, .SD => {
                self.function = false;
                self.operation = @intFromEnum(instruction.opcode);
                self.immediate = @bitCast(instruction.imm);
            },
            .ECALL => {
                self.function = false;
                self.operation = @intFromEnum(instruction.opcode);
            },
            // Reuse the exact legacy arithmetic opcode coordinate: the old
            // byte bus projects affinely to these full-u16 FUNCTION tuples.
            .MUL,
            .MULH,
            .MULHSU,
            .MULHU,
            .MULW,
            .DIV,
            .DIVU,
            .REM,
            .REMU,
            .DIVW,
            .DIVUW,
            .REMW,
            .REMUW,
            => self.operation = @intFromEnum(instruction.opcode),
            // Already handled by the shared pure operation authority above.
            .ADD, .SUB, .SLL, .SLT, .SLTU, .XOR, .SRL, .SRA, .OR, .AND, .ADDI, .SLTI, .SLTIU, .XORI, .ORI, .ANDI, .SLLI, .SRLI, .SRAI, .ADDW, .SUBW, .SLLW, .SRLW, .SRAW, .ADDIW, .SLLIW, .SRLIW, .SRAIW, .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU => unreachable,
            .EBREAK => unreachable,
        }
        return self;
    }
    pub fn staticNext(self: Entry, taken: bool) u64 {
        return if (self.instruction.opcode == .JAL or (self.branch and taken)) self.pc +% @as(u64, @bitCast(self.instruction.imm)) else self.pc +% 4;
    }
    pub fn hasTakenEdge(self: Entry) bool {
        return self.valid and self.branch and self.staticNext(true) & 3 == 0;
    }
    /// Invalid entries have valid=0; they remain identity-bound in the program
    /// owner but cannot authenticate an active query. Taken edges are explicit.
    pub fn romTuple(self: Entry, taken: bool) [L.rom.COUNT]M {
        var out: [L.rom.COUNT]M = @splat(M.zero());
        if (!self.valid or (taken and !self.hasTakenEdge())) return out;
        out[0] = M.one();
        put(&out, L.rom.pc, self.pc);
        if (!self.dynamic_next) put(&out, L.rom.next_pc, self.staticNext(taken));
        out[L.rom.operation] = M.fromCanonical(self.operation);
        for (self.ids, 0..) |id, i| {
            out[L.rom.registers + i] = M.fromCanonical(id);
            out[L.rom.zero + i] = M.fromCanonical(@intFromBool(id == 0));
        }
        put(&out, L.rom.immediate, self.immediate);
        for ([_]bool{ self.use_immediate, self.branch, self.use_pc, self.dynamic_next, self.function }, 0..) |flag, i| out[L.rom.flags + i] = M.fromCanonical(@intFromBool(flag));
        if (self.dynamic_next) put(&out, L.rom.link, self.pc +% 4);
        out[L.rom.taken] = M.fromCanonical(@intFromBool(taken));
        return out;
    }
};
pub fn put(out: []M, at: usize, value: u64) void {
    for (0..4) |i| out[at + i] = M.fromCanonical(@as(u16, @truncate(value >> @as(u6, @intCast(16 * i)))));
}

/// Immutable schema/opcode-map fingerprint, separately bound from program bytes.
pub fn identity() [32]u8 {
    const std = @import("std");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.word16-execution.full64.v1:main53/inter40/D3;FUNCTION13:old-ALU0..9,JALR10-nonzero-I,JALR0-AND16,BIN16..18,SHIFT32..37,raw-MUL-DIV49..61;OWNER19:raw-LS28..38,ECALL63;epoch16/tick24;normalized-static-RHS;ROM30-link-and-taken");
    for (std.enums.values(isa.Opcode)) |op| for ([_]i64{ 0, -16 }) |immediate| {
        const entry = Entry.fromInstruction(0, 0, .{ .opcode = op, .rs1 = 1, .rs2 = 2, .rd = 3, .imm = immediate });
        const fields = [_]u8{ @intFromEnum(op), @intFromBool(entry.valid), entry.operation, entry.ids[0], entry.ids[1], entry.ids[2], @intFromBool(entry.use_immediate), @intFromBool(entry.branch), @intFromBool(entry.use_pc), @intFromBool(entry.dynamic_next), @intFromBool(entry.function) };
        hash.update(&fields);
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, entry.immediate, .little);
        hash.update(&bytes);
    };
    return hash.finalResult();
}
