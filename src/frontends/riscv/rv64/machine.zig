//! RV64IM instruction retirement, with fail-atomic architectural state.
const std = @import("std");
const isa = @import("decode.zig");
const mem = @import("memory.zig");
const Word = @import("word.zig").Word;
pub const Error = isa.Error || mem.Error || error{ EnvironmentCall, Breakpoint, StepLimit };
pub const MemoryEffect = @import("retirement.zig").MemoryEffect;
pub const Retirement = @import("retirement.zig").Retirement;
const Cache = @import("decode_cache.zig").Cache;

pub const Cpu = struct {
    regs: [32]u64 = @splat(0),
    pc: u64,
    retired: u64 = 0,

    pub fn init(entry: u64, stack: u64) Cpu {
        var result = Cpu{ .pc = entry };
        result.regs[2] = stack;
        return result;
    }

    pub fn read(self: *const Cpu, index: u5) u64 {
        return if (index == 0) 0 else self.regs[index];
    }

    /// Fetch, decode, execute and retire one instruction. Environment calls
    /// are surfaced as traps; there is no implicit SP1 syscall dispatch.
    pub fn step(self: *Cpu, memory: *mem.Memory) Error!Retirement {
        if (self.retired == std.math.maxInt(u64)) return error.StepLimit;
        const word = try memory.fetch(self.pc);
        return self.retire(memory, word, try isa.Instruction.decode(word));
    }

    pub fn stepCached(self: *Cpu, memory: *mem.Memory, cache: *Cache) Error!Retirement {
        if (self.retired == std.math.maxInt(u64)) return error.StepLimit;
        const word = try memory.fetch(self.pc);
        return self.retire(memory, word, try cache.decode(word));
    }

    fn retire(self: *Cpu, memory: *mem.Memory, word: u32, inst: isa.Instruction) Error!Retirement {
        const effects = isa.effects(inst.opcode);
        const a = if (effects.reads_rs1) self.read(inst.rs1) else 0;
        const b = if (effects.reads_rs2) self.read(inst.rs2) else 0;
        const sa: i64 = @bitCast(a);
        const sb: i64 = @bitCast(b);
        const imm: u64 = @bitCast(inst.imm);
        const aw: u32 = @truncate(a);
        const bw: u32 = @truncate(b);
        const shift: u6 = @truncate(b);
        const shiftw: u5 = @truncate(b);
        const shifti: u6 = @intCast(imm & 63);
        const shiftiw: u5 = @intCast(imm & 31);
        var next_pc = self.pc +% 4;
        var result: u64 = 0;
        const writes = effects.writes_rd;
        var effect: ?MemoryEffect = null;
        var taken = false;
        switch (inst.opcode) {
            .ADD => result = a +% b,
            .SUB => result = a -% b,
            .ADDI => result = a +% imm,
            .SLT => result = @intFromBool(sa < sb),
            .SLTU => result = @intFromBool(a < b),
            .SLTI => result = @intFromBool(sa < inst.imm),
            .SLTIU => result = @intFromBool(a < imm),
            .AND => result = a & b,
            .OR => result = a | b,
            .XOR => result = a ^ b,
            .ANDI => result = a & imm,
            .ORI => result = a | imm,
            .XORI => result = a ^ imm,
            .SLL => result = a << shift,
            .SRL => result = a >> shift,
            .SRA => result = @bitCast(sa >> shift),
            .SLLI => result = a << shifti,
            .SRLI => result = a >> shifti,
            .SRAI => result = @bitCast(sa >> shifti),
            .ADDW => result = sext32(aw +% bw),
            .SUBW => result = sext32(aw -% bw),
            .ADDIW => result = sext32(aw +% @as(u32, @truncate(imm))),
            .SLLW => result = sext32(aw << shiftw),
            .SRLW => result = sext32(aw >> shiftw),
            .SRAW => result = sext32(@bitCast(@as(i32, @bitCast(aw)) >> shiftw)),
            .SLLIW => result = sext32(aw << shiftiw),
            .SRLIW => result = sext32(aw >> shiftiw),
            .SRAIW => result = sext32(@bitCast(@as(i32, @bitCast(aw)) >> shiftiw)),
            .LUI => result = imm,
            .AUIPC => result = self.pc +% imm,
            .MUL => result = a *% b,
            .MULHU => result = @intCast((@as(u128, a) * b) >> 64),
            .MULH => result = @truncate(@as(u128, @bitCast(@as(i128, sa) * sb)) >> 64),
            .MULHSU => result = @truncate(@as(u128, @bitCast(@as(i128, sa) * @as(i128, b))) >> 64),
            .MULW => result = sext32(aw *% bw),
            .DIV => result = divSigned64(sa, sb, false),
            .REM => result = divSigned64(sa, sb, true),
            .DIVU => result = if (b == 0) std.math.maxInt(u64) else a / b,
            .REMU => result = if (b == 0) a else a % b,
            .DIVW => result = sext32(divSigned32(@bitCast(aw), @bitCast(bw), false)),
            .REMW => result = sext32(divSigned32(@bitCast(aw), @bitCast(bw), true)),
            .DIVUW => result = sext32(if (bw == 0) std.math.maxInt(u32) else aw / bw),
            .REMUW => result = sext32(if (bw == 0) aw else aw % bw),
            .LB, .LH, .LW, .LD, .LBU, .LHU, .LWU => {
                const address = a +% imm;
                const width = effects.memory_width;
                const observed = try memory.loadObserved(address, width);
                const value = observed.value;
                result = switch (inst.opcode) {
                    .LB => @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(value)))))),
                    .LH => @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(value)))))),
                    .LW => sext32(@truncate(value)),
                    else => value,
                };
                effect = .{ .address = Word.fromInt(address), .width = width, .value = Word.fromInt(value), .before_word = Word.fromInt(observed.before_word), .after_word = Word.fromInt(observed.after_word), .write = false };
            },
            .SB, .SH, .SW, .SD => {
                const address = a +% imm;
                const width = effects.memory_width;
                const observed = try memory.storeObserved(address, width, b);
                effect = .{ .address = Word.fromInt(address), .width = width, .value = Word.fromInt(observed.value), .before_word = Word.fromInt(observed.before_word), .after_word = Word.fromInt(observed.after_word), .write = true };
            },
            .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU => {
                taken = switch (inst.opcode) {
                    .BEQ => a == b,
                    .BNE => a != b,
                    .BLT => sa < sb,
                    .BGE => sa >= sb,
                    .BLTU => a < b,
                    .BGEU => a >= b,
                    else => unreachable,
                };
                if (taken) next_pc = self.pc +% imm;
            },
            .JAL, .JALR => {
                result = next_pc;
                next_pc = if (inst.opcode == .JAL) self.pc +% imm else (a +% imm) & ~@as(u64, 1);
                taken = true;
            },
            .FENCE => {},
            .ECALL => return error.EnvironmentCall,
            .EBREAK => return error.Breakpoint,
        }
        // Untaken branches do not trap on their unused target. Stores cannot
        // reach this failure, so CPU and memory remain unchanged on a trap.
        if (taken and next_pc & 3 != 0) return error.MisalignedAddress;
        const retirement = Retirement{
            .clock = self.retired + 1,
            .immediate = Word.fromInt(imm),
            .previous_rd = Word.fromInt(if (writes) self.read(inst.rd) else 0),
            .branch_taken = taken,
            .pc = Word.fromInt(self.pc),
            .next_pc = Word.fromInt(next_pc),
            .instruction = word,
            .opcode = inst.opcode,
            .rs1 = if (effects.reads_rs1) inst.rs1 else 0,
            .rs2 = if (effects.reads_rs2) inst.rs2 else 0,
            .lhs = Word.fromInt(a),
            .rhs = Word.fromInt(b),
            .rd = if (writes) inst.rd else 0,
            .result = Word.fromInt(result),
            .writes_rd = writes and inst.rd != 0,
            .memory = effect,
        };
        if (retirement.writes_rd) self.regs[inst.rd] = result;
        self.regs[0] = 0;
        self.pc = next_pc;
        self.retired += 1;
        return retirement;
    }
};

pub fn sext32(value: u32) u64 {
    return @bitCast(@as(i64, @as(i32, @bitCast(value))));
}

fn divSigned64(a: i64, b: i64, remainder: bool) u64 {
    if (b == 0) return if (remainder) @bitCast(a) else std.math.maxInt(u64);
    if (a == std.math.minInt(i64) and b == -1) return if (remainder) 0 else @bitCast(a);
    return @bitCast(if (remainder) @rem(a, b) else @divTrunc(a, b));
}

fn divSigned32(a: i32, b: i32, remainder: bool) u32 {
    if (b == 0) return if (remainder) @bitCast(a) else std.math.maxInt(u32);
    if (a == std.math.minInt(i32) and b == -1) return if (remainder) 0 else @bitCast(a);
    return @bitCast(if (remainder) @rem(a, b) else @divTrunc(a, b));
}
