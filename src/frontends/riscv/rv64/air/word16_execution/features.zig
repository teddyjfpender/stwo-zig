//! Immutable decode/effect authority; operation normalization computes no ISA result.
const isa = @import("../../decode.zig");
const execution = @import("../../execution_profile.zig");
const Old = @import("../word16_v1/operations.zig");
const M = @import("stwo_core").fields.m31.M31;
const L = @import("layout.zig");
pub const PROFILE = execution.Profile.ethereum_services_v2;
pub const JALR = 10;
/// Compact decode code-address bound (see romTupleCompact / README).
pub const COMPACT_PC_LIMIT: u64 = 1 << 31;
/// ROM flag slots reused by compact decode for the LS offset limbs.
pub const COMPACT_LS_LOW = 0;
pub const COMPACT_LS_SIGN = 2;
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
    /// Compact decode: the value committed in B on an immediate row. AUIPC
    /// and JAL fold to the static constants pc+imm and pc+4 (ADD with A=0);
    /// every other immediate FUNCTION instruction keeps its normalized IMM.
    /// Zero when the instruction has no FUNCTION immediate (B is then rs2).
    pub fn compactB(self: Entry) u64 {
        if (!self.use_immediate) return 0;
        return if (self.use_pc) self.pc +% self.immediate else self.immediate;
    }
    /// Compact decode: the LS offset as (low16, sign limb). A RISC-V LS offset
    /// is a 12-bit sign extension, so limbs 1..3 are equal and in {0, 0xFFFF}.
    /// FUNCTION and ECALL rows carry (0, 0).
    pub fn compactLs(self: Entry) ?[2]u16 {
        if (self.function or self.instruction.opcode == .ECALL) return if (self.function or self.immediate == 0) .{ 0, 0 } else null;
        const limbs = [4]u16{ @truncate(self.immediate), @truncate(self.immediate >> 16), @truncate(self.immediate >> 32), @truncate(self.immediate >> 48) };
        if (limbs[1] != limbs[2] or limbs[1] != limbs[3] or (limbs[1] != 0 and limbs[1] != 0xFFFF)) return null;
        return .{ limbs[0], limbs[1] };
    }
    /// Compact decode admission. Every ROM PC and static successor is below
    /// 2^31 (so felt(pc) is injective and canonical), an immediate never
    /// shares B with a read rs2, and the LS offset fits (low16, sign).
    pub fn compactValid(self: Entry) bool {
        if (!self.valid or self.pc >= COMPACT_PC_LIMIT) return false;
        if (!self.dynamic_next and self.staticNext(false) >= COMPACT_PC_LIMIT) return false;
        if (self.use_immediate and self.ids[1] != 0) return false;
        return self.compactLs() != null;
    }
    pub fn compactTakenEdge(self: Entry) bool {
        return self.compactValid() and self.hasTakenEdge() and self.staticNext(true) < COMPACT_PC_LIMIT;
    }
    /// ROM30 under compact decode. Same 30 coordinates and challenges as
    /// `romTuple`, with these meanings: pc and next are single field elements
    /// in limb 0 (limbs 1..3 zero; next is zero on dynamic rows); `immediate`
    /// is the B-slot immediate compactB (bound against (1-enabled1)*B); the
    /// use_immediate and use_pc flag slots carry the two LS-offset limbs.
    pub fn romTupleCompact(self: Entry, taken: bool) [L.rom.COUNT]M {
        var out: [L.rom.COUNT]M = @splat(M.zero());
        if (!self.compactValid() or (taken and !self.compactTakenEdge())) return out;
        const ls = self.compactLs().?;
        out[0] = M.one();
        out[L.rom.pc] = M.fromCanonical(@intCast(self.pc));
        if (!self.dynamic_next) out[L.rom.next_pc] = M.fromCanonical(@intCast(self.staticNext(taken)));
        out[L.rom.operation] = M.fromCanonical(self.operation);
        for (self.ids, 0..) |id, i| {
            out[L.rom.registers + i] = M.fromCanonical(id);
            out[L.rom.zero + i] = M.fromCanonical(@intFromBool(id == 0));
        }
        put(&out, L.rom.immediate, self.compactB());
        out[L.rom.flags + COMPACT_LS_LOW] = M.fromCanonical(ls[0]);
        out[L.rom.flags + 1] = M.fromCanonical(@intFromBool(self.branch));
        out[L.rom.flags + COMPACT_LS_SIGN] = M.fromCanonical(ls[1]);
        out[L.rom.flags + 3] = M.fromCanonical(@intFromBool(self.dynamic_next));
        out[L.rom.flags + 4] = M.fromCanonical(@intFromBool(self.function));
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
    hash.update("rv64.word16-execution.full64.v3:main47/inter40/D3;zero=1-enabled;previous-clock=tick-1-gap16-65536*gap8;FUNCTION13:old-ALU0..9,JALR10-nonzero-I,JALR0-AND16,BIN16..18,SHIFT32..37,raw-MUL-DIV49..61;OWNER19:raw-LS28..38,ECALL63;epoch16/tick24;normalized-static-RHS;ROM30-link-and-taken");
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

/// Separate domain for the opt-in byte-pair CPU interaction. Mixed ONLY when
/// Geometry.cpu_u8_pairs is set (always on top of the fused-tail identity).
pub fn pairIdentity() [32]u8 {
    const std = @import("std");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.word16-execution.full64.u8-pairs.v1:inter32/D3/residuals50;REG3=fraction(R*b*a=w*(a-b));FUNCTION=fraction(G*d=function);ROM=fraction(H*d=active);OWNER+U16=fraction(F*d0*d1=d0+w*d1);U16x2=fraction(K*d2*d3=d2+d3);U8PAIRS=AND-relation tagged (x,y,0,1): (g0,g1),(g2,0) fused((S-S'+claim*first-C7)*p0*p1-(p0+p1));AND-table=pair-inverse(I*d*p=1),term=(m*p+m_pair*d)*I");
    const base = fusedTailIdentity();
    hash.update(&base);
    return hash.finalResult();
}

/// Separate domain for the wide-clock CPU encoding. Mixed ONLY when the CPU
/// log exceeds layout.CLOCK24_MAX_LOG (always on top of the fused tail).
pub fn wideClockIdentity() [32]u8 {
    const std = @import("std");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.word16-execution.full64.wide-clock.v1:log23;fused-tail-only;REG-tick=4*row+slot+1<2^25;previous-clock=tick-1-gap16-65536*gap8;gap8-range=U16(128*gap8)=>gap=gap16+512*u<2^26;OWNER-tick=row+1(stride1)<2^24;RAM-side epoch16/tick24 unchanged");
    const base = fusedTailIdentity();
    hash.update(&base);
    return hash.finalResult();
}

/// Separate domain for the opt-in fused-tail CPU interaction. Mixed ONLY when
/// Geometry.cpu_fused_tail is set, so the historical transcript is unchanged.
pub fn fusedTailIdentity() [32]u8 {
    const std = @import("std");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.word16-execution.full64.fused-tail.v1:inter36/D3/residuals51;REG3=fraction(R*b*a=w*(a-b));OWNER+U16=fraction(F*d0*d1=d0+w*d1);FUNCTION,ROM,U16x2,U8x2=strict-inverse;U8-single=fused((S-S'+claim*first-C8)*d6-1)");
    const base = identity();
    hash.update(&base);
    return hash.finalResult();
}

/// Separate domain for the opt-in compact decode CPU MAIN. Mixed ONLY when
/// Geometry.cpu_compact_decode is set (always on top of the pair identity).
pub fn compactIdentity() [32]u8 {
    const std = @import("std");
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("rv64.word16-execution.full64.compact-decode.v1:main37/D3;pc=first*initial+(1-first)*(next0'+65536*next1');ROM.pc,next=felt(limb0),limbs1..3=0;pc,next<2^31;B=imm-slot(ROM.imm=(1-enabled1)*B),AUIPC=ADD(0,pc+imm),JAL=ADD(0,pc+4);ls_imm=(low16,sign)@ROM.flags0,2;OWNER.IMM=(l0,s,s,s);FUNCTION.C(dyn)=(next0,next1,0,0);padding=(1-active)*(felt(next)-felt(next'));last*(felt(next)-felt(final))");
    for (std.enums.values(isa.Opcode)) |op| for ([_]i64{ 0, -16 }) |immediate| {
        const entry = Entry.fromInstruction(0, 0x1000, .{ .opcode = op, .rs1 = 1, .rs2 = 2, .rd = 3, .imm = immediate });
        const ls = entry.compactLs() orelse .{ 0xDEAD, 0xDEAD };
        var bytes: [13]u8 = undefined;
        bytes[0] = @intFromEnum(op);
        std.mem.writeInt(u64, bytes[1..9], entry.compactB(), .little);
        std.mem.writeInt(u16, bytes[9..11], ls[0], .little);
        std.mem.writeInt(u16, bytes[11..13], ls[1], .little);
        hash.update(&bytes);
        hash.update(&[_]u8{@intFromBool(entry.compactValid())});
    };
    const base = pairIdentity();
    hash.update(&base);
    return hash.finalResult();
}
