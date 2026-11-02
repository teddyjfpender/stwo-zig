//! Fast first-pass RV64IM execution over the reference memory: instructions
//! pre-decoded once per program into straight-line blocks, threaded dispatch
//! (labelled switch), and direct read/write page tables in front of `Pages`.
//!
//! The engine retires only instructions whose effect cannot differ from
//! `machine.Cpu.retire`: in-code, decodable, non-trapping, on pages whose
//! rights admit the whole page and that already exist. Anything else (ECALL,
//! EBREAK, illegal words, misaligned or out-of-table accesses, absent pages,
//! watched pages and pcs, the step budget) stops *before* the instruction with
//! architectural state untouched, so the caller retires it with the reference
//! session and every trap and service keeps the reference semantics.
//!
//! Prover-side witness generation only; no field here is proof authority.
const std = @import("std");
const isa = @import("decode.zig");
const machine = @import("machine.zig");
const mem = @import("memory.zig");
const pages = @import("pages.zig");
const Page = pages.Page;
const PAGE_SHIFT = 12;
comptime {
    std.debug.assert(mem.PAGE_SIZE == 1 << PAGE_SHIFT);
}
/// Address-space pages covered by the direct tables (higher pages go slow).
pub const MAX_TABLE_PAGES: u64 = 1 << 20;
pub const MAX_CODE_SLOTS: u64 = 1 << 24;
/// Sink register for writes to x0.
const SINK = 32;

const Op = enum(u8) {
    enter,
    slow,
    nop,
    add,
    sub,
    sll,
    slt,
    sltu,
    xor,
    srl,
    sra,
    @"or",
    @"and",
    addi,
    slti,
    sltiu,
    xori,
    ori,
    andi,
    slli,
    srli,
    srai,
    addw,
    subw,
    sllw,
    srlw,
    sraw,
    addiw,
    slliw,
    srliw,
    sraiw,
    li,
    mul,
    mulh,
    mulhsu,
    mulhu,
    div,
    divu,
    rem,
    remu,
    mulw,
    divw,
    divuw,
    remw,
    remuw,
    lb,
    lh,
    lw,
    ld,
    lbu,
    lhu,
    lwu,
    sb,
    sh,
    sw,
    sd,
    beq,
    bne,
    blt,
    bge,
    bltu,
    bgeu,
    jal,
    jalr,
};

const Slot = extern struct {
    op: Op = .slow,
    rd: u8 = SINK,
    rs1: u8 = 0,
    rs2: u8 = 0,
    /// Branch/JAL target slot.
    target: u32 = 0,
    /// Immediate; LUI/AUIPC/JAL/JALR: precomputed result or link value.
    imm: u64 = 0,
};
comptime {
    std.debug.assert(@sizeOf(Slot) == 16);
}

pub const Exit = enum { limit, slow };
pub const PcCounts = struct { start: u64, end: u64, counts: []u64, outside: *u64 };
pub const Error = std.mem.Allocator.Error || error{ FastExecutionCodeTooLarge, FastExecutionTableTooLarge, FastExecutionCheckpointOverflow };

pub const Options = struct {
    /// Slots whose pc is listed always stop the engine before executing.
    stop_pcs: []const u64 = &.{},
    /// Byte ranges [start, start+len) whose pages the engine never writes, so
    /// every store into them is retired (and observed) by the caller.
    watch: []const [2]u64 = &.{},
    /// Per-slot retirement counts (difference array) for census reports.
    counting: bool = false,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    memory: *mem.Memory,
    code_lo: u64,
    code_hi: u64,
    slots: []Slot,
    /// Instructions from a slot to the end of its block (0 on slow slots).
    blen: []u32,
    /// Reference opcode per fast slot (census only).
    opcodes: []isa.Opcode,
    rd_tab: []?[*]u8,
    wr_tab: []?[*]u8,
    /// Bit 0: whole page readable; bit 1: whole page writable and not watched.
    rights: []u8,
    /// Shared with `memory.backing.dirty` while attached.
    dirty: pages.Dirty,
    /// Difference array over slots (counting only).
    counts: []i64,
    counting: bool,
    fast_retired: u64 = 0,

    pub fn init(a: std.mem.Allocator, memory: *mem.Memory, options: Options) Error!Engine {
        const entries = memory.mappings.entries.items;
        var lo: u64 = std.math.maxInt(u64);
        var hi: u64 = 0;
        var top: u64 = 0;
        for (entries) |e| {
            if (e.permissions.execute) {
                lo = @min(lo, e.first & ~@as(u64, 3));
                hi = @max(hi, (e.last | 3) +% 1);
            }
            top = @max(top, (e.last >> PAGE_SHIFT) + 1);
        }
        if (lo >= hi) {
            lo = 0;
            hi = 0;
        }
        const n_slots = (hi - lo) / 4;
        if (n_slots >= MAX_CODE_SLOTS) return error.FastExecutionCodeTooLarge;
        const n_pages: usize = @intCast(@min(top, MAX_TABLE_PAGES));
        var self = Engine{ .allocator = a, .memory = memory, .code_lo = lo, .code_hi = hi, .slots = &.{}, .blen = &.{}, .opcodes = &.{}, .rd_tab = &.{}, .wr_tab = &.{}, .rights = &.{}, .dirty = .{ .bits = &.{} }, .counts = &.{}, .counting = options.counting };
        errdefer self.deinit();
        // One trailing slow sentinel so fall-through past the code never indexes out.
        self.slots = try a.alloc(Slot, n_slots + 1);
        @memset(self.slots, .{});
        self.blen = try a.alloc(u32, n_slots + 1);
        self.opcodes = try a.alloc(isa.Opcode, n_slots + 1);
        @memset(self.opcodes, .EBREAK);
        self.rd_tab = try a.alloc(?[*]u8, n_pages);
        @memset(self.rd_tab, null);
        self.wr_tab = try a.alloc(?[*]u8, n_pages);
        @memset(self.wr_tab, null);
        self.rights = try a.alloc(u8, n_pages);
        @memset(self.rights, 0);
        self.dirty.bits = try a.alloc(u64, (n_pages + 63) / 64);
        @memset(self.dirty.bits, 0);
        if (options.counting) {
            self.counts = try a.alloc(i64, n_slots + 1);
            @memset(self.counts, 0);
        }
        // Rights per page: a page is fast only if every byte admits the access.
        for (entries) |e| {
            var p = e.first >> PAGE_SHIFT;
            while (p <= e.last >> PAGE_SHIFT and p < n_pages) : (p += 1) {
                const base = p << PAGE_SHIFT;
                var bits: u8 = 0;
                if (memory.mappings.check(base, mem.PAGE_SIZE, .read)) |_| bits |= 1 else |_| {}
                if (memory.mappings.check(base, mem.PAGE_SIZE, .write)) |_| bits |= 2 else |_| {}
                self.rights[@intCast(p)] = bits;
            }
        }
        for (options.watch) |range| {
            if (range[1] == 0) continue;
            var p = range[0] >> PAGE_SHIFT;
            const last = (range[0] +| (range[1] - 1)) >> PAGE_SHIFT;
            while (p <= last and p < n_pages) : (p += 1) self.rights[@intCast(p)] &= ~@as(u8, 2);
        }
        // Pre-decode every executable word; the reference fetch check decides.
        for (0..n_slots) |i| {
            const pc = lo + 4 * i;
            const word = memory.fetch(pc) catch continue;
            // Writable code would let a store outdate the pre-decoded slot.
            if (memory.mappings.check(pc, 4, .write)) |_| continue else |_| {}
            const inst = isa.Instruction.decode(word) catch continue;
            self.slots[i] = self.lower(inst, pc);
            if (self.slots[i].op != .slow) self.opcodes[i] = inst.opcode;
        }
        for (options.stop_pcs) |pc| if (self.slotOf(pc)) |i| {
            self.slots[i] = .{};
        };
        // Block lengths, scanning backwards: a terminator ends its block.
        var length: u32 = 0;
        var i = n_slots + 1;
        while (i > 0) {
            i -= 1;
            const op = self.slots[i].op;
            length = switch (op) {
                .slow => 0,
                .beq, .bne, .blt, .bge, .bltu, .bgeu, .jal, .jalr => 1,
                else => length + 1,
            };
            self.blen[i] = length;
        }
        return self;
    }

    pub fn deinit(self: *Engine) void {
        self.detach();
        const a = self.allocator;
        a.free(self.counts);
        a.free(self.dirty.bits);
        a.free(self.rights);
        a.free(self.wr_tab);
        a.free(self.rd_tab);
        a.free(self.opcodes);
        a.free(self.blen);
        a.free(self.slots);
        self.* = undefined;
    }

    /// Route reference-path writes into this engine's dirty set.
    pub fn attach(self: *Engine) void {
        self.memory.backing.dirty = &self.dirty;
    }
    pub fn detach(self: *Engine) void {
        if (self.memory.backing.dirty == &self.dirty) self.memory.backing.dirty = null;
    }
    /// Start a new dirty interval: forget every page written so far and
    /// require the fast path to re-register each page on its next store.
    pub fn resetDirty(self: *Engine) void {
        self.dirty.clear();
        @memset(self.wr_tab, null);
    }

    fn slotOf(self: *const Engine, pc: u64) ?usize {
        if (pc < self.code_lo or pc >= self.code_hi or pc & 3 != 0) return null;
        return @intCast((pc - self.code_lo) / 4);
    }

    fn lower(self: *const Engine, inst: isa.Instruction, pc: u64) Slot {
        const imm: u64 = @bitCast(inst.imm);
        const fx = isa.effects(inst.opcode);
        var s = Slot{ .rd = if (fx.writes_rd and inst.rd != 0) inst.rd else SINK, .rs1 = if (fx.reads_rs1) inst.rs1 else 0, .rs2 = if (fx.reads_rs2) inst.rs2 else 0, .imm = imm };
        s.op = switch (inst.opcode) {
            .ADD => .add,
            .SUB => .sub,
            .SLL => .sll,
            .SLT => .slt,
            .SLTU => .sltu,
            .XOR => .xor,
            .SRL => .srl,
            .SRA => .sra,
            .OR => .@"or",
            .AND => .@"and",
            .ADDI => .addi,
            .SLTI => .slti,
            .SLTIU => .sltiu,
            .XORI => .xori,
            .ORI => .ori,
            .ANDI => .andi,
            .SLLI => .slli,
            .SRLI => .srli,
            .SRAI => .srai,
            .ADDW => .addw,
            .SUBW => .subw,
            .SLLW => .sllw,
            .SRLW => .srlw,
            .SRAW => .sraw,
            .ADDIW => .addiw,
            .SLLIW => .slliw,
            .SRLIW => .srliw,
            .SRAIW => .sraiw,
            .LUI => .li,
            .AUIPC => blk: {
                s.imm = pc +% imm;
                break :blk .li;
            },
            .MUL => .mul,
            .MULH => .mulh,
            .MULHSU => .mulhsu,
            .MULHU => .mulhu,
            .DIV => .div,
            .DIVU => .divu,
            .REM => .rem,
            .REMU => .remu,
            .MULW => .mulw,
            .DIVW => .divw,
            .DIVUW => .divuw,
            .REMW => .remw,
            .REMUW => .remuw,
            .LB => .lb,
            .LH => .lh,
            .LW => .lw,
            .LD => .ld,
            .LBU => .lbu,
            .LHU => .lhu,
            .LWU => .lwu,
            .SB => .sb,
            .SH => .sh,
            .SW => .sw,
            .SD => .sd,
            .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU, .JAL => blk: {
                // A static target outside the slot table (or misaligned) is
                // left to the reference, which traps only when taken.
                const target = self.slotOf(pc +% imm) orelse return .{};
                s.target = @intCast(target);
                if (inst.opcode == .JAL) {
                    s.imm = pc +% 4;
                    break :blk .jal;
                }
                break :blk switch (inst.opcode) {
                    .BEQ => .beq,
                    .BNE => .bne,
                    .BLT => .blt,
                    .BGE => .bge,
                    .BLTU => .bltu,
                    .BGEU => .bgeu,
                    else => unreachable,
                };
            },
            .JALR => .jalr,
            .FENCE => .nop,
            .ECALL, .EBREAK => return .{},
        };
        return s;
    }

    /// Cold path: admit an existing page whose rights cover the access.
    noinline fn fill(self: *Engine, index: u64, write: bool) ?[*]u8 {
        if (index >= self.rights.len) return null;
        const i: usize = @intCast(index);
        const need: u8 = if (write) 2 else 1;
        if (self.rights[i] & need == 0) return null;
        const page = self.memory.backing.peek(index) orelse return null;
        const base: [*]u8 = page;
        if (self.rights[i] & 1 != 0) self.rd_tab[i] = base;
        if (write) {
            self.dirty.mark(index);
            self.wr_tab[i] = base;
        }
        return base;
    }

    /// Retire fast instructions until `cpu.retired == limit` (`.limit`) or the
    /// next instruction must be retired by the reference session (`.slow`).
    pub fn run(self: *Engine, cpu: *machine.Cpu, limit: u64) Exit {
        if (cpu.retired >= limit) return .limit;
        return if (self.counting) self.runImpl(cpu, limit, true) else self.runImpl(cpu, limit, false);
    }

    fn runImpl(self: *Engine, cpu: *machine.Cpu, limit: u64, comptime counting: bool) Exit {
        var i: usize = self.slotOf(cpu.pc) orelse return .slow;
        var r: [33]u64 = undefined;
        @memcpy(r[0..32], &cpu.regs);
        r[0] = 0;
        r[SINK] = 0;
        const slots = self.slots.ptr;
        const blen = self.blen.ptr;
        const counts = self.counts.ptr;
        const rd_tab = self.rd_tab;
        const wr_tab = self.wr_tab;
        const start = cpu.retired;
        var retired = start;
        var end: usize = i;
        sw: switch (Op.enter) {
            .enter => {
                const n = blen[i];
                end = i;
                if (n == 0 or n > limit - retired) break :sw;
                retired += n;
                end = i + n;
                if (counting) {
                    counts[i] += 1;
                    counts[end] -= 1;
                }
                continue :sw slots[i].op;
            },
            .slow => break :sw,
            .nop => {
                i += 1;
                continue :sw slots[i].op;
            },
            .li => {
                const s = slots[i];
                r[s.rd] = s.imm;
                i += 1;
                continue :sw slots[i].op;
            },
            inline .add, .sub, .sll, .slt, .sltu, .xor, .srl, .sra, .@"or", .@"and", .addi, .slti, .sltiu, .xori, .ori, .andi, .slli, .srli, .srai, .addw, .subw, .sllw, .srlw, .sraw, .addiw, .slliw, .srliw, .sraiw, .mul, .mulh, .mulhsu, .mulhu, .div, .divu, .rem, .remu, .mulw, .divw, .divuw, .remw, .remuw => |op| {
                const s = slots[i];
                r[s.rd] = alu(op, r[s.rs1], r[s.rs2], s.imm);
                i += 1;
                continue :sw slots[i].op;
            },
            inline .lb, .lh, .lw, .ld, .lbu, .lhu, .lwu => |op| {
                const s = slots[i];
                const T = switch (op) {
                    .lb, .lbu => u8,
                    .lh, .lhu => u16,
                    .lw, .lwu => u32,
                    .ld => u64,
                    else => unreachable,
                };
                const address = r[s.rs1] +% s.imm;
                if (address & (@sizeOf(T) - 1) != 0) break :sw;
                const index = address >> PAGE_SHIFT;
                const base = (if (index < rd_tab.len) rd_tab[@intCast(index)] else null) orelse self.fill(index, false) orelse break :sw;
                const raw = std.mem.readInt(T, base[@intCast(address & (mem.PAGE_SIZE - 1))..][0..@sizeOf(T)], .little);
                r[s.rd] = switch (op) {
                    .lb => @bitCast(@as(i64, @as(i8, @bitCast(raw)))),
                    .lh => @bitCast(@as(i64, @as(i16, @bitCast(raw)))),
                    .lw => @bitCast(@as(i64, @as(i32, @bitCast(raw)))),
                    else => raw,
                };
                i += 1;
                continue :sw slots[i].op;
            },
            inline .sb, .sh, .sw, .sd => |op| {
                const s = slots[i];
                const T = switch (op) {
                    .sb => u8,
                    .sh => u16,
                    .sw => u32,
                    .sd => u64,
                    else => unreachable,
                };
                const address = r[s.rs1] +% s.imm;
                if (address & (@sizeOf(T) - 1) != 0) break :sw;
                const index = address >> PAGE_SHIFT;
                const base = (if (index < wr_tab.len) wr_tab[@intCast(index)] else null) orelse self.fill(index, true) orelse break :sw;
                std.mem.writeInt(T, base[@intCast(address & (mem.PAGE_SIZE - 1))..][0..@sizeOf(T)], @truncate(r[s.rs2]), .little);
                i += 1;
                continue :sw slots[i].op;
            },
            inline .beq, .bne, .blt, .bge, .bltu, .bgeu => |op| {
                const s = slots[i];
                const a = r[s.rs1];
                const b = r[s.rs2];
                const sa: i64 = @bitCast(a);
                const sb: i64 = @bitCast(b);
                const taken = switch (op) {
                    .beq => a == b,
                    .bne => a != b,
                    .blt => sa < sb,
                    .bge => sa >= sb,
                    .bltu => a < b,
                    .bgeu => a >= b,
                    else => unreachable,
                };
                i = if (taken) s.target else i + 1;
                continue :sw .enter;
            },
            .jal => {
                const s = slots[i];
                r[s.rd] = s.imm;
                i = s.target;
                continue :sw .enter;
            },
            .jalr => {
                const s = slots[i];
                const target = (r[s.rs1] +% s.imm) & ~@as(u64, 1);
                if (target & 3 != 0 or target < self.code_lo or target >= self.code_hi) break :sw;
                r[s.rd] = self.code_lo + 4 * @as(u64, i) + 4;
                i = @intCast((target - self.code_lo) / 4);
                continue :sw .enter;
            },
        }
        // Stopped before slot i: un-retire the rest of the current block.
        retired -= end - i;
        if (counting and end != i) {
            counts[i] -= 1;
            counts[end] += 1;
        }
        if (retired != start) {
            @memcpy(&cpu.regs, r[0..32]);
            cpu.regs[0] = 0;
            cpu.pc = self.code_lo + 4 * @as(u64, i);
            cpu.retired = retired;
            self.fast_retired += retired - start;
        }
        return if (retired == limit) .limit else .slow;
    }

    /// Census: add fast retirements per reference opcode (and load/store
    /// totals) to `opcode_counts`. Requires `counting`.
    /// With `pcs`, also adds per-pc counts inside [pcs.start, pcs.end) (4-byte
    /// granules) and the rest to `pcs.outside`, like the reference pc profile.
    pub fn census(self: *const Engine, opcode_counts: []u64, loads: *u64, stores: *u64, pcs: ?PcCounts) void {
        if (!self.counting) return;
        var running: i64 = 0;
        for (self.counts, self.opcodes, self.slots, 0..) |delta, opcode, slot, index| {
            running += delta;
            if (running == 0) continue;
            std.debug.assert(slot.op != .slow and running > 0);
            const n: u64 = @intCast(running);
            if (pcs) |p| {
                const pc = self.code_lo + 4 * @as(u64, index);
                if (pc >= p.start and pc < p.end) p.counts[@intCast((pc - p.start) / 4)] += n else p.outside.* += n;
            }
            opcode_counts[@intFromEnum(opcode)] += n;
            const fx = isa.effects(opcode);
            if (fx.memory_width != 0) {
                if (fx.reads_rs2) stores.* += n else loads.* += n;
            }
        }
    }
};

inline fn alu(comptime op: Op, a: u64, b: u64, imm: u64) u64 {
    const sa: i64 = @bitCast(a);
    const sb: i64 = @bitCast(b);
    const aw: u32 = @truncate(a);
    const bw: u32 = @truncate(b);
    const sext32 = machine.sext32;
    return switch (op) {
        .add => a +% b,
        .sub => a -% b,
        .addi => a +% imm,
        .slt => @intFromBool(sa < sb),
        .sltu => @intFromBool(a < b),
        .slti => @intFromBool(sa < @as(i64, @bitCast(imm))),
        .sltiu => @intFromBool(a < imm),
        .@"and" => a & b,
        .@"or" => a | b,
        .xor => a ^ b,
        .andi => a & imm,
        .ori => a | imm,
        .xori => a ^ imm,
        .sll => a << @as(u6, @truncate(b)),
        .srl => a >> @as(u6, @truncate(b)),
        .sra => @bitCast(sa >> @as(u6, @truncate(b))),
        .slli => a << @as(u6, @truncate(imm)),
        .srli => a >> @as(u6, @truncate(imm)),
        .srai => @bitCast(sa >> @as(u6, @truncate(imm))),
        .addw => sext32(aw +% bw),
        .subw => sext32(aw -% bw),
        .addiw => sext32(aw +% @as(u32, @truncate(imm))),
        .sllw => sext32(aw << @as(u5, @truncate(b))),
        .srlw => sext32(aw >> @as(u5, @truncate(b))),
        .sraw => sext32(@bitCast(@as(i32, @bitCast(aw)) >> @as(u5, @truncate(b)))),
        .slliw => sext32(aw << @as(u5, @truncate(imm))),
        .srliw => sext32(aw >> @as(u5, @truncate(imm))),
        .sraiw => sext32(@bitCast(@as(i32, @bitCast(aw)) >> @as(u5, @truncate(imm)))),
        .mul => a *% b,
        .mulhu => @intCast((@as(u128, a) * b) >> 64),
        .mulh => @truncate(@as(u128, @bitCast(@as(i128, sa) * sb)) >> 64),
        .mulhsu => @truncate(@as(u128, @bitCast(@as(i128, sa) * @as(i128, b))) >> 64),
        .mulw => sext32(aw *% bw),
        .div => machine.divSigned64(sa, sb, false),
        .rem => machine.divSigned64(sa, sb, true),
        .divu => if (b == 0) std.math.maxInt(u64) else a / b,
        .remu => if (b == 0) a else a % b,
        .divw => sext32(machine.divSigned32(@bitCast(aw), @bitCast(bw), false)),
        .remw => sext32(machine.divSigned32(@bitCast(aw), @bitCast(bw), true)),
        .divuw => sext32(if (bw == 0) std.math.maxInt(u32) else aw / bw),
        .remuw => sext32(if (bw == 0) aw else aw % bw),
        else => @compileError("not an ALU op"),
    };
}
