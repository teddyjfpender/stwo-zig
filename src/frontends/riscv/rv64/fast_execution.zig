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
const compact_tape = @import("compact_tape.zig");
const boundary_capture = @import("boundary_capture.zig");
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
    andn,
    orn,
    xnor,
    rev8,
    sext_b,
    sext_h,
    zext_h,
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
const UNKNOWN_MASK: u8 = 0xff;
/// Output of `Engine.runTraced`, appended in place (see there).
pub const Trace = struct {
    /// Tape storage; `len` steps are already written.
    steps: []compact_tape.Step,
    len: usize,
    memory_before: *std.ArrayList(u64),
    capture: *boundary_capture.Capture,
    /// `Batch.register_clocks` plus a sink entry (index 32) for x0 writes.
    clocks: [33]u32,
    divisions: u32 = 0,
    multiplications: u32 = 0,
};
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
    /// Decode set; must equal the reference session's (`Session.decoder.isa`).
    isa: isa.Isa = .rv64im,
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
    /// False for an engine that borrows `slots`/`blen`/`opcodes`/`rights`
    /// from a program engine (`initBorrowing`); those tables are immutable.
    owns_program: bool = true,
    /// Decode set the slots were lowered with (`Options.isa`).
    decode_isa: isa.Isa = .rv64im,
    /// Traced mode: boundary-capture rights per page (1 = every word
    /// read-only, 3 = every word read/write, 0 = mixed or unreadable,
    /// UNKNOWN until first use). Computed from `memory.mappings` only.
    cmask: []u8 = &.{},

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
        var self = Engine{ .allocator = a, .memory = memory, .code_lo = lo, .code_hi = hi, .slots = &.{}, .blen = &.{}, .opcodes = &.{}, .rd_tab = &.{}, .wr_tab = &.{}, .rights = &.{}, .dirty = .{ .bits = &.{} }, .counts = &.{}, .counting = options.counting, .decode_isa = options.isa };
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
            const inst = isa.decodeFor(options.isa, word) catch continue;
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
        a.free(self.cmask);
        a.free(self.counts);
        a.free(self.dirty.bits);
        a.free(self.wr_tab);
        a.free(self.rd_tab);
        if (self.owns_program) {
            a.free(self.rights);
            a.free(self.opcodes);
            a.free(self.blen);
            a.free(self.slots);
        }
        self.* = undefined;
    }

    /// An independent program engine with the same decoded program, page
    /// rights and stop pcs as `source` (deep copy; `source` may run meanwhile
    /// on its own memory: only immutable tables are read). Census is off.
    pub fn cloneProgram(a: std.mem.Allocator, source: *const Engine) Error!Engine {
        var self = Engine{ .allocator = a, .memory = source.memory, .code_lo = source.code_lo, .code_hi = source.code_hi, .slots = &.{}, .blen = &.{}, .opcodes = &.{}, .rd_tab = &.{}, .wr_tab = &.{}, .rights = &.{}, .dirty = .{ .bits = &.{} }, .counts = &.{}, .counting = false, .decode_isa = source.decode_isa };
        errdefer self.deinit();
        self.slots = try a.dupe(Slot, source.slots);
        self.blen = try a.dupe(u32, source.blen);
        self.opcodes = try a.dupe(isa.Opcode, source.opcodes);
        self.rights = try a.dupe(u8, source.rights);
        self.rd_tab = try a.alloc(?[*]u8, source.rd_tab.len);
        @memset(self.rd_tab, null);
        self.wr_tab = try a.alloc(?[*]u8, source.wr_tab.len);
        @memset(self.wr_tab, null);
        self.dirty.bits = try a.alloc(u64, source.dirty.bits.len);
        @memset(self.dirty.bits, 0);
        return self;
    }

    /// Turn every fast slot whose pc `admit` refuses into a slow slot (the
    /// reference session then retires it, with its checks and errors), and
    /// recompute block lengths. `admit` sees the raw image word and its
    /// decode under `decode_isa`. Program engines only, before any run.
    pub fn restrict(self: *Engine, context: anytype, comptime admit: fn (@TypeOf(context), pc: u64, raw: u32, inst: isa.Instruction) bool) void {
        std.debug.assert(self.owns_program);
        for (self.slots[0 .. self.slots.len - 1], 0..) |*slot, i| {
            if (slot.op == .slow) continue;
            const pc = self.code_lo + 4 * @as(u64, i);
            const keep = blk: {
                const raw = self.memory.fetch(pc) catch break :blk false;
                const inst = isa.decodeFor(self.decode_isa, raw) catch break :blk false;
                if (inst.opcode != self.opcodes[i]) break :blk false;
                break :blk admit(context, pc, raw, inst);
            };
            if (!keep) {
                slot.* = .{};
                self.opcodes[i] = .EBREAK;
            }
        }
        var length: u32 = 0;
        var i = self.slots.len;
        while (i > 0) {
            i -= 1;
            length = switch (self.slots[i].op) {
                .slow => 0,
                .beq, .bne, .blt, .bge, .bltu, .bgeu, .jal, .jalr => 1,
                else => length + 1,
            };
            self.blen[i] = length;
        }
    }

    /// An engine executing on `memory` with `program`'s immutable decoded
    /// program and page rights (borrowed; `program` must outlive it).
    /// `memory` must have `program.memory`'s mappings (a checkpoint copy).
    pub fn initBorrowing(a: std.mem.Allocator, memory: *mem.Memory, program: *const Engine) Error!Engine {
        var self = Engine{ .allocator = a, .memory = memory, .code_lo = program.code_lo, .code_hi = program.code_hi, .slots = program.slots, .blen = program.blen, .opcodes = program.opcodes, .rd_tab = &.{}, .wr_tab = &.{}, .rights = program.rights, .dirty = .{ .bits = &.{} }, .counts = &.{}, .counting = false, .owns_program = false, .decode_isa = program.decode_isa };
        errdefer self.deinit();
        self.rd_tab = try a.alloc(?[*]u8, program.rd_tab.len);
        @memset(self.rd_tab, null);
        self.wr_tab = try a.alloc(?[*]u8, program.wr_tab.len);
        @memset(self.wr_tab, null);
        self.dirty.bits = try a.alloc(u64, program.dirty.bits.len);
        @memset(self.dirty.bits, 0);
        self.cmask = try a.alloc(u8, program.rights.len);
        @memset(self.cmask, UNKNOWN_MASK);
        return self;
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
            .ANDN => .andn,
            .ORN => .orn,
            .XNOR => .xnor,
            .REV8 => .rev8,
            .SEXT_B => .sext_b,
            .SEXT_H => .sext_h,
            .ZEXT_H => .zext_h,
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
            // A foreign write observer (segment continuity) sees fast
            // stores too: the fast path writes without `Pages.store`.
            if (self.memory.backing.dirty) |d| if (d != &self.dirty) d.mark(index);
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
            inline .add, .sub, .sll, .slt, .sltu, .xor, .srl, .sra, .@"or", .@"and", .addi, .slti, .sltiu, .xori, .ori, .andi, .slli, .srli, .srai, .addw, .subw, .sllw, .srlw, .sraw, .addiw, .slliw, .srliw, .sraiw, .mul, .mulh, .mulhsu, .mulhu, .div, .divu, .rem, .remu, .mulw, .divw, .divuw, .remw, .remuw, .andn, .orn, .xnor, .rev8, .sext_b, .sext_h, .zext_h => |op| {
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

    /// Boundary-capture rights of every 8-byte word of page `index`, when
    /// uniform (1 read-only, 3 read/write), else 0. Mirrors the per-word
    /// `mappings.check` pair of `boundary_capture.Capture.publish`.
    noinline fn captureMask(self: *Engine, index: u64) u8 {
        const i: usize = @intCast(index);
        if (self.cmask[i] != UNKNOWN_MASK) return self.cmask[i];
        const base = index << PAGE_SHIFT;
        const m = &self.memory.mappings;
        var mask: u8 = 0;
        if (m.check(base, mem.PAGE_SIZE, .read)) |_| {
            if (m.check(base, mem.PAGE_SIZE, .write)) |_| mask = 3 else |_| {
                mask = 1;
                var word: u64 = 0;
                while (word < mem.PAGE_SIZE) : (word += 8) {
                    if (m.check(base + word, 8, .write)) |_| {
                        mask = 0;
                        break;
                    } else |_| {}
                }
            }
        } else |_| {}
        self.cmask[i] = mask;
        return mask;
    }

    /// Traced retirement (borrowing engines only): like `run`, but every
    /// fast instruction also writes exactly the reference advice
    /// (`compact_tape.Tape.append`), boundary word (`Capture.append`) and
    /// batch register clocks / service request counts (`Batch.observe`).
    /// An instruction whose capture update the reference would refuse, or
    /// that needs any allocation, stops the engine before it executes, so
    /// the caller's reference step reports the reference error. `trace`
    /// must have `memory_before` capacity for `limit - cpu.retired` words.
    pub fn runTraced(self: *Engine, cpu: *machine.Cpu, limit: u64, trace: *Trace) Exit {
        if (cpu.retired >= limit) return .limit;
        var i: usize = self.slotOf(cpu.pc) orelse return .slow;
        std.debug.assert(self.cmask.len == self.rights.len);
        var r: [33]u64 = undefined;
        @memcpy(r[0..32], &cpu.regs);
        r[0] = 0;
        r[SINK] = 0;
        const slots = self.slots.ptr;
        const blen = self.blen.ptr;
        const rd_tab = self.rd_tab;
        const wr_tab = self.wr_tab;
        const cmask = self.cmask;
        const code_lo = self.code_lo;
        const steps = trace.steps.ptr;
        const before = trace.memory_before;
        const cap = trace.capture;
        const start = trace.len;
        std.debug.assert(limit - cpu.retired <= trace.steps.len - start);
        const end_pos: usize = start + @as(usize, @intCast(limit - cpu.retired));
        std.debug.assert(before.capacity - before.items.len >= end_pos - start);
        var pos = start;
        var clocks = trace.clocks;
        const saved_zero = clocks[0];
        var divisions: u32 = 0;
        var multiplications: u32 = 0;
        sw: switch (Op.enter) {
            .enter => {
                const n = blen[i];
                if (n == 0 or n > end_pos - pos) break :sw;
                continue :sw slots[i].op;
            },
            .slow => break :sw,
            .nop => {
                steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = 0, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = compact_tape.NO_MEMORY, .flags = 0 };
                pos += 1;
                i += 1;
                continue :sw slots[i].op;
            },
            .li => {
                const s = slots[i];
                const tick: u32 = @intCast(4 * pos);
                steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = 0, .rhs = 0, .previous_rd = r[s.rd], .result = s.imm, .memory_index = compact_tape.NO_MEMORY, .flags = 0 };
                clocks[s.rd] = tick + 3;
                r[s.rd] = s.imm;
                r[SINK] = 0;
                pos += 1;
                i += 1;
                continue :sw slots[i].op;
            },
            inline .add, .sub, .sll, .slt, .sltu, .xor, .srl, .sra, .@"or", .@"and", .addi, .slti, .sltiu, .xori, .ori, .andi, .slli, .srli, .srai, .addw, .subw, .sllw, .srlw, .sraw, .addiw, .slliw, .srliw, .sraiw, .mul, .mulh, .mulhsu, .mulhu, .div, .divu, .rem, .remu, .mulw, .divw, .divuw, .remw, .remuw, .andn, .orn, .xnor, .rev8, .sext_b, .sext_h, .zext_h => |op| {
                const s = slots[i];
                const x = r[s.rs1];
                const y = r[s.rs2];
                const v = alu(op, x, y, s.imm);
                const tick: u32 = @intCast(4 * pos);
                steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = x, .rhs = y, .previous_rd = r[s.rd], .result = v, .memory_index = compact_tape.NO_MEMORY, .flags = 0 };
                clocks[s.rs1] = tick + 1;
                clocks[s.rs2] = tick + 2;
                clocks[s.rd] = tick + 3;
                switch (op) {
                    .div, .divu, .rem, .remu, .divw, .divuw, .remw, .remuw => divisions += 1,
                    .mul, .mulh, .mulhsu, .mulhu, .mulw => multiplications += 1,
                    else => {},
                }
                r[s.rd] = v;
                r[SINK] = 0;
                pos += 1;
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
                const x = r[s.rs1];
                const address = x +% s.imm;
                if (address & (@sizeOf(T) - 1) != 0) break :sw;
                const index = address >> PAGE_SHIFT;
                const base = (if (index < rd_tab.len) rd_tab[@intCast(index)] else null) orelse self.fill(index, false) orelse break :sw;
                const m = if (cmask[@intCast(index)] != UNKNOWN_MASK) cmask[@intCast(index)] else self.captureMask(index);
                if (m == 0) break :sw;
                const offset: usize = @intCast(address & (mem.PAGE_SIZE - 1));
                const word = std.mem.readInt(u64, base[offset & ~@as(usize, 7) ..][0..8], .little);
                const tick: u32 = @intCast(4 * pos);
                if (!cap.fastWord(address & ~@as(u64, 7), word, word, @intCast(m), tick + 4)) break :sw;
                const raw: T = @truncate(word >> @intCast((offset & 7) * 8));
                const v: u64 = switch (op) {
                    .lb => @bitCast(@as(i64, @as(i8, @bitCast(raw)))),
                    .lh => @bitCast(@as(i64, @as(i16, @bitCast(raw)))),
                    .lw => @bitCast(@as(i64, @as(i32, @bitCast(raw)))),
                    else => raw,
                };
                steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = x, .rhs = 0, .previous_rd = r[s.rd], .result = v, .memory_index = @intCast(before.items.len), .flags = 0 };
                before.appendAssumeCapacity(word);
                clocks[s.rs1] = tick + 1;
                clocks[s.rd] = tick + 3;
                r[s.rd] = v;
                r[SINK] = 0;
                pos += 1;
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
                const x = r[s.rs1];
                const y = r[s.rs2];
                const address = x +% s.imm;
                if (address & (@sizeOf(T) - 1) != 0) break :sw;
                const index = address >> PAGE_SHIFT;
                const base = (if (index < wr_tab.len) wr_tab[@intCast(index)] else null) orelse self.fill(index, true) orelse break :sw;
                const m = if (cmask[@intCast(index)] != UNKNOWN_MASK) cmask[@intCast(index)] else self.captureMask(index);
                if (m != 3) break :sw;
                const offset: usize = @intCast(address & (mem.PAGE_SIZE - 1));
                const bytes = base[offset & ~@as(usize, 7) ..][0..8];
                const word = std.mem.readInt(u64, bytes, .little);
                const shift: u6 = @intCast((offset & 7) * 8);
                const width_mask: u64 = std.math.maxInt(T);
                const after = (word & ~(width_mask << shift)) | ((y & width_mask) << shift);
                const tick: u32 = @intCast(4 * pos);
                if (!cap.fastWord(address & ~@as(u64, 7), word, after, 3, tick + 4)) break :sw;
                std.mem.writeInt(u64, bytes, after, .little);
                steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, i) + 4, .lhs = x, .rhs = y, .previous_rd = 0, .result = 0, .memory_index = @intCast(before.items.len), .flags = 0 };
                before.appendAssumeCapacity(word);
                clocks[s.rs1] = tick + 1;
                clocks[s.rs2] = tick + 2;
                pos += 1;
                i += 1;
                continue :sw slots[i].op;
            },
            inline .beq, .bne, .blt, .bge, .bltu, .bgeu => |op| {
                const s = slots[i];
                const x = r[s.rs1];
                const y = r[s.rs2];
                const sx: i64 = @bitCast(x);
                const sy: i64 = @bitCast(y);
                const taken = switch (op) {
                    .beq => x == y,
                    .bne => x != y,
                    .blt => sx < sy,
                    .bge => sx >= sy,
                    .bltu => x < y,
                    .bgeu => x >= y,
                    else => unreachable,
                };
                const next: usize = if (taken) s.target else i + 1;
                const tick: u32 = @intCast(4 * pos);
                steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, next), .lhs = x, .rhs = y, .previous_rd = 0, .result = 0, .memory_index = compact_tape.NO_MEMORY, .flags = @intFromBool(taken) };
                clocks[s.rs1] = tick + 1;
                clocks[s.rs2] = tick + 2;
                pos += 1;
                i = next;
                continue :sw .enter;
            },
            .jal => {
                const s = slots[i];
                const tick: u32 = @intCast(4 * pos);
                steps[pos] = .{ .next_pc = code_lo + 4 * @as(u64, s.target), .lhs = 0, .rhs = 0, .previous_rd = r[s.rd], .result = s.imm, .memory_index = compact_tape.NO_MEMORY, .flags = 1 };
                clocks[s.rd] = tick + 3;
                r[s.rd] = s.imm;
                r[SINK] = 0;
                pos += 1;
                i = s.target;
                continue :sw .enter;
            },
            .jalr => {
                const s = slots[i];
                const x = r[s.rs1];
                const target = (x +% s.imm) & ~@as(u64, 1);
                if (target & 3 != 0 or target < code_lo or target >= self.code_hi) break :sw;
                const link = code_lo + 4 * @as(u64, i) + 4;
                const tick: u32 = @intCast(4 * pos);
                steps[pos] = .{ .next_pc = target, .lhs = x, .rhs = 0, .previous_rd = r[s.rd], .result = link, .memory_index = compact_tape.NO_MEMORY, .flags = 1 };
                clocks[s.rs1] = tick + 1;
                clocks[s.rd] = tick + 3;
                r[s.rd] = link;
                r[SINK] = 0;
                pos += 1;
                i = @intCast((target - code_lo) / 4);
                continue :sw .enter;
            },
        }
        const retired = pos - start;
        clocks[0] = saved_zero;
        trace.clocks = clocks;
        trace.len = pos;
        trace.divisions += divisions;
        trace.multiplications += multiplications;
        if (retired != 0) {
            @memcpy(&cpu.regs, r[0..32]);
            cpu.regs[0] = 0;
            cpu.pc = code_lo + 4 * @as(u64, i);
            cpu.retired += retired;
            cap.steps += @intCast(retired);
            self.fast_retired += retired;
        }
        return if (pos == end_pos) .limit else .slow;
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
        .andn => a & ~b,
        .orn => a | ~b,
        .xnor => ~(a ^ b),
        .rev8 => @byteSwap(a),
        .sext_b => @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(a)))))),
        .sext_h => @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(a)))))),
        .zext_h => a & 0xffff,
        else => @compileError("not an ALU op"),
    };
}
