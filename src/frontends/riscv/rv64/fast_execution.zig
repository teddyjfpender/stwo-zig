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
/// CPU-only first-pass advice. PC is remapped through the receiver-owned ROM;
/// branches record their taken bit as `result`, like native CPU metadata.
/// No operands, register clocks, field columns or memory/service ledger live
/// here. A consumer still needs the segment initial state and ordered advice.
pub const MinimalRecord = extern struct { result: u64, pc: u32, next_pc: u32 };
pub const MINIMAL_CHUNK_ROWS: usize = 256;
/// Architectural state preceding each chunk, captured inside the original
/// fast pass. Unused registers may be zeroed by a later transport adapter;
/// retaining them here permits an independent prefix consistency check.
pub const MinimalSeed = extern struct { values: [32]u64, clocks: [32]u32 };
pub const MinimalTrace = struct {
    records: []MinimalRecord,
    len: usize = 0,
    seeds: []MinimalSeed = &.{},
    clocks: [32]u32 = @splat(0),
    seed_prepared: bool = false,
    /// Reference fallback calls this BEFORE retirement; a trap publishes no
    /// record and the same seed may be overwritten on retry.
    pub fn prepareReference(self: *MinimalTrace, registers: *const [32]u64) void {
        if (self.seeds.len == 0 or self.len % MINIMAL_CHUNK_ROWS != 0) return;
        std.debug.assert(self.len / MINIMAL_CHUNK_ROWS < self.seeds.len);
        self.seeds[self.len / MINIMAL_CHUNK_ROWS] = .{ .values = registers.*, .clocks = self.clocks };
        self.seeds[self.len / MINIMAL_CHUNK_ROWS].values[0] = 0;
        self.seed_prepared = true;
    }
    fn appendRecord(self: *MinimalTrace, pc: u64, next_pc: u64, result: u64, ids: [3]u8) void {
        std.debug.assert(self.len < self.records.len);
        std.debug.assert(self.seeds.len == 0 or self.len % MINIMAL_CHUNK_ROWS != 0 or self.seed_prepared);
        self.records[self.len] = .{ .result = result, .pc = @intCast(pc), .next_pc = @intCast(next_pc) };
        if (self.seeds.len != 0) for (ids, 0..) |id, slot| {
            if (id != 0 and id != SINK) self.clocks[id] = @intCast(4 * self.len + slot + 1);
        };
        self.len += 1;
        self.seed_prepared = false;
    }
    fn appendFast(self: *MinimalTrace, pc: u64, next_pc: u64, result: u64, registers: *const [32]u64, ids: [3]u8) void {
        self.prepareReference(registers);
        self.appendRecord(pc, next_pc, result, ids);
    }
    /// Slow instructions (including services) are retired by the unchanged
    /// reference session. Append only after successful retirement, never retry.
    pub fn appendRetirement(self: *MinimalTrace, row: machine.Retirement) !void {
        if (self.len == self.records.len) return error.MinimalTraceFull;
        if (self.seeds.len != 0 and self.len % MINIMAL_CHUNK_ROWS == 0 and !self.seed_prepared) return error.MinimalSeedMissing;
        if (row.pc.toInt() > std.math.maxInt(u32) or row.next_pc.toInt() > std.math.maxInt(u32)) return error.MinimalTracePcRange;
        const branch = switch (row.opcode) {
            .BEQ, .BNE, .BLT, .BGE, .BLTU, .BGEU => true,
            else => false,
        };
        self.appendRecord(row.pc.toInt(), row.next_pc.toInt(), if (branch) @intFromBool(row.branch_taken) else row.result.toInt(), .{ row.rs1, row.rs2, row.rd });
    }
};
comptime {
    std.debug.assert(@sizeOf(MinimalRecord) == 16 and @sizeOf(MinimalSeed) == 384);
}
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
        return if (self.counting) self.runImpl(cpu, limit, true, false, false, null, null) else self.runImpl(cpu, limit, false, false, false, null, null);
    }

    /// Optional first-pass CPU records, emitted by the existing arithmetic and
    /// page-table loop. Default `run` specializes this entire path away.
    /// Capacity is checked before any instruction; .limit refers to the
    /// requested limit or the end of the supplied record span.
    pub fn runMinimal(self: *Engine, cpu: *machine.Cpu, limit: u64, trace: *MinimalTrace) !Exit {
        if (trace.len > trace.records.len) return error.MinimalTraceFull;
        if (trace.seeds.len != 0 and trace.seeds.len < std.math.divCeil(usize, trace.records.len, MINIMAL_CHUNK_ROWS) catch unreachable) return error.MinimalSeedCapacity;
        if (self.code_lo > std.math.maxInt(u32) or self.code_hi > std.math.maxInt(u32)) return error.MinimalTracePcRange;
        const bounded = @min(limit, cpu.retired +| (trace.records.len - trace.len));
        if (cpu.retired >= bounded) return .limit;
        return if (self.counting) self.runImpl(cpu, bounded, true, true, false, trace, null) else self.runImpl(cpu, bounded, false, true, false, trace, null);
    }

    pub fn runMinimalRam(self: *Engine, cpu: *machine.Cpu, limit: u64, trace: *MinimalTrace, words: *@import("ram_word_set.zig").Set) !Exit {
        if (words.failure) |err| return err;
        if (trace.len > trace.records.len) return error.MinimalTraceFull;
        if (trace.seeds.len != 0 and trace.seeds.len < std.math.divCeil(usize, trace.records.len, MINIMAL_CHUNK_ROWS) catch unreachable) return error.MinimalSeedCapacity;
        if (self.code_lo > std.math.maxInt(u32) or self.code_hi > std.math.maxInt(u32)) return error.MinimalTracePcRange;
        const bounded = @min(limit, cpu.retired +| (trace.records.len - trace.len));
        if (cpu.retired >= bounded) return .limit;
        const result = if (self.counting) self.runImpl(cpu, bounded, true, true, true, trace, words) else self.runImpl(cpu, bounded, false, true, true, trace, words);
        if (words.failure) |err| return err;
        return result;
    }

    /// Same first pass with an explicit RAM-key sidecar. Normal run specializes
    /// all marks away; fetches and failed accesses never publish RAM keys.
    pub fn runRam(self: *Engine, cpu: *machine.Cpu, limit: u64, words: *@import("ram_word_set.zig").Set) !Exit {
        if (words.failure) |err| return err;
        if (cpu.retired >= limit) return .limit;
        const result = if (self.counting) self.runImpl(cpu, limit, true, false, true, null, words) else self.runImpl(cpu, limit, false, false, true, null, words);
        if (words.failure) |err| return err;
        return result;
    }

    fn runImpl(self: *Engine, cpu: *machine.Cpu, limit: u64, comptime counting: bool, comptime minimal: bool, comptime ram: bool, trace: ?*MinimalTrace, words: ?*@import("ram_word_set.zig").Set) Exit {
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
                if (minimal) trace.?.appendFast(self.code_lo + 4 * @as(u64, i), self.code_lo + 4 * @as(u64, i) + 4, 0, r[0..32], .{ 0, 0, 0 });
                i += 1;
                continue :sw slots[i].op;
            },
            .li => {
                const s = slots[i];
                if (minimal) trace.?.appendFast(self.code_lo + 4 * @as(u64, i), self.code_lo + 4 * @as(u64, i) + 4, s.imm, r[0..32], .{ 0, 0, s.rd });
                r[s.rd] = s.imm;
                i += 1;
                continue :sw slots[i].op;
            },
            inline .add, .sub, .sll, .slt, .sltu, .xor, .srl, .sra, .@"or", .@"and", .addi, .slti, .sltiu, .xori, .ori, .andi, .slli, .srli, .srai, .addw, .subw, .sllw, .srlw, .sraw, .addiw, .slliw, .srliw, .sraiw, .mul, .mulh, .mulhsu, .mulhu, .div, .divu, .rem, .remu, .mulw, .divw, .divuw, .remw, .remuw, .andn, .orn, .xnor, .rev8, .sext_b, .sext_h, .zext_h => |op| {
                const s = slots[i];
                const result = alu(op, r[s.rs1], r[s.rs2], s.imm);
                if (minimal) trace.?.appendFast(self.code_lo + 4 * @as(u64, i), self.code_lo + 4 * @as(u64, i) + 4, result, r[0..32], .{ s.rs1, s.rs2, s.rd });
                r[s.rd] = result;
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
                if (ram) words.?.mark(address & ~@as(u64, 7)) catch |err| {
                    words.?.failure = err;
                    break :sw;
                };
                const raw = std.mem.readInt(T, base[@intCast(address & (mem.PAGE_SIZE - 1))..][0..@sizeOf(T)], .little);
                const result: u64 = switch (op) {
                    .lb => @bitCast(@as(i64, @as(i8, @bitCast(raw)))),
                    .lh => @bitCast(@as(i64, @as(i16, @bitCast(raw)))),
                    .lw => @bitCast(@as(i64, @as(i32, @bitCast(raw)))),
                    else => raw,
                };
                if (minimal) trace.?.appendFast(self.code_lo + 4 * @as(u64, i), self.code_lo + 4 * @as(u64, i) + 4, result, r[0..32], .{ s.rs1, 0, s.rd });
                r[s.rd] = result;
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
                if (ram) words.?.mark(address & ~@as(u64, 7)) catch |err| {
                    words.?.failure = err;
                    break :sw;
                };
                std.mem.writeInt(T, base[@intCast(address & (mem.PAGE_SIZE - 1))..][0..@sizeOf(T)], @truncate(r[s.rs2]), .little);
                if (minimal) trace.?.appendFast(self.code_lo + 4 * @as(u64, i), self.code_lo + 4 * @as(u64, i) + 4, 0, r[0..32], .{ s.rs1, s.rs2, 0 });
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
                const next = if (taken) s.target else i + 1;
                if (minimal) trace.?.appendFast(self.code_lo + 4 * @as(u64, i), self.code_lo + 4 * @as(u64, next), @intFromBool(taken), r[0..32], .{ s.rs1, s.rs2, 0 });
                i = next;
                continue :sw .enter;
            },
            .jal => {
                const s = slots[i];
                if (minimal) trace.?.appendFast(self.code_lo + 4 * @as(u64, i), self.code_lo + 4 * @as(u64, s.target), s.imm, r[0..32], .{ 0, 0, s.rd });
                r[s.rd] = s.imm;
                i = s.target;
                continue :sw .enter;
            },
            .jalr => {
                const s = slots[i];
                const target = (r[s.rs1] +% s.imm) & ~@as(u64, 1);
                if (target & 3 != 0 or target < self.code_lo or target >= self.code_hi) break :sw;
                const link = self.code_lo + 4 * @as(u64, i) + 4;
                if (minimal) trace.?.appendFast(self.code_lo + 4 * @as(u64, i), target, link, r[0..32], .{ s.rs1, 0, s.rd });
                r[s.rd] = link;
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
    const TraceExecution = @import("fast_trace_execution.zig").For(.{
        .std = std,
        .machine = machine,
        .mem = mem,
        .compact_tape = compact_tape,
        .PAGE_SHIFT = PAGE_SHIFT,
        .SINK = SINK,
        .Op = Op,
        .Exit = Exit,
        .UNKNOWN_MASK = UNKNOWN_MASK,
        .Trace = Trace,
        .Engine = Engine,
        .alu = alu,
        .slotOf = slotOf,
        .fill = fill,
        .captureMask = captureMask,
    });
    pub const runTraced = TraceExecution.runTraced;

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

const Arithmetic = @import("fast_alu.zig").For(.{
    .Op = Op,
    .machine = machine,
    .std = std,
});
const alu = Arithmetic.alu;
