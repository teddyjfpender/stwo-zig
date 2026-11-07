//! M9 GPU capture replay, CPU half (prototype; `STWO_RV64_M9_GPU_REPLAY`, default off).
//!
//! The fast first pass already walks the whole guest once (`fast_execution.Engine.run`).
//! Here the same loop also records, per segment:
//!   - a `Seed` (all 32 registers, pc, step and memory-tape cursors) at the first block
//!     entry at least `chunk` steps after the previous seed, and right after every step
//!     the engine cannot retire (services, traps, absent pages);
//!   - the aligned 8-byte word BEFORE every load/store, in retirement order. This is
//!     exactly `compact_tape.Tape.memory_before`, so the GPU replay never reads guest RAM;
//!   - every host-retired ("slow") step as its finished `compact_tape.Step`.
//! A GPU kernel (`src/backends/cuda/native/rv64/m9_gpu_replay.cu`) then re-executes every
//! chunk independently from its seed and emits the compact tape steps of the CPU
//! recorder (`fast_execution.Engine.runTraced` / `compact_tape.Tape.appendRecord`).
//!
//! Prover-side scheduling/witness only. Nothing here is proof authority: the receiver
//! re-derives everything, and the CPU recorder stays the oracle in the parity tool.
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
const fast = rv.fast_execution;
const machine = rv.machine;
const mem = rv.memory;
const compact_tape = rv.compact_tape;
pub const Step = compact_tape.Step;

const PAGE_SHIFT = 12;
const SINK = 32;

pub fn enabled() bool {
    const text = std.posix.getenv("STWO_RV64_M9_GPU_REPLAY") orelse return false;
    return std.mem.eql(u8, text, "1");
}

pub const DEFAULT_CHUNK_STEPS: u32 = 256;

/// State before a chunk; `steps` instructions follow it, all retired by the engine.
pub const Seed = extern struct {
    regs: [32]u64,
    pc: u64,
    /// Segment-local position of the chunk's first step.
    first_step: u32,
    steps: u32,
    /// Index into the segment's memory tape of the chunk's first memory word.
    first_mem: u32,
    /// 1: the chunk ends at the next seed (not at a slow step or the segment end), so the
    /// GPU checks its end registers/pc against that seed (continuity).
    check_next: u32,
};
/// One host-retired step, at its segment-local position. `pc_slot` is the ROM slot of the
/// step's own pc (`NO_SLOT` when outside the code table) and `rd` the register it writes
/// (`NO_RD`: none). The GPU checks that the chunk ending at this step stops exactly there,
/// with `r[rd] == step.previous_rd` and, when the next seed follows the step directly,
/// every other register equal to that seed's (end-of-chunk continuity, see `finish`).
pub const SlowStep = extern struct { pos: u32, pc_slot: u32 = NO_SLOT, step: Step, rd: u8 = NO_RD, reserved: [7]u8 = @splat(0) };
pub const NO_SLOT: u32 = 0xffff_ffff;
pub const NO_RD: u8 = 0xff;
comptime {
    std.debug.assert(@sizeOf(Seed) == 280 and @sizeOf(SlowStep) == 64 and @sizeOf(Step) == 48);
}

/// GPU opcode numbering: index into `OP_NAMES` (same names as the engine's private `Op`).
pub const OP_NAMES = [_][]const u8{
    "slow",  "nop",   "add",    "sub",   "sll",   "slt",   "sltu",  "xor",   "srl",    "sra",   "or",   "and",   "addi",
    "slti",  "sltiu", "xori",   "ori",   "andi",  "slli",  "srli",  "srai",  "addw",   "subw",  "sllw", "srlw",  "sraw",
    "addiw", "slliw", "srliw",  "sraiw", "li",    "mul",   "mulh",  "mulhsu", "mulhu", "div",   "divu", "rem",   "remu",
    "mulw",  "divw",  "divuw",  "remw",  "remuw", "andn",  "orn",   "xnor",  "rev8",   "sext_b", "sext_h", "zext_h", "lb",
    "lh",    "lw",    "ld",     "lbu",   "lhu",   "lwu",   "sb",    "sh",    "sw",     "sd",    "beq",  "bne",   "blt",
    "bge",   "bltu",  "bgeu",   "jal",   "jalr",
};
/// Same 16-byte layout as the engine's `Slot`, with a stable opcode number.
pub const GpuSlot = extern struct { op: u8, rd: u8, rs1: u8, rs2: u8, target: u32, imm: u64 };
comptime {
    std.debug.assert(@sizeOf(GpuSlot) == 16);
}

fn gpuOp(name: []const u8) !u8 {
    for (OP_NAMES, 0..) |n, i| if (std.mem.eql(u8, n, name)) return @intCast(i);
    return error.M9UnknownEngineOp;
}

/// The engine's pre-decoded program as the GPU ROM (one slot per 4-byte code word).
pub fn exportRom(a: std.mem.Allocator, e: *const fast.Engine) ![]GpuSlot {
    const out = try a.alloc(GpuSlot, e.slots.len);
    errdefer a.free(out);
    for (e.slots, out) |s, *o| o.* = .{ .op = try gpuOp(@tagName(s.op)), .rd = s.rd, .rs1 = s.rs1, .rs2 = s.rs2, .target = s.target, .imm = s.imm };
    return out;
}

/// Per-segment recording (seeds, memory-before tape, host steps).
pub const SegmentTape = struct {
    allocator: std.mem.Allocator,
    chunk: u32,
    seeds: std.ArrayList(Seed) = .empty,
    memory: std.ArrayList(u64) = .empty,
    slow: std.ArrayList(SlowStep) = .empty,
    /// Absolute retirement count at the segment start / last seed.
    start: u64 = 0,
    last_seed: u64 = 0,
    code_lo: u64 = 0,
    /// ROM length (`Engine.slots.len`, including the trailing slow sentinel), the GPU's `slots`.
    slots: usize = 0,
    /// ROM slot of the pc after the segment's last step (`NO_SLOT` outside the table);
    /// the GPU checks the segment's last chunk against it. Set by `finish`.
    end_slot: u32 = NO_SLOT,

    pub fn init(a: std.mem.Allocator, chunk: u32) SegmentTape {
        return .{ .allocator = a, .chunk = @max(chunk, 1) };
    }
    pub fn deinit(self: *SegmentTape) void {
        self.seeds.deinit(self.allocator);
        self.memory.deinit(self.allocator);
        self.slow.deinit(self.allocator);
        self.* = undefined;
    }
    /// Begin a segment at `cpu` (absolute clock `cpu.retired`), at most `budget` steps.
    pub fn begin(self: *SegmentTape, e: *const fast.Engine, cpu: *const machine.Cpu, budget: u64) !void {
        self.code_lo = e.code_lo;
        self.slots = e.slots.len;
        self.end_slot = NO_SLOT;
        self.seeds.clearRetainingCapacity();
        self.memory.clearRetainingCapacity();
        self.slow.clearRetainingCapacity();
        self.start = cpu.retired;
        // Bounded by one word per step and one seed per chunk plus one per slow step;
        // reserve once so the hot loop appends without checks.
        try self.memory.ensureTotalCapacity(self.allocator, @intCast(budget));
        try self.seeds.ensureTotalCapacity(self.allocator, @intCast(budget / self.chunk + 64));
        self.seedAt(&cpu.regs, cpu.pc, cpu.retired);
    }
    inline fn seedAt(self: *SegmentTape, regs: *const [32]u64, pc: u64, retired: u64) void {
        var s = Seed{ .regs = regs.*, .pc = pc, .first_step = @intCast(retired - self.start), .steps = 0, .first_mem = @intCast(self.memory.items.len), .check_next = 0 };
        s.regs[0] = 0;
        self.seeds.appendAssumeCapacity(s);
        self.last_seed = retired;
    }
    /// Record one host-retired step (after it retired) and seed the state after it.
    pub fn hostStep(self: *SegmentTape, record: machine.Retirement, cpu: *const machine.Cpu) !void {
        const pos: u32 = @intCast(record.clock - 1 - self.start);
        var memory_index: u32 = compact_tape.NO_MEMORY;
        if (record.memory) |effect| {
            memory_index = @intCast(self.memory.items.len);
            try self.memory.append(self.allocator, effect.before_word.toInt());
        }
        try self.slow.append(self.allocator, .{ .pos = pos, .pc_slot = self.slot(record.pc.toInt()), .rd = if (record.writes_rd and record.rd != 0) record.rd else NO_RD, .step = .{ .next_pc = record.next_pc.toInt(), .lhs = record.lhs.toInt(), .rhs = record.rhs.toInt(), .previous_rd = record.previous_rd.toInt(), .result = record.result.toInt(), .memory_index = memory_index, .flags = @intFromBool(record.branch_taken) } });
        try self.seeds.ensureUnusedCapacity(self.allocator, 1);
        self.seedAt(&cpu.regs, cpu.pc, cpu.retired);
    }
    pub fn slot(self: *const SegmentTape, pc: u64) u32 {
        // Same rule as the GPU's end check: a slot index inside the exported ROM.
        if (pc < self.code_lo or pc & 3 != 0 or (pc - self.code_lo) / 4 >= self.slots) return NO_SLOT;
        return @intCast((pc - self.code_lo) / 4);
    }
    /// Close the segment at absolute clock `end` with the cpu at `end_pc`: fill chunk
    /// lengths, drop empty chunks. Every chunk ends at the next kept seed (`check_next`),
    /// at a host step (GPU checks `pc_slot`, memory cursor and registers) or at the segment end
    /// (GPU checks `end_slot` and the memory-tape length).
    pub fn finish(self: *SegmentTape, end: u64, end_pc: u64) void {
        self.end_slot = self.slot(end_pc);
        const total: u32 = @intCast(end - self.start);
        var j: usize = 0; // next slow step at or after the seed
        var w: usize = 0;
        const seeds = self.seeds.items;
        for (seeds, 0..) |seed, k| {
            while (j < self.slow.items.len and self.slow.items[j].pos < seed.first_step) j += 1;
            var stop = total;
            if (k + 1 < seeds.len) stop = @min(stop, seeds[k + 1].first_step);
            if (j < self.slow.items.len) stop = @min(stop, self.slow.items[j].pos);
            var s = seed;
            s.steps = stop - seed.first_step;
            s.check_next = 0;
            if (s.steps == 0) continue;
            seeds[w] = s;
            w += 1;
        }
        self.seeds.shrinkRetainingCapacity(w);
        // A chunk is continuity-checked against the next kept seed only when that seed
        // starts exactly where the chunk ends (no host step in between).
        const kept = self.seeds.items;
        for (kept[0..kept.len -| 1], kept[@min(1, kept.len)..]) |*s, next| {
            s.check_next = @intFromBool(next.first_step == s.first_step + s.steps);
        }
    }
    /// Structural check of a finished segment: chunks and host steps partition
    /// [0, total) in order, and every chunk end is a seed, a host step or the end.
    pub fn verifyPartition(self: *const SegmentTape, end: u64) error{M9BadPartition}!void {
        const total = end - self.start;
        var at: u64 = 0;
        var j: usize = 0;
        var k: usize = 0;
        const seeds = self.seeds.items;
        const slow = self.slow.items;
        while (at < total) {
            if (j < slow.len and slow[j].pos == at) {
                j += 1;
                at += 1;
            } else if (k < seeds.len and seeds[k].first_step == at and seeds[k].steps > 0) {
                at += seeds[k].steps;
                k += 1;
            } else return error.M9BadPartition;
        }
        if (at != total or j != slow.len or k != seeds.len) return error.M9BadPartition;
    }
};

inline fn fillPage(e: *fast.Engine, index: u64, write: bool) ?[*]u8 {
    // Mirrors the engine's private cold `fill` (same rights, dirty marks, tables).
    if (index >= e.rights.len) return null;
    const i: usize = @intCast(index);
    const need: u8 = if (write) 2 else 1;
    if (e.rights[i] & need == 0) return null;
    const page = e.memory.backing.peek(index) orelse return null;
    const base: [*]u8 = page;
    if (e.rights[i] & 1 != 0) e.rd_tab[i] = base;
    if (write) {
        e.dirty.mark(index);
        if (e.memory.backing.dirty) |d| if (d != &e.dirty) d.mark(index);
        e.wr_tab[i] = base;
    }
    return base;
}
noinline fn fillCold(e: *fast.Engine, index: u64, write: bool) ?[*]u8 {
    return fillPage(e, index, write);
}

/// `Engine.run` (no counting) that also records seeds and memory-before words into `t`.
/// Stops before any instruction `run` would stop before; near the step limit it can stop
/// a few steps earlier than `run` (whole blocks only), so those steps become host steps
/// (24628607: 5 of 26.9 M; 26235159: 18 of 204.8 M) [M]. Retired totals are identical.
pub fn runSeeded(e: *fast.Engine, cpu: *machine.Cpu, limit: u64, t: *SegmentTape) fast.Exit {
    if (cpu.retired >= limit) return .limit;
    const Slot = std.meta.Child(@TypeOf(e.slots));
    const Op = @FieldType(Slot, "op");
    if (cpu.pc < e.code_lo or cpu.pc >= e.code_hi or cpu.pc & 3 != 0) return .slow;
    var i: usize = @intCast((cpu.pc - e.code_lo) / 4);
    var r: [33]u64 = undefined;
    @memcpy(r[0..32], &cpu.regs);
    r[0] = 0;
    r[SINK] = 0;
    const slots = e.slots.ptr;
    const blen = e.blen.ptr;
    const rd_tab = e.rd_tab;
    const wr_tab = e.wr_tab;
    const code_lo = e.code_lo;
    const words = t.memory.items.ptr;
    var nwords = t.memory.items.len;
    std.debug.assert(t.memory.capacity - nwords >= limit - cpu.retired);
    const start = cpu.retired;
    var retired = start;
    var end: usize = i;
    sw: switch (@as(Op, .enter)) {
        .enter => {
            const n = blen[i];
            end = i;
            if (n == 0 or n > limit - retired) break :sw;
            if (retired - t.last_seed >= t.chunk and retired != t.last_seed) {
                if (t.seeds.items.len == t.seeds.capacity) break :sw; // caller reserves; never hit
                t.memory.items.len = nwords;
                t.seedAt(r[0..32], code_lo + 4 * @as(u64, i), retired);
            }
            retired += n;
            end = i + n;
            continue :sw slots[i].op;
        },
        .slow => break :sw,
        .nop => {
            i += 1;
            continue :sw slots[i].op;
        },
        .li => {
            r[slots[i].rd] = slots[i].imm;
            i += 1;
            continue :sw slots[i].op;
        },
        inline .add, .sub, .sll, .slt, .sltu, .xor, .srl, .sra, .@"or", .@"and", .addi, .slti, .sltiu, .xori, .ori, .andi, .slli, .srli, .srai, .addw, .subw, .sllw, .srlw, .sraw, .addiw, .slliw, .srliw, .sraiw, .mul, .mulh, .mulhsu, .mulhu, .div, .divu, .rem, .remu, .mulw, .divw, .divuw, .remw, .remuw, .andn, .orn, .xnor, .rev8, .sext_b, .sext_h, .zext_h => |op| {
            const s = slots[i];
            r[s.rd] = alu(@tagName(op), r[s.rs1], r[s.rs2], s.imm);
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
            const base = (if (index < rd_tab.len) rd_tab[@intCast(index)] else null) orelse fillCold(e, index, false) orelse break :sw;
            const offset: usize = @intCast(address & (mem.PAGE_SIZE - 1));
            const word = std.mem.readInt(u64, base[offset & ~@as(usize, 7) ..][0..8], .little);
            words[nwords] = word;
            nwords += 1;
            const raw: T = @truncate(word >> @intCast((offset & 7) * 8));
            r[s.rd] = switch (op) {
                .lb => @bitCast(@as(i64, @as(i8, @bitCast(raw)))),
                .lh => @bitCast(@as(i64, @as(i16, @bitCast(raw)))),
                .lw => @bitCast(@as(i64, @as(i32, @bitCast(raw)))),
                else => raw,
            };
            r[SINK] = 0;
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
            const base = (if (index < wr_tab.len) wr_tab[@intCast(index)] else null) orelse fillCold(e, index, true) orelse break :sw;
            const offset: usize = @intCast(address & (mem.PAGE_SIZE - 1));
            words[nwords] = std.mem.readInt(u64, base[offset & ~@as(usize, 7) ..][0..8], .little);
            nwords += 1;
            std.mem.writeInt(T, base[offset..][0..@sizeOf(T)], @truncate(r[s.rs2]), .little);
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
            r[SINK] = 0;
            i = s.target;
            continue :sw .enter;
        },
        .jalr => {
            const s = slots[i];
            const target = (r[s.rs1] +% s.imm) & ~@as(u64, 1);
            if (target & 3 != 0 or target < code_lo or target >= e.code_hi) break :sw;
            r[s.rd] = code_lo + 4 * @as(u64, i) + 4;
            r[SINK] = 0;
            i = @intCast((target - code_lo) / 4);
            continue :sw .enter;
        },
    }
    t.memory.items.len = nwords;
    retired -= end - i;
    if (retired != start) {
        @memcpy(&cpu.regs, r[0..32]);
        cpu.regs[0] = 0;
        cpu.pc = code_lo + 4 * @as(u64, i);
        cpu.retired = retired;
        e.fast_retired += retired - start;
    }
    return if (retired == limit) .limit else .slow;
}

inline fn alu(comptime op: []const u8, a: u64, b: u64, imm: u64) u64 {
    @setEvalBranchQuota(100_000);
    const sa: i64 = @bitCast(a);
    const sb: i64 = @bitCast(b);
    const aw: u32 = @truncate(a);
    const bw: u32 = @truncate(b);
    const sext32 = machine.sext32;
    const eq = std.mem.eql;
    if (comptime eq(u8, op, "add")) return a +% b;
    if (comptime eq(u8, op, "sub")) return a -% b;
    if (comptime eq(u8, op, "addi")) return a +% imm;
    if (comptime eq(u8, op, "slt")) return @intFromBool(sa < sb);
    if (comptime eq(u8, op, "sltu")) return @intFromBool(a < b);
    if (comptime eq(u8, op, "slti")) return @intFromBool(sa < @as(i64, @bitCast(imm)));
    if (comptime eq(u8, op, "sltiu")) return @intFromBool(a < imm);
    if (comptime eq(u8, op, "and")) return a & b;
    if (comptime eq(u8, op, "or")) return a | b;
    if (comptime eq(u8, op, "xor")) return a ^ b;
    if (comptime eq(u8, op, "andi")) return a & imm;
    if (comptime eq(u8, op, "ori")) return a | imm;
    if (comptime eq(u8, op, "xori")) return a ^ imm;
    if (comptime eq(u8, op, "sll")) return a << @as(u6, @truncate(b));
    if (comptime eq(u8, op, "srl")) return a >> @as(u6, @truncate(b));
    if (comptime eq(u8, op, "sra")) return @bitCast(sa >> @as(u6, @truncate(b)));
    if (comptime eq(u8, op, "slli")) return a << @as(u6, @truncate(imm));
    if (comptime eq(u8, op, "srli")) return a >> @as(u6, @truncate(imm));
    if (comptime eq(u8, op, "srai")) return @bitCast(sa >> @as(u6, @truncate(imm)));
    if (comptime eq(u8, op, "addw")) return sext32(aw +% bw);
    if (comptime eq(u8, op, "subw")) return sext32(aw -% bw);
    if (comptime eq(u8, op, "addiw")) return sext32(aw +% @as(u32, @truncate(imm)));
    if (comptime eq(u8, op, "sllw")) return sext32(aw << @as(u5, @truncate(b)));
    if (comptime eq(u8, op, "srlw")) return sext32(aw >> @as(u5, @truncate(b)));
    if (comptime eq(u8, op, "sraw")) return sext32(@bitCast(@as(i32, @bitCast(aw)) >> @as(u5, @truncate(b))));
    if (comptime eq(u8, op, "slliw")) return sext32(aw << @as(u5, @truncate(imm)));
    if (comptime eq(u8, op, "srliw")) return sext32(aw >> @as(u5, @truncate(imm)));
    if (comptime eq(u8, op, "sraiw")) return sext32(@bitCast(@as(i32, @bitCast(aw)) >> @as(u5, @truncate(imm))));
    if (comptime eq(u8, op, "mul")) return a *% b;
    if (comptime eq(u8, op, "mulhu")) return @intCast((@as(u128, a) * b) >> 64);
    if (comptime eq(u8, op, "mulh")) return @truncate(@as(u128, @bitCast(@as(i128, sa) * sb)) >> 64);
    if (comptime eq(u8, op, "mulhsu")) return @truncate(@as(u128, @bitCast(@as(i128, sa) * @as(i128, b))) >> 64);
    if (comptime eq(u8, op, "mulw")) return sext32(aw *% bw);
    if (comptime eq(u8, op, "div")) return machine.divSigned64(sa, sb, false);
    if (comptime eq(u8, op, "rem")) return machine.divSigned64(sa, sb, true);
    if (comptime eq(u8, op, "divu")) return if (b == 0) std.math.maxInt(u64) else a / b;
    if (comptime eq(u8, op, "remu")) return if (b == 0) a else a % b;
    if (comptime eq(u8, op, "divw")) return sext32(machine.divSigned32(@bitCast(aw), @bitCast(bw), false));
    if (comptime eq(u8, op, "remw")) return sext32(machine.divSigned32(@bitCast(aw), @bitCast(bw), true));
    if (comptime eq(u8, op, "divuw")) return sext32(if (bw == 0) std.math.maxInt(u32) else aw / bw);
    if (comptime eq(u8, op, "remuw")) return sext32(if (bw == 0) aw else aw % bw);
    if (comptime eq(u8, op, "andn")) return a & ~b;
    if (comptime eq(u8, op, "orn")) return a | ~b;
    if (comptime eq(u8, op, "xnor")) return ~(a ^ b);
    if (comptime eq(u8, op, "rev8")) return @byteSwap(a);
    if (comptime eq(u8, op, "sext_b")) return @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(a))))));
    if (comptime eq(u8, op, "sext_h")) return @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(a))))));
    if (comptime eq(u8, op, "zext_h")) return a & 0xffff;
    @compileError("not an ALU op: " ++ op);
}
