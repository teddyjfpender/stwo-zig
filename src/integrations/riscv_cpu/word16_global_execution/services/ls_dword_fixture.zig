//! ethereum_services_v3 LS-D64 fixture: a real v3 executor tape of mixed
//! loads/stores in two CPU shards sharing one global RAM chain. With the
//! LS-D64 component present, every LD/SD of a shard is its row and the core
//! LS32 instances take the LB/LBU/SW/SH rows.
//!
//! Shard 0 (epoch 1): SD, LD, SD, LB, SW, LD (negative offset), ADDI.
//! Shard 1 (epoch 2): LD (reads shard 0's SW word), LBU, SD, LD, SH, LD, ADDI.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const rv = front.rv64;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const T = @import("types.zig");

pub const BASE: u64 = 0x8000000000002000;
pub const SIZE: u64 = 0x100;
const X6: u64 = BASE + 0x40;
const X11: u64 = BASE + 0x80;

fn load(f3: u32, rd: u32, rs1: u32, imm: i12) u32 {
    return (@as(u32, @as(u12, @bitCast(imm))) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | 0x03;
}
fn addi(rd: u32, rs1: u32, imm: u12) u32 {
    return (@as(u32, imm) << 20) | (rs1 << 15) | (rd << 7) | 0x13;
}
fn store(f3: u32, rs2: u32, rs1: u32, imm: i12) u32 {
    const u: u32 = @as(u12, @bitCast(imm));
    return ((u >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((u & 31) << 7) | 0x23;
}
/// Shard 1 then runs EXTRA alternating SD/LD so its dword rows overflow a
/// log5 head (31 rows) into a tail instance.
const EXTRA = 34;
pub const WORDS = BASE_WORDS ++ extra();
fn extra() [EXTRA]u32 {
    var out: [EXTRA]u32 = undefined;
    for (&out, 0..) |*w, i| {
        const off: i12 = @intCast(8 * (i % 16));
        w.* = if (i % 2 == 0) store(3, 5, 6, off) else load(3, 17, 6, off);
    }
    return out;
}
const BASE_WORDS = [_]u32{
    // shard 0
    store(3, 5, 6, 0), // SD x5, 0(x6)
    load(3, 7, 6, 0), // LD x7, 0(x6)
    store(3, 7, 6, 8), // SD x7, 8(x6)
    load(0, 8, 6, 3), // LB x8, 3(x6)
    store(2, 5, 6, 16), // SW x5, 16(x6)
    load(3, 9, 11, -8), // LD x9, -8(x11)
    addi(15, 5, 1), // a non-LS step (count headroom for double_consume)
    // shard 1
    load(3, 12, 6, 16), // LD x12, 16(x6)
    load(4, 10, 6, 9), // LBU x10, 9(x6)
    store(3, 10, 6, 24), // SD x10, 24(x6)
    load(3, 13, 6, 8), // LD x13, 8(x6)
    store(1, 5, 6, 2), // SH x5, 2(x6)
    load(3, 14, 6, 0), // LD x14, 0(x6)
    addi(16, 5, 2),
};
pub const SHARD0_STEPS: u32 = 7;
pub const STEPS: u32 = WORDS.len;
/// Per shard LD/SD rows (LS-D64) and other LS rows (LS32).
pub const DWORD_ROWS = [2]u32{ 4, 4 + EXTRA };
pub const GENERAL_ROWS = [2]u32{ 2, 2 };
pub const CPU_LOG: u32 = 6;
pub const BOUNDARY_LOG: u32 = 6;
const marker: u8 = 0;

fn initialWord(address: u64) u64 {
    return address *% 0x9E3779B97F4A7C15;
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < BASE or address >= BASE + SIZE or address & 7 != 0) return error.UntrustedDwordFixtureAddress;
    return initialWord(address);
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < BASE or address >= BASE + SIZE) return error.UntrustedDwordFixtureAddress;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
pub fn initialRegisters() [32]u64 {
    var r: [32]u64 = @splat(0);
    r[5] = 0x0123456789abcdef;
    r[6] = X6;
    r[11] = X11;
    return r;
}
pub fn expectedFor(identity: [32]u8, final: [32]u64) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x4c), .initial_pc = 4096, .initial_registers = initialRegisters(), .max_prefix_steps = 63 }, .program_identity = identity, .total_steps = STEPS, .max_total_steps = STEPS, .final_pc = 4096 + 4 * STEPS, .final_registers = final };
}

pub const Captured = struct {
    allocator: std.mem.Allocator,
    program: *Program,
    tapes: [2]rv.compact_tape.Tape,
    native: [2]Native,
    advice: C.Advice,
    final: [32]u64,
    pub fn init(a: std.mem.Allocator) !Captured {
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.init(a, .{ .base = 4096, .words = &WORDS });
        errdefer program.deinit();
        var memory = rv.memory.Memory.init(a, .{});
        defer memory.deinit();
        try memory.map(.{ .start = 4096, .size = 4 * WORDS.len, .permissions = .{ .read = true, .execute = true } });
        try memory.map(.{ .start = BASE, .size = SIZE, .permissions = .{ .read = true, .write = true } });
        for (WORDS, 0..) |word, i| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try memory.initialize(4096 + 4 * i, &bytes);
        }
        var address = BASE;
        while (address < BASE + SIZE) : (address += 8) {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, initialWord(address), .little);
            try memory.initialize(address, &bytes);
        }
        var cpu = rv.machine.Cpu.init(4096, 0);
        cpu.regs = initialRegisters();
        var session = try rv.ethereum_services.Session.initWithProfile(a, cpu, &memory, .{ .max_retirements = 128 }, .ethereum_services_v3);
        defer session.deinit();
        const sizes = [2]u32{ SHARD0_STEPS, STEPS - SHARD0_STEPS };
        var tapes: [2]rv.compact_tape.Tape = undefined;
        var boundaries: [2]A.word16_execution.types.Boundary = undefined;
        var made: usize = 0;
        errdefer for (tapes[0..made]) |*t| t.deinit();
        for (sizes, &tapes, &boundaries) |steps, *tape, *boundary| {
            const c = &session.keccak.base.cpu;
            tape.* = try rv.compact_tape.Tape.init(a, steps, c.pc, c.retired, .ethereum_services_v3);
            made += 1;
            boundary.* = .{ .steps = steps, .initial_pc = c.pc, .final_pc = undefined, .initial_registers = c.regs, .final_registers = undefined, .register_clocks = @splat(0) };
            for (0..steps) |local| {
                var event: rv.ethereum_services.Event = undefined;
                const record = if (try session.step(&event)) |row| blk: {
                    try tape.append(row);
                    break :blk row;
                } else blk: {
                    try tape.appendEvent(event);
                    break :blk event.retirement();
                };
                const effects = rv.execution_profile.effects(.ethereum_services_v2, record.opcode);
                const tick: u32 = @intCast(4 * local);
                if (effects.reads_rs1 and record.rs1 != 0) boundary.register_clocks[record.rs1] = tick + 1;
                if (effects.reads_rs2 and record.rs2 != 0) boundary.register_clocks[record.rs2] = tick + 2;
                if (effects.writes_rd and record.rd != 0) boundary.register_clocks[record.rd] = tick + 3;
            }
            boundary.final_pc = c.pc;
            boundary.final_registers = c.regs;
        }
        const final = session.keccak.base.cpu.regs;
        var n0 = try Native.captureForCombinedServicesV3(a, program, boundaries[0], 1, CPU_LOG, &tapes[0], .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, boundaries[1], 2, CPU_LOG, &tapes[1], .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &tapes[0], &tapes[1] }, image());
        errdefer advice.deinit();
        for (advice.events, DWORD_ROWS, GENERAL_ROWS) |events, d, g| {
            if (@import("pipeline.zig").dwordCount(events) != d or events.len != d + g) return error.InvalidDwordFixtureChronology;
        }
        return .{ .allocator = a, .program = program, .tapes = tapes, .native = .{ n0, n1 }, .advice = advice, .final = final };
    }
    pub fn deinit(self: *Captured) void {
        self.advice.deinit();
        for (&self.native) |*n| n.deinit();
        for (&self.tapes) |*t| t.deinit();
        self.program.deinit();
        self.allocator.destroy(self.program);
    }
};

pub const Case = struct {
    allocator: std.mem.Allocator,
    setups: [2]*R.CpuSetup,
    final: [32]u64,
    bundle: E.Bundle,
    /// Locally valid but false LS witnesses that only the closures reject:
    /// lb_as_dword (OWNER: an LB executed by the CPU consumed as an LD row),
    /// double_consume (OWNER: one LD tuple consumed by two LS-D64 rows),
    /// shifted_base (OWNER: A+4 with the immediate 4 lower, same aligned EA),
    /// ram_predecessor (RAM: an LD claims a predecessor clock never written).
    pub const Mutation = enum { none, lb_as_dword, double_consume, shifted_base, ram_predecessor };
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity, self.final);
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    pub fn init(a: std.mem.Allocator, bridges: [2]T.Logs, mutation: Mutation) !Case {
        return initLayout(a, bridges, mutation, false);
    }
    /// `all_fused`: every opt-in fused/byte-pair layout flag on (CPU, MUL,
    /// LS32/INIT/TEARDOWN, ALU, LS-D64).
    pub fn initLayout(a: std.mem.Allocator, bridges: [2]T.Logs, mutation: Mutation, all_fused: bool) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        try mutate(a, &captured.advice, mutation);
        var setups: [2]*R.CpuSetup = undefined;
        var made: usize = 0;
        errdefer for (setups[0..made]) |s| {
            s.deinit();
            a.destroy(s);
        };
        for (&setups, bridges, captured.native) |*out, b, native| {
            const s = try a.create(R.CpuSetup);
            errdefer a.destroy(s);
            var geometry = try native.geometry();
            geometry.initial_log = BOUNDARY_LOG;
            geometry.terminal_log = BOUNDARY_LOG;
            if (all_fused) setAllFused(&geometry);
            s.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, geometry, b);
            out.* = s;
            made += 1;
        }
        // A forged extra row needs the census hint of the forged event list.
        if (mutation == .double_consume) captured.native[0].raw_counts.memory += 1;
        const bundle = try E.produce(a, &.{ setups[0], setups[1] }, &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity, captured.final));
        return .{ .allocator = a, .setups = setups, .final = captured.final, .bundle = bundle };
    }
};
fn find(events: []const A.memory.load_store_v2.native.Event, opcode: rv.decode.Opcode) usize {
    for (events, 0..) |e, i| if (e.opcode == opcode) return i;
    unreachable;
}
fn mutate(a: std.mem.Allocator, advice: *C.Advice, mutation: Case.Mutation) !void {
    const events = advice.events[0];
    switch (mutation) {
        .none => {},
        .lb_as_dword => {
            const i = find(events, .LB);
            const e = &events[i];
            e.opcode = .LD;
            e.immediate &= ~@as(u64, 7);
            e.c = e.before.value;
        },
        .double_consume => {
            const i = find(events, .LD);
            const grown = try a.alloc(A.memory.load_store_v2.native.Event, events.len + 1);
            @memcpy(grown[0..events.len], events);
            grown[events.len] = events[i];
            a.free(events);
            advice.events[0] = grown;
        },
        .shifted_base => {
            const i = find(events, .LD);
            events[i].a +%= 4;
            events[i].immediate -%= 4;
        },
        .ram_predecessor => {
            // The first LD of shard 0 reads the word SD wrote in epoch 1;
            // claim the initial-image clock (epoch 0, tick 0) for that value.
            const i = find(events, .LD);
            if (events[i].before.epoch != 1) return error.InvalidDwordFixtureChronology;
            events[i].before.epoch = 0;
            events[i].before.tick = 0;
        },
    }
}
pub fn setAllFused(g: anytype) void {
    g.cpu_fused_tail = true;
    g.cpu_u8_pairs = true;
    g.mul_u8_pairs = true;
    g.ls_fused_pairs = true;
    g.alu_fused_tail = true;
    g.ls_dword_fused_pairs = true;
}
