//! Two v3 shards per curve/field op: SD, call, call | SD, call on one
//! cross-page inline packet at 0x8000000000000fe0. The SD stores zero into a
//! read-only input limb (keeping every precondition), the second call re-reads
//! the outputs the first one wrote in place, and shard 1 re-reads the packet
//! across the epoch boundary.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const CR = @import("../curves/roster.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const T = @import("types.zig");
const Curves = front.rv64.ethereum_services.curves;
pub const Op = Curves.Op;
pub const ADDRESS: u64 = 0x8000000000000fe0;
pub const LOG: u32 = A.crypto.curves.layout.MIN_LOG;
const marker: u8 = 0;

/// Input limb (word index) zeroed by each shard's SD: a low limb of the last
/// read-only input (or the arith384_mont padding).
pub fn storedWords(op: Op) [2]u32 {
    return switch (op) {
        .bn254_g1_add, .bn254_fp2_mul => .{ 12, 13 },
        .bn254_g1_double => .{ 5, 6 },
        .bls12_381_fp2_mul, .bls12_381_g1_add => .{ 18, 19 },
        .arith384_mont => .{ 18, 19 },
        .bls12_381_g1_double => .{ 6, 7 },
    };
}
fn sd(word: u32) u32 {
    const off = 8 * word;
    return ((off >> 5) << 25) | (10 << 15) | (3 << 12) | ((off & 31) << 7) | 0x23;
}
/// sd x0,8w0(a0); ecall; ecall | sd x0,8w1(a0); ecall
const CODE = blk: {
    var out: [Curves.COUNT][5]u32 = undefined;
    for (Curves.ALL, &out) |op, *c| {
        const w = storedWords(op);
        c.* = .{ sd(w[0]), 0x73, 0x73, sd(w[1]), 0x73 };
    }
    break :blk out;
};
pub fn words(op: Op) *const [5]u32 {
    return &CODE[Curves.index(op)];
}
/// Deterministic operands satisfying the preconditions: canonical values
/// (top limb masked below the modulus' top limb), m odd, distinct x.
pub fn initialWords(op: Op) [Curves.MAX_WORDS]u64 {
    var out: [Curves.MAX_WORDS]u64 = @splat(0);
    const n = Curves.words(op);
    for (out[0..n], 0..) |*w, i| w.* = 0x9e3779b97f4a7c15 *% (i + 1) ^ 0xd1b54a32d192ed03 ^ (@as(u64, @intFromEnum(op)) << 40);
    const limbs: usize = if (@intFromEnum(op) <= 7) 4 else 6;
    for (0..@min(4, n / limbs)) |v| out[v * limbs + limbs - 1] &= if (limbs == 4) 0x0fffffffffffffff else 0x0fffffffffffffff >> 4;
    if (op == .arith384_mont) out[12] |= 1;
    return out;
}
fn initial(context: *const anyopaque, address: u64) !u64 {
    const op: Op = @enumFromInt(@as(*const u8, @ptrCast(context)).*);
    if (address < ADDRESS or address >= ADDRESS + 8 * Curves.words(op) or address & 7 != 0) return error.UntrustedCurveAddress;
    return initialWords(op)[(address - ADDRESS) / 8];
}
fn rights(context: *const anyopaque, address: u64) !u2 {
    const op: Op = @enumFromInt(@as(*const u8, @ptrCast(context)).*);
    if (address < ADDRESS or address >= ADDRESS + 8 * Curves.words(op)) return error.UntrustedCurveAddress;
    return 3;
}
const op_bytes = blk: {
    var out: [Curves.COUNT]u8 = undefined;
    for (Curves.ALL, &out) |op, *b| b.* = @intFromEnum(op);
    break :blk out;
};
pub fn image(op: Op) @import("../../word16_execution/memory/statement.zig").Image {
    _ = marker;
    return .{ .context = &op_bytes[Curves.index(op)], .initial_word = initial, .rights_at = rights };
}
fn regs(op: Op) [32]u64 {
    var r: [32]u64 = @splat(0);
    r[10] = ADDRESS;
    r[17] = Curves.tag(op);
    return r;
}
pub fn expectedFor(op: Op, identity: [32]u8) P.Expected {
    return .{ .admission = .{ .image = image(op), .image_identity = @splat(0x4e), .initial_pc = 4096, .initial_registers = regs(op), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 5, .max_total_steps = 5, .final_pc = 4116, .final_registers = regs(op) };
}
pub fn call(op: Op, id: u64, clock: u64, pc: u64, before: [Curves.MAX_WORDS]u64) !front.rv64.ethereum_services.CurveCall {
    const after = try Curves.execute(op, before[0..Curves.words(op)]);
    return .{ .op = op, .call_id = id, .clock = clock, .pc = pc, .pointer = ADDRESS, .before = before, .after = after };
}
pub const Captured = struct {
    allocator: std.mem.Allocator,
    op: Op,
    program: *Program,
    words: *const [5]u32,
    tapes: [2]front.rv64.compact_tape.Tape,
    native: [2]Native,
    advice: C.Advice,
    pub fn init(a: std.mem.Allocator, op: Op) !Captured {
        const program = try a.create(Program);
        errdefer a.destroy(program);
        const code = words(op);
        program.* = try Program.init(a, .{ .base = 4096, .words = code });
        errdefer program.deinit();
        const stored = storedWords(op);
        var t0 = try front.rv64.compact_tape.Tape.init(a, 3, 4096, 0, .ethereum_services_v3);
        errdefer t0.deinit();
        var t1 = try front.rv64.compact_tape.Tape.init(a, 2, 4108, 3, .ethereum_services_v3);
        errdefer t1.deinit();
        var packet = initialWords(op);
        t0.storage[0] = .{ .next_pc = 4100, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try t0.memory_before.append(a, packet[stored[0]]);
        t0.len = 1;
        packet[stored[0]] = 0;
        const c1 = try call(op, 1, 2, 4100, packet);
        try t0.appendCurve(c1);
        const c2 = try call(op, 2, 3, 4104, c1.after);
        try t0.appendCurve(c2);
        t1.storage[0] = .{ .next_pc = 4112, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try t1.memory_before.append(a, c2.after[stored[1]]);
        t1.len = 1;
        packet = c2.after;
        packet[stored[1]] = 0;
        try t1.appendCurve(try call(op, 3, 5, 4112, packet));
        var p0: A.word16_execution.types.Boundary = .{ .steps = 3, .initial_pc = 4096, .final_pc = 4108, .initial_registers = regs(op), .final_registers = regs(op), .register_clocks = @splat(0) };
        p0.register_clocks[10] = 9;
        p0.register_clocks[17] = 10;
        var p1: A.word16_execution.types.Boundary = .{ .steps = 2, .initial_pc = 4108, .final_pc = 4116, .initial_registers = regs(op), .final_registers = regs(op), .register_clocks = @splat(0) };
        p1.register_clocks[10] = 5;
        p1.register_clocks[17] = 6;
        var n0 = try Native.captureForCombinedServicesV3(a, program, p0, 1, 5, &t0, .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, p1, 2, 5, &t1, .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &t0, &t1 }, image(op));
        errdefer advice.deinit();
        const k = Curves.index(op);
        if (advice.initial.len != Curves.words(op) or advice.curves[0][k].len != 2 or advice.curves[1][k].len != 1 or advice.curves[1][k][0].predecessors[stored[1]].epoch != 2 or advice.curves[1][k][0].predecessors[0].epoch != 1) return error.InvalidCurveFixtureChronology;
        return .{ .allocator = a, .op = op, .program = program, .words = code, .tapes = .{ t0, t1 }, .native = .{ n0, n1 }, .advice = advice };
    }
    pub fn deinit(self: *Captured) void {
        self.advice.deinit();
        for (&self.native) |*n| n.deinit();
        for (&self.tapes) |*t| t.deinit();
        self.program.deinit();
        self.allocator.destroy(self.program);
    }
};
pub fn bridges(op: Op) T.Logs {
    var logs = T.Logs{};
    logs.set(T.curveFamily(op), 5);
    return logs;
}
pub const Case = struct {
    allocator: std.mem.Allocator,
    op: Op,
    words: *const [5]u32,
    setups: [2]*R.CpuSetup,
    truth: *CR.TruthSetup,
    /// Two spans (calls 1..2 and 3) when true, one span of three otherwise.
    split: bool,
    bundle: E.Bundle,
    /// wrong_output: a locally valid bridge publishes an output the truth
    /// never produced. forged_input: a consistent bridge/truth pair over an
    /// input word RAM never held. wrong_pointer: the bridge reads 32 bytes on.
    pub const Mutation = enum { none, wrong_output, forged_input, wrong_pointer };
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn truths(self: *const Case, out: *[2]R.Truth) []const R.Truth {
        return truthsFor(self.truth, self.split, out);
    }
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.op, self.setups[0].materials.program.identity);
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        self.truth.deinit();
        self.allocator.destroy(self.truth);
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    fn setTerminal(advice: *C.Advice, after: []const u64) void {
        for (advice.terminal) |*cell| {
            const offset = cell.address -% ADDRESS;
            if (offset < 8 * after.len) cell.state.value = after[offset / 8];
        }
    }
    pub fn init(a: std.mem.Allocator, op: Op, mutation: Mutation, split: bool) !Case {
        var captured = try Captured.init(a, op);
        defer captured.deinit();
        const k = Curves.index(op);
        const n = Curves.words(op);
        switch (mutation) {
            .none => {},
            .wrong_output => {
                captured.advice.curves[1][k][0].after[0] ^= 1;
                setTerminal(&captured.advice, captured.advice.curves[1][k][0].after[0..n]);
            },
            .forged_input => {
                const c = &captured.advice.curves[1][k][0];
                const w = storedWords(op)[0];
                c.before[w] ^= 2;
                c.predecessors[w].value ^= 2;
                c.after = try Curves.execute(op, c.before[0..n]);
                setTerminal(&captured.advice, c.after[0..n]);
            },
            .wrong_pointer => captured.advice.curves[0][k][0].pointer += 32,
        }
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = captured.words }, try captured.native[0].geometry(), bridges(op));
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = captured.words }, try captured.native[1].geometry(), bridges(op));
        errdefer s1.deinit();
        const t = try a.create(CR.TruthSetup);
        errdefer a.destroy(t);
        t.* = try CR.TruthSetup.init(a, op, LOG);
        errdefer t.deinit();
        var buffer: [2]R.Truth = undefined;
        const bundle = try E.produce(a, &.{ s0, s1 }, truthsFor(t, split, &buffer), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(op, captured.program.identity));
        return .{ .allocator = a, .op = op, .words = captured.words, .setups = .{ s0, s1 }, .truth = t, .split = split, .bundle = bundle };
    }
};
pub fn truthsFor(setup: *const CR.TruthSetup, split: bool, out: *[2]R.Truth) []const R.Truth {
    if (split) {
        out.* = .{ .{ .curve = .{ .setup = setup, .first_id = 1, .calls = 2 } }, .{ .curve = .{ .setup = setup, .first_id = 3, .calls = 1 } } };
        return out;
    }
    out[0] = .{ .curve = .{ .setup = setup, .first_id = 1, .calls = 3 } };
    return out[0..1];
}
