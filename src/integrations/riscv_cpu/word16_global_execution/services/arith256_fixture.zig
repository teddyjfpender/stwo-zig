//! Two v3 shards: SD, arith256_mod, arith256_mod | SD, arith256_mod on one
//! cross-page 160-byte packet. The first store changes c, the second call
//! re-reads the r the first one wrote, and the last store zeroes m so the
//! final call exercises the m = 0 rule (r = 0).
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const AR = @import("../arith256/roster.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const Arith = front.rv64.ethereum_services.arith256;
pub const ADDRESS: u64 = 0x8000000000000fe0;
pub const TAG: u64 = 0x30021;
pub const LOG: u32 = A.crypto.arith256.layout.MIN_LOG;
/// sd x0,64(a0); ecall; ecall | sd x0,120(a0); ecall
pub const WORDS = [_]u32{ 0x04053023, 0x73, 0x73, 0x06053c23, 0x73 };
const marker: u8 = 0;
/// a, b, c: 256-bit values; m: only its top limb is nonzero (BN254's top
/// word), so the shard-1 store of limb 3 makes m = 0; r slot: garbage.
pub fn initialWords() [20]u64 {
    var out: [20]u64 = undefined;
    for (out[0..12], 0..) |*w, i| w.* = 0x9e3779b97f4a7c15 *% (i + 1) ^ 0xd1b54a32d192ed03;
    out[12..16].* = .{ 0, 0, 0, 0x30644e72e131a029 };
    for (out[16..20], 0..) |*w, i| w.* = 0xa5a5a5a500000000 + i;
    return out;
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < ADDRESS or address >= ADDRESS + 160 or address & 7 != 0) return error.UntrustedArith256Address;
    return initialWords()[(address - ADDRESS) / 8];
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address >= ADDRESS + 160) return error.UntrustedArith256Address;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
fn regs() [32]u64 {
    var r: [32]u64 = @splat(0);
    r[10] = ADDRESS;
    r[17] = TAG;
    return r;
}
pub fn expectedFor(identity: [32]u8) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x4d), .initial_pc = 4096, .initial_registers = regs(), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 5, .max_total_steps = 5, .final_pc = 4116, .final_registers = regs() };
}
pub fn call(id: u64, clock: u64, pc: u64, before: [20]u64) front.rv64.ethereum_services.Arith256ModCall {
    var after = before;
    after[16..20].* = Arith.mulAddModPacket(before);
    return .{ .call_id = id, .clock = clock, .pc = pc, .pointer = ADDRESS, .before = before, .after = after };
}
pub const Captured = struct {
    allocator: std.mem.Allocator,
    program: *Program,
    tapes: [2]front.rv64.compact_tape.Tape,
    native: [2]Native,
    advice: C.Advice,
    pub fn init(a: std.mem.Allocator) !Captured {
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.init(a, .{ .base = 4096, .words = &WORDS });
        errdefer program.deinit();
        var t0 = try front.rv64.compact_tape.Tape.init(a, 3, 4096, 0, .ethereum_services_v3);
        errdefer t0.deinit();
        var t1 = try front.rv64.compact_tape.Tape.init(a, 2, 4108, 3, .ethereum_services_v3);
        errdefer t1.deinit();
        var packet = initialWords();
        t0.storage[0] = .{ .next_pc = 4100, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try t0.memory_before.append(a, packet[8]);
        t0.len = 1;
        packet[8] = 0;
        const c1 = call(1, 2, 4100, packet);
        try t0.appendArith256Mod(c1);
        const c2 = call(2, 3, 4104, c1.after);
        try t0.appendArith256Mod(c2);
        t1.storage[0] = .{ .next_pc = 4112, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try t1.memory_before.append(a, c2.after[15]);
        t1.len = 1;
        packet = c2.after;
        packet[15] = 0;
        try t1.appendArith256Mod(call(3, 5, 4112, packet));
        var p0: A.word16_execution.types.Boundary = .{ .steps = 3, .initial_pc = 4096, .final_pc = 4108, .initial_registers = regs(), .final_registers = regs(), .register_clocks = @splat(0) };
        p0.register_clocks[10] = 9;
        p0.register_clocks[17] = 10;
        var p1: A.word16_execution.types.Boundary = .{ .steps = 2, .initial_pc = 4108, .final_pc = 4116, .initial_registers = regs(), .final_registers = regs(), .register_clocks = @splat(0) };
        p1.register_clocks[10] = 5;
        p1.register_clocks[17] = 6;
        var n0 = try Native.captureForCombinedServicesV3(a, program, p0, 1, 5, &t0, .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, p1, 2, 5, &t1, .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &t0, &t1 }, image());
        errdefer advice.deinit();
        if (advice.initial.len != 20 or advice.arith256_mod[0].len != 2 or advice.arith256_mod[1].len != 1 or advice.arith256_mod[1][0].predecessors[15].epoch != 2 or advice.arith256_mod[1][0].predecessors[0].epoch != 1) return error.InvalidArith256FixtureChronology;
        return .{ .allocator = a, .program = program, .tapes = .{ t0, t1 }, .native = .{ n0, n1 }, .advice = advice };
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
    truth: *AR.TruthSetup,
    /// Two spans (calls 1..2 and 3) when true, one span of three otherwise.
    split: bool,
    bundle: E.Bundle,
    /// wrong_output: a locally valid bridge publishes an r the truth never
    /// produced. zero_modulus_r: the m = 0 call claims r = 1. forged_input: a
    /// consistent bridge/truth pair over a c word RAM never held.
    pub const Mutation = enum { none, wrong_output, zero_modulus_r, forged_input, wrong_pointer };
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn truths(self: *const Case, out: *[2]R.Truth) []const R.Truth {
        return truthsFor(self.truth, self.split, out);
    }
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity);
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
            if (offset < 160) cell.state.value = after[offset / 8];
        }
    }
    pub fn init(a: std.mem.Allocator, mutation: Mutation, split: bool) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        switch (mutation) {
            .none => {},
            .wrong_output => {
                captured.advice.arith256_mod[1][0].after[16] ^= 1;
                setTerminal(&captured.advice, &captured.advice.arith256_mod[1][0].after);
            },
            .zero_modulus_r => {
                const c = &captured.advice.arith256_mod[1][0];
                if (Arith.limbs(c.before[12..16]) != 0) return error.InvalidArith256Fixture;
                c.after[16..20].* = .{ 1, 0, 0, 0 };
                setTerminal(&captured.advice, &c.after);
            },
            .forged_input => {
                const c = &captured.advice.arith256_mod[1][0];
                c.before[9] ^= 1;
                c.predecessors[9].value ^= 1;
                c.after = c.before;
                c.after[16..20].* = Arith.mulAddModPacket(c.before[0..20].*);
                setTerminal(&captured.advice, &c.after);
            },
            .wrong_pointer => captured.advice.arith256_mod[0][0].pointer += 32,
        }
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[0].geometry(), .{ .arith256_mod = 5 });
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[1].geometry(), .{ .arith256_mod = 5 });
        errdefer s1.deinit();
        const t = try a.create(AR.TruthSetup);
        errdefer a.destroy(t);
        t.* = try AR.TruthSetup.init(a, LOG);
        errdefer t.deinit();
        var buffer: [2]R.Truth = undefined;
        const bundle = try E.produce(a, &.{ s0, s1 }, truthsFor(t, split, &buffer), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity));
        return .{ .allocator = a, .setups = .{ s0, s1 }, .truth = t, .split = split, .bundle = bundle };
    }
};
pub fn truthsFor(setup: *const AR.TruthSetup, split: bool, out: *[2]R.Truth) []const R.Truth {
    if (split) {
        out.* = .{ .{ .arith256_mod = .{ .setup = setup, .first_id = 1, .calls = 2 } }, .{ .arith256_mod = .{ .setup = setup, .first_id = 3, .calls = 1 } } };
        return out;
    }
    out[0] = .{ .arith256_mod = .{ .setup = setup, .first_id = 1, .calls = 3 } };
    return out[0..1];
}
