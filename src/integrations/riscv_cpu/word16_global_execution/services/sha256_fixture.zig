//! Two v3 shards: SD, SHA-256, SHA-256 | SD, SHA-256 on one cross-page packet.
//! Ordinary stores interleave with compressions, chaining state across shards.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const HR = @import("../sha256/roster.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const Sha = front.rv64.ethereum_services.sha256;
pub const ADDRESS: u64 = 0x8000000000000fe0;
pub const TAG: u64 = 0x30010;
/// sd x0,0(a0); ecall; ecall | sd x0,32(a0); ecall
pub const WORDS = [_]u32{ 0x00053023, 0x73, 0x73, 0x02053023, 0x73 };
const marker: u8 = 0;
pub fn initialWords() [12]u64 {
    const iv = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    var out: [12]u64 = undefined;
    for (0..4) |i| out[i] = @as(u64, iv[2 * i]) | (@as(u64, iv[2 * i + 1]) << 32);
    var block: [64]u8 = undefined;
    for (&block, 0..) |*b, i| b.* = @truncate(0x31 * i + 7);
    for (0..8) |i| out[4 + i] = std.mem.readInt(u64, block[8 * i ..][0..8], .little);
    return out;
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < ADDRESS or address >= ADDRESS + 96 or address & 7 != 0) return error.UntrustedSha256Address;
    return initialWords()[(address - ADDRESS) / 8];
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address >= ADDRESS + 96) return error.UntrustedSha256Address;
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
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x5a), .initial_pc = 4096, .initial_registers = regs(), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 5, .max_total_steps = 5, .final_pc = 4116, .final_registers = regs() };
}
fn call(id: u64, clock: u64, pc: u64, before: [12]u64) front.rv64.ethereum_services.Sha256Call {
    var after = before;
    after[0..4].* = Sha.compressPacket(before);
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
        try t0.memory_before.append(a, packet[0]);
        t0.len = 1;
        packet[0] = 0;
        const c1 = call(1, 2, 4100, packet);
        try t0.appendSha256(c1);
        const c2 = call(2, 3, 4104, c1.after);
        try t0.appendSha256(c2);
        t1.storage[0] = .{ .next_pc = 4112, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try t1.memory_before.append(a, c2.after[4]);
        t1.len = 1;
        packet = c2.after;
        packet[4] = 0;
        try t1.appendSha256(call(3, 5, 4112, packet));
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
        if (advice.initial.len != 12 or advice.sha256[0].len != 2 or advice.sha256[1].len != 1 or advice.sha256[1][0].predecessors[4].epoch != 2 or advice.sha256[1][0].predecessors[0].epoch != 1) return error.InvalidSha256FixtureChronology;
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
    truth: *HR.TruthSetup,
    /// Two spans (calls 1..2 and 3) when true, one span of three otherwise.
    split: bool,
    bundle: E.Bundle,
    pub const Mutation = enum { none, wrong_output, forged_message, wrong_pointer };
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
    pub fn init(a: std.mem.Allocator, mutation: Mutation, split: bool) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        switch (mutation) {
            .none => {},
            .wrong_output => {
                // Locally valid bridge and truth; the bridge publishes a state
                // the truth never produced. Only Wire35 can see the difference.
                captured.advice.sha256[1][0].after[1] ^= 1;
                for (captured.advice.terminal) |*cell| if (cell.address == ADDRESS + 8) {
                    cell.state.value ^= 1;
                };
            },
            .forged_message => {
                // A consistent truth/bridge pair for a block word the RAM chain
                // never held: only global RAM closure can see it.
                const c = &captured.advice.sha256[1][0];
                c.before[6] ^= 1;
                c.predecessors[6].value ^= 1;
                c.after = c.before;
                c.after[0..4].* = Sha.compressPacket(c.before[0..12].*);
                for (captured.advice.terminal) |*cell| {
                    const offset = cell.address -% ADDRESS;
                    if (offset < 96) cell.state.value = c.after[offset / 8];
                }
            },
            .wrong_pointer => captured.advice.sha256[0][0].pointer += 32,
        }
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[0].geometry(), .{ .sha256 = 5 });
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[1].geometry(), .{ .sha256 = 5 });
        errdefer s1.deinit();
        const ht = try a.create(HR.TruthSetup);
        errdefer a.destroy(ht);
        ht.* = try HR.TruthSetup.init(a, 5);
        errdefer ht.deinit();
        var buffer: [2]R.Truth = undefined;
        const bundle = try E.produce(a, &.{ s0, s1 }, truthsFor(ht, split, &buffer), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity));
        return .{ .allocator = a, .setups = .{ s0, s1 }, .truth = ht, .split = split, .bundle = bundle };
    }
};
pub fn truthsFor(setup: *const HR.TruthSetup, split: bool, out: *[2]R.Truth) []const R.Truth {
    if (split) {
        out.* = .{ .{ .sha256 = .{ .setup = setup, .first_id = 1, .calls = 2 } }, .{ .sha256 = .{ .setup = setup, .first_id = 3, .calls = 1 } } };
        return out;
    }
    out[0] = .{ .sha256 = .{ .setup = setup, .first_id = 1, .calls = 3 } };
    return out[0..1];
}
