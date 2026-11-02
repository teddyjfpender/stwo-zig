//! ethereum_services_v3 JUMPDEST fixture: one real CPU proof per shard with the
//! admitted jumpdest_bitmap bridges (jdesc, jscan, jtab) sharing the global RAM
//! chain with LS.
//!
//! Shard 0 (epoch 1): ECALL jumpdest(code B+0x100, 72 bytes, bitmap B+0x200):
//! two scan rows, PUSH32 data crossing the row boundary; LD x5 <- B+0x200
//! observes the written bitmap word.
//! Shard 1 (epoch 2): a0 += 24; ECALL jumpdest(code B+0x200, 16 bytes, bitmap
//! B+0x280) analyzes shard 0's two bitmap words across the epoch boundary;
//! LD x5 <- B+0x280 observes its bitmap word.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const BM = A.crypto.bulk_memory;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const Tape = front.rv64.compact_tape.Tape;
pub const B: u64 = 0x8000000000001000;
/// ECALL; LD x5, 0x200(a0); ADDI a0, a0, 24; ECALL; LD x5, 0x268(a0).
pub const WORDS = [_]u32{ 0x73, 0x20053283, 0x01850513, 0x73, 0x26853283 };
const JD: u64 = BM.types.JUMPDEST_TAG;
const marker: u8 = 0;
/// Call 0's 72 code bytes: JUMPDEST at 0, 3, 10; PUSH1 data 0x5b at 2;
/// PUSH32 at 40 whose data (41..72) holds 0x5b at 64 and 70.
fn codeByte(i: usize) u8 {
    return switch (i) {
        0, 3, 10, 64, 70 => 0x5b,
        1 => 0x60,
        2 => 0x5b,
        40 => 0x7f,
        else => 0x01,
    };
}
fn codeWord(k: usize) u64 {
    var v: u64 = 0;
    for (0..8) |i| v |= @as(u64, codeByte(8 * k + i)) << @intCast(8 * i);
    return v;
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < B or address >= B + 0x300 or address & 7 != 0) return error.UntrustedJumpdestFixtureAddress;
    const o = address - B;
    return switch (o) {
        0 => B + 0x100,
        8 => 72,
        16 => B + 0x200,
        24 => B + 0x200,
        32 => 16,
        40 => B + 0x280,
        else => if (o >= 0x100 and o < 0x148) codeWord((o - 0x100) / 8) else address *% 0x9E3779B97F4A7C15,
    };
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < B or address >= B + 0x300) return error.UntrustedJumpdestFixtureAddress;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
/// The canonical bitmap words of call 0 (2 words) and call 1 (1 word).
pub fn bitmaps() struct { first: [2]u64, second: u64 } {
    var code: [9]u64 = undefined;
    for (&code, 0..) |*w, k| w.* = codeWord(k);
    var pending: [2]u8 = undefined;
    var first: [2]u64 = undefined;
    BM.types.analyzeWords(&code, &pending, &first);
    var p1: [1]u8 = undefined;
    var second: [1]u64 = undefined;
    BM.types.analyzeWords(&first, &p1, &second);
    return .{ .first = first, .second = second[0] };
}
fn regs(a0: u64, x5: u64) [32]u64 {
    var r: [32]u64 = @splat(0);
    r[5] = x5;
    r[10] = a0;
    r[17] = JD;
    return r;
}
pub fn expectedFor(identity: [32]u8) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x5b), .initial_pc = 4096, .initial_registers = regs(B, 0), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 5, .max_total_steps = 5, .final_pc = 4116, .final_registers = regs(B + 24, bitmaps().second) };
}
pub const Captured = struct {
    allocator: std.mem.Allocator,
    program: *Program,
    tapes: [2]Tape,
    native: [2]Native,
    advice: C.Advice,
    pub fn init(a: std.mem.Allocator) !Captured {
        const bm = bitmaps();
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.init(a, .{ .base = 4096, .words = &WORDS });
        errdefer program.deinit();
        var t0 = try Tape.init(a, 2, 4096, 0, .ethereum_services_v3);
        errdefer t0.deinit();
        var t1 = try Tape.init(a, 3, 4104, 2, .ethereum_services_v3);
        errdefer t1.deinit();
        try t0.appendBulk(.{ .clock = 1, .pc = 4096, .pointer = B, .tag = JD });
        // LD x5, 0x200(a0): the bitmap word the call wrote.
        t0.storage[1] = .{ .next_pc = 4104, .lhs = B, .rhs = 0, .previous_rd = 0, .result = bm.first[0], .memory_index = 0, .flags = 0 };
        try t0.memory_before.append(a, bm.first[0]);
        t0.len = 2;
        t1.storage[0] = .{ .next_pc = 4108, .lhs = B, .rhs = 0, .previous_rd = B, .result = B + 24, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        t1.len = 1;
        try t1.appendBulk(.{ .clock = 4, .pc = 4108, .pointer = B + 24, .tag = JD });
        t1.storage[2] = .{ .next_pc = 4116, .lhs = B + 24, .rhs = 0, .previous_rd = bm.first[0], .result = bm.second, .memory_index = 0, .flags = 0 };
        try t1.memory_before.append(a, bm.second);
        t1.len = 3;
        var p0: A.word16_execution.types.Boundary = .{ .steps = 2, .initial_pc = 4096, .final_pc = 4104, .initial_registers = regs(B, 0), .final_registers = regs(B, bm.first[0]), .register_clocks = @splat(0) };
        p0.register_clocks[5] = 7;
        p0.register_clocks[10] = 5;
        p0.register_clocks[17] = 2;
        var p1: A.word16_execution.types.Boundary = .{ .steps = 3, .initial_pc = 4104, .final_pc = 4116, .initial_registers = regs(B, bm.first[0]), .final_registers = regs(B + 24, bm.second), .register_clocks = @splat(0) };
        p1.register_clocks[5] = 11;
        p1.register_clocks[10] = 9;
        p1.register_clocks[17] = 6;
        var n0 = try Native.captureForCombinedServicesV3(a, program, p0, 1, 5, &t0, .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, p1, 2, 5, &t1, .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &t0, &t1 }, image());
        errdefer advice.deinit();
        const b0 = advice.bulk[0];
        const b1 = advice.bulk[1];
        if (b0.calls.len != 1 or b0.calls[0].op != .jumpdest or b1.calls.len != 1 or b1.calls[0].op != .jumpdest or b1.words[0].src.value != bm.first[0] or b1.words[0].src.epoch != 1 or b1.words[1].src.value != bm.first[1]) return error.InvalidJumpdestFixtureChronology;
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
/// jdesc and jscan at the minimum log 5, the transition table at its log 14.
pub const bridges = [2]@import("types.zig").Logs{ .{ .bulk = .{ .jdesc = 5, .jscan = 5, .jtab = BM.types.TABLE_LOG } }, .{ .bulk = .{ .jdesc = 5, .jscan = 5, .jtab = BM.types.TABLE_LOG } } };
pub const Case = struct {
    allocator: std.mem.Allocator,
    setups: [2]*R.CpuSetup,
    bundle: E.Bundle,
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity);
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    pub const Mutation = enum { none, wrong_code_word, stale_code, wrong_length };
    pub fn init(a: std.mem.Allocator) !Case {
        return initMutation(a, .none);
    }
    pub fn initMutation(a: std.mem.Allocator, mutation: Mutation) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        switch (mutation) {
            .none => {},
            // The prover analyzes a code byte nobody wrote; the code TERM agrees.
            .wrong_code_word => {
                const w = &captured.advice.bulk[0].words[3].src;
                w.value ^= 0x01;
                for (captured.advice.terminal) |*cell| if (cell.address == B + 0x118) {
                    cell.state.value = w.value;
                };
            },
            // Call 1 analyzes the initial image of B+0x200 instead of call 0's
            // bitmap word (whose TERM is made to agree).
            .stale_code => {
                const w = &captured.advice.bulk[1].words[0].src;
                w.* = .{ .value = (B + 0x200) *% 0x9E3779B97F4A7C15, .rights = 3 };
                for (captured.advice.terminal) |*cell| if (cell.address == B + 0x200) {
                    cell.state.value = w.value;
                };
            },
            // Call 0 claims 64 bytes (one scan row): its packet read and the
            // missing code/bitmap accesses break RAM.
            .wrong_length => {
                const c = &captured.advice.bulk[0].calls[0];
                c.len = 64;
                c.packet[1].value = 64;
                const words = captured.advice.bulk[0].words;
                // Entries: 8 code words then 1 bitmap word.
                words[8] = words[9];
                captured.advice.bulk[0].words = captured.advice.allocator.realloc(words, 9) catch unreachable;
            },
        }
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[0].geometry(), bridges[0]);
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[1].geometry(), bridges[1]);
        errdefer s1.deinit();
        const bundle = try E.produce(a, &.{ s0, s1 }, &.{}, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity));
        return .{ .allocator = a, .setups = .{ s0, s1 }, .bundle = bundle };
    }
};
