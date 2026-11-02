//! ethereum_services_v3 bulk-memory extension fixture: unaligned memcpy and
//! memcmp in real CPU proofs sharing the global RAM chain with LS.
//!
//! Shard 0 (epoch 1): ECALL memcpy(B+0x200, B+0x103, 24) (source shift 3: four
//! source words, three destination words); ADDI a7, a7, 2 (memcpy -> memcmp).
//! Shard 1 (epoch 2): ADDI a0, a0, 24; ECALL memcmp(B+0x200, B+0x300, 24) whose
//! `a` operand is the copy written in epoch 1; `b` equals the copy in word 0
//! and differs in byte 5 of word 1, so two of three word pairs are examined;
//! LD x5 <- the result word observes the memcmp result.
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
/// ECALL; ADDI a7,a7,2; ADDI a0,a0,24; ECALL; LD x5,24(a0).
pub const WORDS = [_]u32{ 0x73, 0x00288893, 0x01850513, 0x73, 0x01853283 };
const MEMCPY: u64 = 0x30001;
const MEMCMP: u64 = 0x30003;
const SHIFT: u3 = 3;
const marker: u8 = 0;
fn pseudo(address: u64) u64 {
    return address *% 0x9E3779B97F4A7C15;
}
/// Destination word j of the copy (bytes src + 8j .. src + 8j + 7).
pub fn copied(j: u64) u64 {
    return BM.types.shifted(pseudo(B + 0x100 + 8 * j), pseudo(B + 0x108 + 8 * j), SHIFT);
}
/// The memcmp `b` operand: equal in word 0, byte 5 of word 1 differs.
fn other(j: u64) u64 {
    return if (j == 1) copied(1) ^ (@as(u64, 0x10) << 40) else copied(j) ^ (if (j == 2) @as(u64, 0xFF) else 0);
}
/// memcmp(copy, other, 24) as an architectural u64 result word.
pub fn result() u64 {
    return @bitCast(@as(i64, BM.types.compareWords(copied(1), other(1))));
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < B or address >= B + 0x400 or address & 7 != 0) return error.UntrustedBulkFixtureAddress;
    const o = address - B;
    return switch (o) {
        0 => B + 0x200,
        8 => B + 0x100 + SHIFT,
        16 => 24,
        24 => B + 0x200,
        32 => B + 0x300,
        40 => 24,
        48 => 0x77,
        0x300, 0x308, 0x310 => other((o - 0x300) / 8),
        else => pseudo(address),
    };
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < B or address >= B + 0x400) return error.UntrustedBulkFixtureAddress;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
fn regs(a0: u64, a7: u64, x5: u64) [32]u64 {
    var r: [32]u64 = @splat(0);
    r[5] = x5;
    r[10] = a0;
    r[17] = a7;
    return r;
}
pub fn expectedFor(identity: [32]u8) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x5c), .initial_pc = 4096, .initial_registers = regs(B, MEMCPY, 0), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 5, .max_total_steps = 5, .final_pc = 4116, .final_registers = regs(B + 24, MEMCMP, result()) };
}
pub const Captured = struct {
    allocator: std.mem.Allocator,
    program: *Program,
    tapes: [2]Tape,
    native: [2]Native,
    advice: C.Advice,
    pub fn init(a: std.mem.Allocator) !Captured {
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.init(a, .{ .base = 4096, .words = &WORDS });
        errdefer program.deinit();
        var t0 = try Tape.init(a, 2, 4096, 0, .ethereum_services_v3);
        errdefer t0.deinit();
        var t1 = try Tape.init(a, 3, 4104, 2, .ethereum_services_v3);
        errdefer t1.deinit();
        try t0.appendBulk(.{ .clock = 1, .pc = 4096, .pointer = B, .tag = MEMCPY });
        t0.storage[1] = .{ .next_pc = 4104, .lhs = MEMCPY, .rhs = 0, .previous_rd = MEMCPY, .result = MEMCMP, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        t0.len = 2;
        t1.storage[0] = .{ .next_pc = 4108, .lhs = B, .rhs = 0, .previous_rd = B, .result = B + 24, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        t1.len = 1;
        try t1.appendBulk(.{ .clock = 4, .pc = 4108, .pointer = B + 24, .tag = MEMCMP });
        // LD x5, 24(a0) = B + 48: the memcmp result word.
        t1.storage[2] = .{ .next_pc = 4116, .lhs = B + 24, .rhs = 0, .previous_rd = 0, .result = result(), .memory_index = 0, .flags = 0 };
        try t1.memory_before.append(a, result());
        t1.len = 3;
        var p0: A.word16_execution.types.Boundary = .{ .steps = 2, .initial_pc = 4096, .final_pc = 4104, .initial_registers = regs(B, MEMCPY, 0), .final_registers = regs(B, MEMCMP, 0), .register_clocks = @splat(0) };
        p0.register_clocks[10] = 1;
        p0.register_clocks[17] = 7;
        var p1: A.word16_execution.types.Boundary = .{ .steps = 3, .initial_pc = 4104, .final_pc = 4116, .initial_registers = regs(B, MEMCMP, 0), .final_registers = regs(B + 24, MEMCMP, result()), .register_clocks = @splat(0) };
        p1.register_clocks[5] = 11;
        p1.register_clocks[10] = 9;
        p1.register_clocks[17] = 6;
        var n0 = try Native.captureForCombinedServicesV3(a, program, p0, 1, 5, &t0, .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, p1, 2, 5, &t1, .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &t0, &t1 }, image());
        errdefer advice.deinit();
        try check(advice);
        return .{ .allocator = a, .program = program, .tapes = .{ t0, t1 }, .native = .{ n0, n1 }, .advice = advice };
    }
    /// The collector's ledger replay matches the byte-level reference.
    fn check(advice: C.Advice) !void {
        const b0 = advice.bulk[0];
        const b1 = advice.bulk[1];
        if (b0.calls.len != 1 or b0.calls[0].body() != .ucopy or b0.calls[0].shift() != SHIFT or b0.words.len != 4) return error.InvalidBulkFixtureChronology;
        if (b1.calls.len != 1 or b1.calls[0].op != .cmp or b1.calls[0].examined != 2 or b1.words.len != 2) return error.InvalidBulkFixtureChronology;
        // memcmp's `a` words are the copy written in epoch 1.
        for (b1.words, 0..) |w, j| if (w.dst.epoch != 1 or w.dst.value != copied(j) or w.src.value != other(j)) return error.InvalidBulkFixtureChronology;
        if (@as(u64, @bitCast(@as(i64, b1.calls[0].result))) != result() or b1.calls[0].result == 0) return error.InvalidBulkFixtureChronology;
        // Byte reference of the copy: dst byte i = initial source byte 0x103 + i.
        for (0..24) |i| {
            const s = pseudo((B + 0x103 + i) & ~@as(u64, 7));
            const d = copied(i / 8);
            if (@as(u8, @truncate(s >> @intCast(8 * ((0x103 + i) & 7)))) != @as(u8, @truncate(d >> @intCast(8 * (i & 7))))) return error.InvalidBulkFixtureChronology;
        }
    }
    pub fn deinit(self: *Captured) void {
        self.advice.deinit();
        for (&self.native) |*n| n.deinit();
        for (&self.tapes) |*t| t.deinit();
        self.program.deinit();
        self.allocator.destroy(self.program);
    }
};
pub const bridges = [2]@import("types.zig").Logs{ .{ .bulk = .{ .desc = 5, .ucopy = 5 } }, .{ .bulk = .{ .cdesc = 5, .cmp = 5 } } };
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
    pub const Mutation = enum { none, wrong_source_byte, wrong_compare_word, forged_result };
    pub fn init(a: std.mem.Allocator) !Case {
        return initMutation(a, .none);
    }
    pub fn initMutation(a: std.mem.Allocator, mutation: Mutation) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        switch (mutation) {
            .none => {},
            // The prover shifts a source byte nobody wrote into dst word 1; the
            // dst word's TERM agrees with the forged copy.
            .wrong_source_byte => {
                const u = &captured.advice.bulk[0];
                u.words[2].src.value ^= 0x1;
                const forged = BM.types.shifted(u.words[1].src.value, u.words[2].src.value, SHIFT);
                for (captured.advice.terminal) |*cell| if (cell.address == B + 0x208) {
                    cell.state.value = forged;
                };
            },
            // memcmp reads an `a` word that is not the copy written in epoch 1
            // (result recomputed from the forged word, so prover checks pass).
            .wrong_compare_word => {
                const c = &captured.advice.bulk[1];
                c.words[1].dst.value ^= 0x1;
                c.calls[0].result = BM.types.compareWords(c.words[1].dst.value, c.words[1].src.value);
            },
            // The descriptor claims the opposite sign. The prover-side
            // validateCall refuses to build it (the AIR rejection of the same
            // forgery is in bulk_memory/tests.zig, "memcmp with a wrong result").
            .forged_result => {
                const c = &captured.advice.bulk[1].calls[0];
                c.result = -c.result;
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
