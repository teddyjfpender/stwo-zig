//! ethereum_services_v3 bulk-memory fixture: one real CPU proof per shard with
//! admitted memset/memcpy bridges sharing the global RAM chain with LS.
//!
//! Shard 0 (epoch 1): ECALL memset(B+0x100, 0x5A, 32); SD a7 -> B+0x100.
//! Shard 1 (epoch 2): a7 -= 1 (memcpy); a0 += 24; ECALL memcpy(B+0x200,
//! B+0x100, 32) which reads the SD-written word and three memset words across
//! the epoch boundary; LD x5 <- B+0x200 observes the copied SD value.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const Tape = front.rv64.compact_tape.Tape;
pub const B: u64 = 0x8000000000001000;
pub const WORDS = [_]u32{ 0x73, 0x11153023, 0xfff88893, 0x01850513, 0x73, 0x1e853283 };
const MEMSET: u64 = 0x30002;
const MEMCPY: u64 = 0x30001;
const marker: u8 = 0;
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < B or address >= B + 0x300 or address & 7 != 0) return error.UntrustedBulkFixtureAddress;
    return switch (address - B) {
        0 => B + 0x100,
        8 => 0x5A,
        16 => 32,
        24 => B + 0x200,
        32 => B + 0x100,
        40 => 32,
        else => address *% 0x9E3779B97F4A7C15,
    };
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < B or address >= B + 0x300) return error.UntrustedBulkFixtureAddress;
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
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x5b), .initial_pc = 4096, .initial_registers = regs(B, MEMSET, 0), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 6, .max_total_steps = 6, .final_pc = 4120, .final_registers = regs(B + 24, MEMCPY, MEMSET) };
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
        var t1 = try Tape.init(a, 4, 4104, 2, .ethereum_services_v3);
        errdefer t1.deinit();
        try t0.appendBulk(.{ .clock = 1, .pc = 4096, .pointer = B, .tag = MEMSET });
        // SD a7, 0x100(a0): the before word is the memset fill.
        t0.storage[1] = .{ .next_pc = 4104, .lhs = B, .rhs = MEMSET, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try t0.memory_before.append(a, 0x5A5A5A5A5A5A5A5A);
        t0.len = 2;
        t1.storage[0] = .{ .next_pc = 4108, .lhs = MEMSET, .rhs = 0, .previous_rd = MEMSET, .result = MEMCPY, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        t1.storage[1] = .{ .next_pc = 4112, .lhs = B, .rhs = 0, .previous_rd = B, .result = B + 24, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        t1.len = 2;
        try t1.appendBulk(.{ .clock = 5, .pc = 4112, .pointer = B + 24, .tag = MEMCPY });
        // LD x5, 0x1E8(a0) = B + 0x200: the word memcpy copied from the SD.
        t1.storage[3] = .{ .next_pc = 4120, .lhs = B + 24, .rhs = 0, .previous_rd = 0, .result = MEMSET, .memory_index = 0, .flags = 0 };
        try t1.memory_before.append(a, MEMSET);
        t1.len = 4;
        var p0: A.word16_execution.types.Boundary = .{ .steps = 2, .initial_pc = 4096, .final_pc = 4104, .initial_registers = regs(B, MEMSET, 0), .final_registers = regs(B, MEMSET, 0), .register_clocks = @splat(0) };
        p0.register_clocks[10] = 5;
        p0.register_clocks[17] = 6;
        var p1: A.word16_execution.types.Boundary = .{ .steps = 4, .initial_pc = 4104, .final_pc = 4120, .initial_registers = regs(B, MEMSET, 0), .final_registers = regs(B + 24, MEMCPY, MEMSET), .register_clocks = @splat(0) };
        p1.register_clocks[5] = 15;
        p1.register_clocks[10] = 13;
        p1.register_clocks[17] = 10;
        var n0 = try Native.captureForCombinedServicesV3(a, program, p0, 1, 5, &t0, .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, p1, 2, 5, &t1, .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &t0, &t1 }, image());
        errdefer advice.deinit();
        const b0 = advice.bulk[0];
        const b1 = advice.bulk[1];
        if (b0.calls.len != 1 or b0.calls[0].op != .set or b1.calls.len != 1 or b1.calls[0].op != .copy or b1.words[0].src.value != MEMSET or b1.words[0].src.epoch != 1 or b1.words[1].src.value != 0x5A5A5A5A5A5A5A5A) return error.InvalidBulkFixtureChronology;
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
pub const bridges = [2]@import("types.zig").Logs{ .{ .bulk = .{ .desc = 5, .set = 5 } }, .{ .bulk = .{ .desc = 5, .copy = 5 } } };
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
    pub const Mutation = enum { none, wrong_copied_word, wrong_fill, stale_source };
    pub fn init(a: std.mem.Allocator) !Case {
        return initMutation(a, .none);
    }
    pub fn initMutation(a: std.mem.Allocator, mutation: Mutation) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        const copy = &captured.advice.bulk[1];
        switch (mutation) {
            .none => {},
            // The prover copies a value nobody wrote; the dst TERM agrees with it.
            .wrong_copied_word => {
                copy.words[2].src.value ^= 1;
                for (captured.advice.terminal) |*cell| if (cell.address == B + 0x210) {
                    cell.state.value ^= 1;
                };
            },
            // memset claims fill 0x5B: the packet read and every written word change.
            .wrong_fill => {
                const set = &captured.advice.bulk[0].calls[0];
                set.word1 = 0x5B;
                set.packet[1].value = 0x5B;
            },
            // memcpy observes the initial image instead of the memset/SD writes.
            .stale_source => {
                copy.words[1].src = .{ .value = (B + 0x108) *% 0x9E3779B97F4A7C15, .rights = 3 };
                for (captured.advice.terminal) |*cell| if (cell.address == B + 0x208) {
                    cell.state.value = copy.words[1].src.value;
                };
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
