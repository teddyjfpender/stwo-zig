//! Four actual CPU instructions, two K calls and25 cross-page words. LD writes
//! x0 deliberately: only the physical RAM argument can authenticate its value.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const X = A.word16_execution;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const R = @import("roster.zig");
const P = @import("../protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
pub const ADDRESS: u64 = 0x8000000000000ff8;
pub const WORDS = [_]u32{ 0x00113023, 0x00000073, 0x00053003, 0x00000073 };
const marker: u8 = 0;
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < ADDRESS or address > ADDRESS + 192 or address & 7 != 0) return error.UntrustedServiceAddress;
    return 0;
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address > ADDRESS + 199) return error.UntrustedServiceAddress;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
fn registers() [32]u64 {
    var r: [32]u64 = @splat(0);
    r[1] = 7;
    r[2] = ADDRESS;
    r[10] = ADDRESS;
    r[17] = 0x10001;
    return r;
}
pub const Case = struct {
    allocator: std.mem.Allocator,
    setups: [2]*R.Setup,
    bundle: E.Bundle,
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity);
    }
    pub fn expectedFor(identity: [32]u8) P.Expected {
        return .{ .admission = .{ .image = image(), .image_identity = @splat(0x6b), .initial_pc = 4096, .initial_registers = registers(), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 4, .max_total_steps = 4, .final_pc = 4112, .final_registers = registers() };
    }
    pub fn keys(self: *const Case) [2]*const R.Setup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    pub const Mutation = enum { none, wrong_output, false_reset };
    pub fn init(a: std.mem.Allocator) !Case {
        return initMutation(a, .none);
    }
    pub fn initMutation(a: std.mem.Allocator, mutation: Mutation) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        captured.mutate(mutation);
        const s0 = try a.create(R.Setup);
        errdefer a.destroy(s0);
        s0.* = try R.Setup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[0].geometry(), .{ .klog = 5, .blog = 5 });
        errdefer s0.deinit();
        const s1 = try a.create(R.Setup);
        errdefer a.destroy(s1);
        s1.* = try R.Setup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[1].geometry(), .{ .klog = 5, .blog = 5 });
        errdefer s1.deinit();
        const bundle = try E.produce(a, &.{ s0, s1 }, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity));
        return .{ .allocator = a, .setups = .{ s0, s1 }, .bundle = bundle };
    }
};

/// Shared narrow fixture capture. Program has a stable owned address before
/// either CPU borrows it; protocol variants consume the same native advice.
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
        var t0 = try front.rv64.compact_tape.Tape.init(a, 2, 4096, 0, .ethereum_services_v2);
        errdefer t0.deinit();
        var t1 = try front.rv64.compact_tape.Tape.init(a, 2, 4104, 2, .ethereum_services_v2);
        errdefer t1.deinit();
        var before: [25]u64 = @splat(0);
        before[0] = 7;
        var perm = std.crypto.core.keccak.KeccakF(1600){ .st = before };
        perm.permute();
        const after1 = perm.st;
        perm.permute();
        const after2 = perm.st;
        t0.len = 1;
        t0.storage[0] = .{ .next_pc = 4100, .lhs = ADDRESS, .rhs = 7, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try t0.memory_before.append(a, 0);
        try t0.appendService(.{ .call_id = 1, .clock = 2, .pc = 4100, .pointer = ADDRESS, .before = before, .after = after1 });
        t1.len = 1;
        t1.storage[0] = .{ .next_pc = 4108, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = after1[0], .memory_index = 0, .flags = 0 };
        try t1.memory_before.append(a, after1[0]);
        try t1.appendService(.{ .call_id = 2, .clock = 4, .pc = 4108, .pointer = ADDRESS, .before = after1, .after = after2 });
        var p0: X.types.Boundary = .{ .steps = 2, .initial_pc = 4096, .final_pc = 4104, .initial_registers = registers(), .final_registers = registers(), .register_clocks = @splat(0) };
        p0.register_clocks[1] = 2;
        p0.register_clocks[2] = 1;
        p0.register_clocks[10] = 5;
        p0.register_clocks[17] = 6;
        var p1 = p0;
        p1.initial_pc = 4104;
        p1.final_pc = 4112;
        p1.register_clocks[1] = 0;
        p1.register_clocks[2] = 0;
        try std.testing.expectError(error.UnqualifiedWord16ServiceOwners, Native.init(a, program, p0, 1, 5, &t0, .{}));
        var n0 = try Native.initForKeccak(a, program, p0, 1, 5, &t0, .{});
        errdefer n0.deinit();
        var n1 = try Native.initForKeccak(a, program, p1, 2, 5, &t1, .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &t0, &t1 }, image());
        errdefer advice.deinit();
        if (advice.initial.len != 25 or advice.calls[0][0].predecessors[0].epoch != 1 or advice.calls[1][0].predecessors[0].epoch != 2 or advice.calls[1][0].predecessors[1].epoch != 1) return error.InvalidFixtureChronology;
        return .{ .allocator = a, .program = program, .tapes = .{ t0, t1 }, .native = .{ n0, n1 }, .advice = advice };
    }
    pub fn mutate(self: *Captured, mutation: Case.Mutation) void {
        if (mutation == .wrong_output) {
            self.advice.calls[1][0].after[3] ^= 1;
            self.advice.terminal[3].state.value ^= 1;
        } else if (mutation == .false_reset) {
            self.advice.calls[1][0].before[1] = 0;
            self.advice.calls[1][0].predecessors[1] = .{ .value = 0, .rights = 3 };
            var forged = std.crypto.core.keccak.KeccakF(1600){ .st = self.advice.calls[1][0].before };
            forged.permute();
            self.advice.calls[1][0].after = forged.st;
            for (self.advice.terminal, 0..) |*cell, lane| cell.state.value = forged.st[lane];
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
