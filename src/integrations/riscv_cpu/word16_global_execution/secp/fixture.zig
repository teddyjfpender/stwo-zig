//! Actual CPU SD→ADD / ADDI→DOUBLE with one global RAM ledger. Point validity
//! is deliberately not assumed: the store changes a raw RCB input coordinate.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const S = A.crypto.secp256k1;
const X = A.word16_execution;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
pub const ADDRESS: u64 = 0x8000000000000fe0;
pub const WORDS = [_]u32{ 0x00053023, 0x73, 0x00188893, 0x73 };
fn initialWords() [24]u64 {
    const x: u256 = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
    const y: u256 = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;
    var out: [24]u64 = undefined;
    for ([_]u256{ x, y, 1, x, y, 1 }, 0..) |v, coord| for (0..4) |lane| {
        out[4 * coord + lane] = @truncate(v >> @as(u8, @intCast(64 * lane)));
    };
    return out;
}
const marker: u8 = 0;
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < ADDRESS or address > ADDRESS + 184 or address & 7 != 0) return error.UntrustedSecpAddress;
    return initialWords()[(address - ADDRESS) / 8];
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address > ADDRESS + 191) return error.UntrustedSecpAddress;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
fn regs(tag: u64) [32]u64 {
    var out: [32]u64 = @splat(0);
    out[10] = ADDRESS;
    out[17] = tag;
    return out;
}
pub fn expectedFor(identity: [32]u8) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x73), .initial_pc = 4096, .initial_registers = regs(0x20011), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 4, .max_total_steps = 4, .final_pc = 4112, .final_registers = regs(0x20012) };
}
fn execute(kind: S.program.Kind, before: [24]u64) ![24]u64 {
    const p = S.program.get(kind);
    var input: [6]u256 = @splat(0);
    for (0..p.inputs) |coord| {
        for (0..4) |lane| input[coord] |= @as(u256, before[4 * coord + lane]) << @as(u8, @intCast(64 * lane));
    }
    const values = try S.program.execute(p, input[0..p.inputs]);
    var after = before;
    for (p.outputs, 0..) |wire, coord| for (0..4) |lane| {
        after[4 * coord + lane] = @truncate(values[wire] >> @as(u8, @intCast(64 * lane)));
    };
    return after;
}
pub const Captured = struct {
    allocator: std.mem.Allocator,
    program: *Program,
    tapes: [2]front.rv64.compact_tape.Tape,
    native: [2]Native,
    advice: C.Advice,
    pub fn init(a: std.mem.Allocator) !Captured {
        return initLsRepeats(a, 1);
    }
    pub fn initLsRepeats(a: std.mem.Allocator, repeats: u32) !Captured {
        if (repeats == 0 or repeats > 1024) return error.InvalidSecpFixtureRepeats;
        const steps = repeats + 1;
        const base1: u64 = 4096 + 4 * @as(u64, steps);
        const words = try a.alloc(u32, repeats + 3);
        defer a.free(words);
        @memset(words[0..repeats], WORDS[0]);
        @memcpy(words[repeats..], WORDS[1..]);
        const cpu_log = try @import("../../word16_execution/coverage.zig").minimalPrefixLog(steps);
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.init(a, .{ .base = 4096, .words = words });
        errdefer program.deinit();
        var t0 = try front.rv64.compact_tape.Tape.init(a, steps, 4096, 0, .ethereum_services_v2);
        errdefer t0.deinit();
        var t1 = try front.rv64.compact_tape.Tape.init(a, 2, base1, steps, .ethereum_services_v2);
        errdefer t1.deinit();
        var before = initialWords();
        before[0] = 0;
        const after = try execute(.add, before);
        const final = try execute(.double, after);
        t0.len = repeats;
        for (0..repeats) |i| {
            t0.storage[i] = .{ .next_pc = 4096 + 4 * (i + 1), .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = @intCast(i), .flags = 0 };
            try t0.memory_before.append(a, if (i == 0) initialWords()[0] else 0);
        }
        try t0.appendSecp(.{ .kind = .add, .packet_format = .little_endian_words_v2, .call_id = 1, .clock = steps, .pc = 4096 + 4 * @as(u64, repeats), .pointer = ADDRESS, .before = before, .after = after });
        t1.len = 1;
        t1.storage[0] = .{ .next_pc = base1 + 4, .lhs = 0x20011, .rhs = 0, .previous_rd = 0x20011, .result = 0x20012, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        try t1.appendSecp(.{ .kind = .double, .packet_format = .little_endian_words_v2, .call_id = 1, .clock = @as(u64, steps) + 2, .pc = base1 + 4, .pointer = ADDRESS, .before = after, .after = final });
        // Native ABI zeros unused DOUBLE tail words; bridge ledger ignores them.
        @memset(t1.secp_calls.items[0].before[12..], 0);
        @memset(t1.secp_calls.items[0].after[12..], 0);
        var p0: X.types.Boundary = .{ .steps = steps, .initial_pc = 4096, .final_pc = base1, .initial_registers = regs(0x20011), .final_registers = regs(0x20011), .register_clocks = @splat(0) };
        p0.register_clocks[10] = 4 * repeats + 1;
        p0.register_clocks[17] = 4 * repeats + 2;
        var p1 = p0;
        p1.steps = 2;
        p1.initial_pc = base1;
        p1.final_pc = base1 + 8;
        p1.register_clocks[10] = 5;
        p1.register_clocks[17] = 6;
        p1.final_registers = regs(0x20012);
        if (Native.init(a, program, p0, 1, cpu_log, &t0, .{})) |bad| {
            var owned = bad;
            owned.deinit();
            return error.PlainAdmittedSecp;
        } else |err| if (err != error.UnqualifiedWord16ServiceOwners) return err;
        if (Native.initForKeccak(a, program, p0, 1, cpu_log, &t0, .{})) |bad| {
            var owned = bad;
            owned.deinit();
            return error.KeccakAdmittedSecp;
        } else |err| if (err != error.UnqualifiedWord16ServiceOwners) return err;
        var n0 = try Native.initForSecp(a, program, p0, 1, cpu_log, &t0, .{});
        errdefer n0.deinit();
        var n1 = try Native.initForSecp(a, program, p1, 2, 5, &t1, .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &t0, &t1 }, image());
        errdefer advice.deinit();
        if (advice.initial.len != 24 or advice.calls[0][0].len != 1 or advice.calls[1][1].len != 1 or advice.calls[0][0][0].predecessors[0].epoch != 1 or advice.calls[1][1][0].predecessors[1].epoch != 1) return error.InvalidSecpFixtureChronology;
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
    truths: [2]*R.TruthSetup,
    bundle: E.Bundle,
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity);
    }
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn truthKeys(self: *const Case) [2]*const R.TruthSetup {
        return .{ self.truths[0], self.truths[1] };
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        for (self.truths) |t| {
            t.deinit();
            self.allocator.destroy(t);
        }
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    pub const Mutation = enum { none, wrong_output, false_reset, wrong_pointer, wrong_kind };
    pub fn init(a: std.mem.Allocator, mutation: Mutation) !Case {
        var c = try Captured.init(a);
        defer c.deinit();
        if (mutation == .wrong_output) {
            c.advice.calls[1][1][0].after[1] ^= 1;
            c.advice.terminal[1].state.value ^= 1;
        } else if (mutation == .false_reset) {
            const call = &c.advice.calls[1][1][0];
            call.before[1] = 0;
            call.predecessors[1] = .{ .value = 0, .rights = 3 };
            call.after = try execute(.double, call.before);
            for (c.advice.terminal[0..12], 0..) |*cell, lane| cell.state.value = call.after[lane];
        }
        if (mutation == .wrong_pointer) c.advice.calls[0][0][0].pointer += 32;
        if (mutation == .wrong_kind) {
            const wrong = c.advice.calls[0][0][0];
            const replacement = try a.dupe(S.word16_bridge.types.Call, &.{wrong});
            a.free(c.advice.calls[0][1]);
            c.advice.calls[0][1] = replacement;
            a.free(c.advice.calls[0][0]);
            c.advice.calls[0][0] = &.{};
        }
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try c.native[0].geometry(), .{ 5, 5 });
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try c.native[1].geometry(), .{ 5, 5 });
        errdefer s1.deinit();
        const ta = try a.create(R.TruthSetup);
        errdefer a.destroy(ta);
        ta.* = try R.TruthSetup.init(a, .add, .{ try S.layout.logSize(.product, &S.program.add, 1), try S.layout.logSize(.linear, &S.program.add, 1) });
        errdefer ta.deinit();
        const td = try a.create(R.TruthSetup);
        errdefer a.destroy(td);
        td.* = try R.TruthSetup.init(a, .double, .{ try S.layout.logSize(.product, &S.program.double, 1), try S.layout.logSize(.linear, &S.program.double, 1) });
        errdefer td.deinit();
        const bundle = try E.produce(a, &.{ s0, s1 }, .{ ta, td }, &.{ &c.native[0], &c.native[1] }, &c.advice, expectedFor(c.program.identity));
        return .{ .allocator = a, .setups = .{ s0, s1 }, .truths = .{ ta, td }, .bundle = bundle };
    }
};
