//! One real CPU proof per shard, all three service kinds sharing one RAM chain.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const SF = @import("../secp/fixture.zig");
const KR = @import("../keccak/shared/roster.zig");
const SR = @import("../secp/roster.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
pub const ADDRESS: u64 = 0x8000000000000fe0;
pub const WORDS = [_]u32{ 0x00053023, 0x73, 0x000208b7, 0x01188893, 0x73, 0x00188893, 0x73 };
const marker: u8 = 0;
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < ADDRESS or address > ADDRESS + 192 or address & 7 != 0) return error.UntrustedCombinedAddress;
    const i = (address - ADDRESS) / 8;
    return if (i < 24) SF.initialWords()[i] else 0xdeadbeef;
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < ADDRESS or address > ADDRESS + 199) return error.UntrustedCombinedAddress;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
fn regs(tag: u64) [32]u64 {
    var r: [32]u64 = @splat(0);
    r[10] = ADDRESS;
    r[17] = tag;
    return r;
}
pub fn expectedFor(identity: [32]u8) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x7e), .initial_pc = 4096, .initial_registers = regs(0x10001), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = 7, .max_total_steps = 7, .final_pc = 4124, .final_registers = regs(0x20012) };
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
        var t0 = try front.rv64.compact_tape.Tape.init(a, 4, 4096, 0, .ethereum_services_v2);
        errdefer t0.deinit();
        var t1 = try front.rv64.compact_tape.Tape.init(a, 3, 4112, 4, .ethereum_services_v2);
        errdefer t1.deinit();
        var before: [25]u64 = undefined;
        for (&before, 0..) |*v, i| v.* = try initial(&marker, ADDRESS + 8 * i);
        before[0] = 0;
        var perm = std.crypto.core.keccak.KeccakF(1600){ .st = before };
        perm.permute();
        const ka = perm.st;
        const sa: [24]u64 = ka[0..24].*;
        const add = try SF.execute(.add, sa);
        const double = try SF.execute(.double, add);
        t0.len = 1;
        t0.storage[0] = .{ .next_pc = 4100, .lhs = ADDRESS, .rhs = 0, .previous_rd = 0, .result = 0, .memory_index = 0, .flags = 0 };
        try t0.memory_before.append(a, SF.initialWords()[0]);
        try t0.appendService(.{ .call_id = 1, .clock = 2, .pc = 4100, .pointer = ADDRESS, .before = before, .after = ka });
        t0.storage[2] = .{ .next_pc = 4108, .lhs = 0, .rhs = 0, .previous_rd = 0x10001, .result = 0x20000, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        t0.storage[3] = .{ .next_pc = 4112, .lhs = 0x20000, .rhs = 0, .previous_rd = 0x20000, .result = 0x20011, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        t0.len = 4;
        try t1.appendSecp(.{ .kind = .add, .packet_format = .little_endian_words_v2, .call_id = 1, .clock = 5, .pc = 4112, .pointer = ADDRESS, .before = sa, .after = add });
        t1.storage[1] = .{ .next_pc = 4120, .lhs = 0x20011, .rhs = 0, .previous_rd = 0x20011, .result = 0x20012, .memory_index = front.rv64.compact_tape.NO_MEMORY, .flags = 0 };
        t1.len = 2;
        try t1.appendSecp(.{ .kind = .double, .packet_format = .little_endian_words_v2, .call_id = 1, .clock = 7, .pc = 4120, .pointer = ADDRESS, .before = add, .after = double });
        @memset(t1.secp_calls.items[1].before[12..], 0);
        @memset(t1.secp_calls.items[1].after[12..], 0);
        var p0: A.word16_execution.types.Boundary = .{ .steps = 4, .initial_pc = 4096, .final_pc = 4112, .initial_registers = regs(0x10001), .final_registers = regs(0x20011), .register_clocks = @splat(0) };
        p0.register_clocks[10] = 5;
        p0.register_clocks[17] = 15;
        var p1: A.word16_execution.types.Boundary = .{ .steps = 3, .initial_pc = 4112, .final_pc = 4124, .initial_registers = regs(0x20011), .final_registers = regs(0x20012), .register_clocks = @splat(0) };
        p1.register_clocks[10] = 9;
        p1.register_clocks[17] = 10;
        var n0 = try Native.captureForCombinedServicesLEv2(a, program, p0, 1, 5, &t0, .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesLEv2(a, program, p1, 2, 5, &t1, .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &t0, &t1 }, image());
        errdefer advice.deinit();
        if (advice.initial.len != 25 or advice.keccak[0].len != 1 or advice.secp[1][0].len != 1 or advice.secp[1][1].len != 1 or advice.keccak[0][0].predecessors[0].epoch != 1 or advice.secp[1][0][0].predecessors[1].epoch != 1 or advice.secp[1][1][0].predecessors[1].epoch != 2) return error.InvalidCombinedFixtureChronology;
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
    ktruth: *KR.TruthSetup,
    addtruth: *SR.TruthSetup,
    doubletruth: *SR.TruthSetup,
    bundle: E.Bundle,
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn truths(self: *const Case) [3]R.Truth {
        return .{ .{ .keccak = .{ .setup = self.ktruth, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = self.addtruth, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = self.doubletruth, .first_id = 1, .calls = 1 } } };
    }
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity);
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        self.ktruth.deinit();
        self.allocator.destroy(self.ktruth);
        self.addtruth.deinit();
        self.allocator.destroy(self.addtruth);
        self.doubletruth.deinit();
        self.allocator.destroy(self.doubletruth);
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    pub const Mutation = enum { none, cross_family_reset, wrong_keccak_output, wrong_secp_output, wrong_pointer };
    pub fn init(a: std.mem.Allocator) !Case {
        return initMutation(a, .none);
    }
    pub fn initMutation(a: std.mem.Allocator, mutation: Mutation) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        if (mutation == .wrong_pointer) captured.advice.keccak[0][0].pointer += 8;
        if (mutation == .wrong_secp_output) {
            captured.advice.secp[1][1][0].after[1] ^= 1;
            captured.advice.terminal[1].state.value ^= 1;
        }
        if (mutation == .cross_family_reset or mutation == .wrong_keccak_output) {
            const add_call = &captured.advice.secp[1][0][0];
            if (mutation == .cross_family_reset) {
                add_call.before[1] = 0;
                add_call.predecessors[1] = .{ .value = 0, .rights = 3 };
            } else {
                captured.advice.keccak[0][0].after[1] ^= 1;
                add_call.before[1] ^= 1;
                add_call.predecessors[1].value ^= 1;
            }
            add_call.after = try SF.execute(.add, add_call.before);
            const double_call = &captured.advice.secp[1][1][0];
            @memcpy(double_call.before[0..12], add_call.after[0..12]);
            for (double_call.predecessors[0..12], 0..) |*pred, lane| pred.value = add_call.after[lane];
            double_call.after = try SF.execute(.double, double_call.before);
            for (captured.advice.terminal[0..12], 0..) |*cell, lane| cell.state.value = double_call.after[lane];
        }
        const s0 = try a.create(R.CpuSetup);
        errdefer a.destroy(s0);
        s0.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[0].geometry(), .{ .keccak = 5 });
        errdefer s0.deinit();
        const s1 = try a.create(R.CpuSetup);
        errdefer a.destroy(s1);
        s1.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, try captured.native[1].geometry(), .{ .add = 5, .double = 5 });
        errdefer s1.deinit();
        const kt = try a.create(KR.TruthSetup);
        errdefer a.destroy(kt);
        kt.* = try KR.TruthSetup.init(a, 5);
        errdefer kt.deinit();
        const at = try a.create(SR.TruthSetup);
        errdefer a.destroy(at);
        at.* = try SR.TruthSetup.init(a, .add, .{ try S.layout.logSize(.product, &S.program.add, 1), try S.layout.logSize(.linear, &S.program.add, 1) });
        errdefer at.deinit();
        const dt = try a.create(SR.TruthSetup);
        errdefer a.destroy(dt);
        dt.* = try SR.TruthSetup.init(a, .double, .{ try S.layout.logSize(.product, &S.program.double, 1), try S.layout.logSize(.linear, &S.program.double, 1) });
        errdefer dt.deinit();
        const truth = [_]R.Truth{ .{ .keccak = .{ .setup = kt, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = at, .first_id = 1, .calls = 1 } }, .{ .secp = .{ .setup = dt, .first_id = 1, .calls = 1 } } };
        const bundle = try E.produce(a, &.{ s0, s1 }, &truth, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity));
        return .{ .allocator = a, .setups = .{ s0, s1 }, .ktruth = kt, .addtruth = at, .doubletruth = dt, .bundle = bundle };
    }
};
