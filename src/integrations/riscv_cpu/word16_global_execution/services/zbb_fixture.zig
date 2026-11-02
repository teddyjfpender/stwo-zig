//! ethereum_services_v3_zbb fixture: the v3 services fixture program (SHA-256,
//! arith256_mod, aligned memset/memcpy in two shards sharing one RAM chain)
//! interleaved with every admitted Zbb BINARY instruction (andn, orn, xnor,
//! rev8, sext.b, sext.h, zext.h), run on the real executor under the Zbb
//! profile and proved with the Zbb ROM and one Zbb BINARY component per shard.
//!
//! Shard 0 (epoch 1): LD x11 <- S; andn/orn/xnor on it; rev8 twice (one
//!   deduplicated fact of weight 2); sext.b of 0x80 (sign set) and 0x7f
//!   (sign clear); sext.h of 0x8000; zext.h; SHA-256(S); arith256_mod;
//!   memset.
//! Shard 1 (epoch 2): memcpy; arith256_mod; LD x9 <- S; rev8 x25 <- x9;
//!   SD x25 -> RAM and LD it back; andn; sext.h/sext.b of loaded values;
//!   SHA-256(S).
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const rv = front.rv64;
const Z = A.word16_v1.binary_zbb;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const HR = @import("../sha256/roster.zig");
const AR = @import("../arith256/roster.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const T = @import("types.zig");
const V3 = @import("v3_fixture.zig");

pub const PROFILE = rv.execution_profile.Profile.ethereum_services_v3_zbb;
pub const S = V3.S;
pub const BASE = V3.BASE;
pub const SIZE = V3.SIZE;
/// Scratch word written and re-read by shard 1 (inside the fixture image).
pub const SCRATCH: u64 = V3.SET_PACKET + 24;

fn r(f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}
fn iType(imm: u32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return (imm << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}
pub fn andn(rd: u32, rs1: u32, rs2: u32) u32 {
    return r(0x20, rs2, rs1, 7, rd, 0x33);
}
pub fn orn(rd: u32, rs1: u32, rs2: u32) u32 {
    return r(0x20, rs2, rs1, 6, rd, 0x33);
}
pub fn xnor(rd: u32, rs1: u32, rs2: u32) u32 {
    return r(0x20, rs2, rs1, 4, rd, 0x33);
}
pub fn rev8(rd: u32, rs1: u32) u32 {
    return iType(0x6b8, rs1, 5, rd, 0x13);
}
pub fn sextB(rd: u32, rs1: u32) u32 {
    return iType(0x604, rs1, 1, rd, 0x13);
}
pub fn sextH(rd: u32, rs1: u32) u32 {
    return iType(0x605, rs1, 1, rd, 0x13);
}
pub fn zextH(rd: u32, rs1: u32) u32 {
    return r(0x04, 0, rs1, 4, rd, 0x3b);
}
fn addi(rd: u32, rs1: u32, imm: u32) u32 {
    return iType(imm, rs1, 0, rd, 0x13);
}
fn lui(rd: u32, imm20: u32) u32 {
    return (imm20 << 12) | (rd << 7) | 0x37;
}
fn ld(rd: u32, rs1: u32, imm: u32) u32 {
    return iType(imm, rs1, 3, rd, 0x03);
}
fn sd(rs2: u32, rs1: u32, imm: u32) u32 {
    return ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((imm & 31) << 7) | 0x23;
}
fn mv(rd: u32, rs1: u32) u32 {
    return addi(rd, rs1, 0);
}
const ECALL: u32 = 0x73;
pub const WORDS = [_]u32{
    // shard 0
    ld(11, 5, 0), andn(12, 11, 6), orn(13, 11, 7), xnor(14, 12, 13), rev8(15, 11), rev8(16, 11),
    addi(29, 0, 0x80), sextB(22, 29), addi(30, 0, 0x7f), sextB(23, 30), lui(31, 0x8), sextH(24, 31), zextH(27, 15),
    mv(10, 5), mv(17, 18), ECALL, // SHA-256
    mv(10, 6), mv(17, 19), ECALL, // arith256_mod
    mv(10, 7), mv(17, 20), ECALL, // memset
    // shard 1
    mv(10, 28), mv(17, 21), ECALL, // memcpy
    mv(10, 6), mv(17, 19), ECALL, // arith256_mod
    ld(9, 5, 0), rev8(25, 9), sd(25, 7, 24), ld(26, 7, 24), andn(30, 26, 9), sextH(31, 26), sextB(29, 9),
    mv(10, 5), mv(17, 18), ECALL, // SHA-256
};
pub const SHARD0_STEPS: u32 = 22;
pub const STEPS: u32 = WORDS.len;
pub const CPU_LOG: u32 = 5;
pub const BOUNDARY_LOG: u32 = 6;
pub const ZBB_LOG: u32 = 5;
/// Zbb chip facts per shard (rev8 x11 deduplicated in shard 0; zext.h is BINARY AND).
pub const ZBB_FACTS = [2]usize{ 7, 4 };
pub const BRIDGES = [2]T.Logs{
    .{ .sha256 = 5, .arith256_mod = 5, .bulk = .{ .desc = 5, .set = 5 }, .zbb = ZBB_LOG },
    .{ .sha256 = 5, .arith256_mod = 5, .bulk = .{ .desc = 5, .copy = 5 }, .zbb = ZBB_LOG },
};
/// The default v3 route layout (Plan.CpuLayout.forProfile): fused-tail CPU
/// interaction, U8 byte-pair CPU queries, LS-D64 for every LD/SD and the
/// fused2 layouts (MUL byte pairs, LS32/INIT/TEARDOWN fused pairs, ALU fused
/// tail, LS-D64 fused pairs), so the Zbb byte-AND lookups share the AND table
/// with every pair consumer of the v3 route. Shard 0
/// has one LD, shard 1 an LD, an SD and an LD (all aligned doublewords).
pub const DWORD_ROWS = [2]u32{ 1, 3 };
pub const V3_BRIDGES = [2]T.Logs{ withDword(BRIDGES[0]), withDword(BRIDGES[1]) };
fn withDword(logs: T.Logs) T.Logs {
    var out = logs;
    out.ls_dword = 5;
    return out;
}
pub const Layout = enum {
    /// Historical CPU AIR (40 interaction columns), every load/store on LS32.
    historical,
    /// v3 default: fused tail + byte pairs + LS-D64 + every fused2 layout.
    v3_default,
    pub fn apply(self: Layout, g: *@import("../../word16_execution/setup.zig").Geometry) void {
        const v3 = self == .v3_default;
        g.cpu_fused_tail = v3;
        g.cpu_u8_pairs = v3;
        g.mul_u8_pairs = v3;
        g.ls_fused_pairs = v3;
        g.alu_fused_tail = v3;
        g.ls_dword_fused_pairs = v3;
    }
};
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return V3.image();
}
pub fn expectedFor(identity: [32]u8, final_registers: [32]u64) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x76), .initial_pc = 4096, .initial_registers = V3.initialRegisters(), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = STEPS, .max_total_steps = STEPS, .final_pc = 4096 + 4 * STEPS, .final_registers = final_registers };
}
pub fn programImage() A.program.setup.Program {
    return .{ .base = 4096, .words = &WORDS };
}

/// A cheating prover: the CPU retires a wrong result (consistent register
/// chain and public final state) while the provider keeps the TRUE fact:
/// forged_zbb_result forges `sext.b x22` (Zbb chip), forged_zext_result
/// forges `zext.h x27` (ROM-mapped to BINARY AND with immediate 0xffff).
pub const Mutation = enum { none, forged_zbb_result, forged_zext_result };
pub const Captured = struct {
    allocator: std.mem.Allocator,
    program: *Program,
    tapes: [2]rv.compact_tape.Tape,
    native: [2]Native,
    advice: C.Advice,
    final_registers: [32]u64,
    pub fn init(a: std.mem.Allocator, mutation: Mutation) !Captured {
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.initWithProfile(a, programImage(), PROFILE);
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
            std.mem.writeInt(u64, &bytes, try V3.image().initial_word(V3.image().context, address), .little);
            try memory.initialize(address, &bytes);
        }
        var cpu = rv.machine.Cpu.init(4096, 0);
        cpu.regs = V3.initialRegisters();
        var session = try rv.ethereum_services.Session.initWithProfile(a, cpu, &memory, .{ .max_retirements = 64, .isa = .rv64im_zbb_binary }, PROFILE);
        defer session.deinit();
        const sizes = [2]u32{ SHARD0_STEPS, STEPS - SHARD0_STEPS };
        var tapes: [2]rv.compact_tape.Tape = undefined;
        var boundaries: [2]A.word16_execution.types.Boundary = undefined;
        var made: usize = 0;
        errdefer for (tapes[0..made]) |*t| t.deinit();
        var zbb_retired: usize = 0;
        for (sizes, &tapes, &boundaries) |steps, *tape, *boundary| {
            const c = &session.keccak.base.cpu;
            tape.* = try rv.compact_tape.Tape.init(a, steps, c.pc, c.retired, PROFILE);
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
                zbb_retired += @intFromBool(!rv.decode.isBase(record.opcode));
                const effects = rv.execution_profile.effects(PROFILE, record.opcode);
                const tick: u32 = @intCast(4 * local);
                if (effects.reads_rs1 and record.rs1 != 0) boundary.register_clocks[record.rs1] = tick + 1;
                if (effects.reads_rs2 and record.rs2 != 0) boundary.register_clocks[record.rs2] = tick + 2;
                if (effects.writes_rd and record.rd != 0) boundary.register_clocks[record.rd] = tick + 3;
            }
            boundary.final_pc = c.pc;
            boundary.final_registers = c.regs;
        }
        if (zbb_retired != 13) return error.InvalidZbbFixtureChronology;
        var final_registers = session.keccak.base.cpu.regs;
        // Shard 0: step 7 is `sext.b x22, x29`, step 12 `zext.h x27, x15`;
        // neither destination is read again.
        if (mutation != .none) {
            const step: usize = if (mutation == .forged_zbb_result) 7 else 12;
            const rd: usize = if (mutation == .forged_zbb_result) 22 else 27;
            tapes[0].storage[step].result ^= 1;
            boundaries[0].final_registers[rd] ^= 1;
            boundaries[1].initial_registers[rd] ^= 1;
            boundaries[1].final_registers[rd] ^= 1;
            final_registers[rd] ^= 1;
        }
        var n0 = try Native.captureForCombinedServicesV3(a, program, boundaries[0], 1, CPU_LOG, &tapes[0], .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, boundaries[1], 2, CPU_LOG, &tapes[1], .{});
        errdefer n1.deinit();
        // zext.h is the core BINARY AND (FUNCTION 16, B = 0xffff); the rest
        // are Zbb chip facts with their exact reference results.
        for ([_]*Native{ &n0, &n1 }, ZBB_FACTS) |n, count| {
            if (n.zbb.facts.len != count) return error.InvalidZbbFixtureChronology;
            if (mutation == .none) for (n.zbb.facts) |f| if (!A.word16_v1.binary_zbb_source.validFact(f)) return error.InvalidZbbFixtureChronology;
        }
        if (n0.zbb.weights[3] != 2 or n0.zbb.facts[3].op != .rev8) return error.InvalidZbbFixtureChronology;
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &tapes[0], &tapes[1] }, image());
        errdefer advice.deinit();
        for (advice.events, DWORD_ROWS) |events, d| if (@import("pipeline.zig").dwordCount(events) != d) return error.InvalidZbbFixtureChronology;
        if (advice.sha256[0].len != 1 or advice.sha256[1].len != 1 or advice.arith256_mod[0].len != 1 or advice.bulk[1].calls.len != 1) return error.InvalidZbbFixtureChronology;
        return .{ .allocator = a, .program = program, .tapes = tapes, .native = .{ n0, n1 }, .advice = advice, .final_registers = final_registers };
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
    sha: *HR.TruthSetup,
    arith: *AR.TruthSetup,
    final_registers: [32]u64,
    bundle: E.Bundle,
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn truths(self: *const Case) [2]R.Truth {
        return V3.truthsFor(self.sha, self.arith);
    }
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity, self.final_registers);
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        self.sha.deinit();
        self.allocator.destroy(self.sha);
        self.arith.deinit();
        self.allocator.destroy(self.arith);
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    /// `bridges` overrides the receiver/prover roster (adversarial presence).
    pub fn init(a: std.mem.Allocator, mutation: Mutation, bridges: [2]T.Logs) !Case {
        return initLayout(a, mutation, bridges, .historical);
    }
    pub fn initLayout(a: std.mem.Allocator, mutation: Mutation, bridges: [2]T.Logs, layout: Layout) !Case {
        var captured = try Captured.init(a, mutation);
        defer captured.deinit();
        if (mutation != .none) {
            // The providers hold the TRUE facts for the forged CPU request.
            for (captured.native[0].zbb.facts) |*f| f.c = Z.result(f.op, f.a, f.b);
            for (captured.native[0].binary.facts) |*f| f.c = switch (f.op) {
                .and_ => f.a & f.b,
                .or_ => f.a | f.b,
                .xor => f.a ^ f.b,
            };
        }
        var setups: [2]*R.CpuSetup = undefined;
        var made: usize = 0;
        errdefer for (setups[0..made]) |s| {
            s.deinit();
            a.destroy(s);
        };
        for (&setups, bridges, captured.native) |*out, logs, native| {
            const s = try a.create(R.CpuSetup);
            errdefer a.destroy(s);
            var geometry = try native.geometry();
            geometry.initial_log = BOUNDARY_LOG;
            geometry.terminal_log = BOUNDARY_LOG;
            layout.apply(&geometry);
            s.* = try R.CpuSetup.initProgramWithProfile(a, programImage(), geometry, logs, PROFILE);
            out.* = s;
            made += 1;
        }
        const sha = try a.create(HR.TruthSetup);
        errdefer a.destroy(sha);
        sha.* = try HR.TruthSetup.init(a, V3.SHA_LOG);
        errdefer sha.deinit();
        const arith = try a.create(AR.TruthSetup);
        errdefer a.destroy(arith);
        arith.* = try AR.TruthSetup.init(a, V3.ARITH_LOG);
        errdefer arith.deinit();
        const roster = V3.truthsFor(sha, arith);
        const bundle = try E.produce(a, &.{ setups[0], setups[1] }, &roster, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity, captured.final_registers));
        return .{ .allocator = a, .setups = setups, .sha = sha, .arith = arith, .final_registers = captured.final_registers, .bundle = bundle };
    }
};
