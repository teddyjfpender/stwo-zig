//! ethereum_services_v3 fixture using all three admitted v3 services together
//! (SHA-256 compression, arith256_mod, aligned memset/memcpy) in two CPU
//! shards that share one global RAM chain. Unlike the per-service fixtures the
//! tapes come from the real v3 executor (ethereum_services.Session), so the
//! advice is exactly what native jobs would capture.
//!
//! Shard 0 (epoch 1): SHA-256(S); arith256_mod(AR); memset(D1, 0xA7, 32).
//! Shard 1 (epoch 2): memcpy(D2 <- S, 32) copies the state SHA-256 wrote in
//! epoch 1; arith256_mod(AR) re-reads the r it wrote; LD x9 <- S; SHA-256(S)
//! chains the state.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const rv = front.rv64;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const HR = @import("../sha256/roster.zig");
const AR = @import("../arith256/roster.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const T = @import("types.zig");
const ShaFixture = @import("sha256_fixture.zig");
const ArithFixture = @import("arith256_fixture.zig");

pub const BASE: u64 = 0x8000000000001000;
pub const S: u64 = BASE; // SHA-256 packet, 96 bytes, 32-byte aligned
pub const AR_PACKET: u64 = BASE + 0x100; // arith256_mod packet, 160 bytes
pub const SET_PACKET: u64 = BASE + 0x200; // memset dst, byte, len
pub const COPY_PACKET: u64 = BASE + 0x220; // memcpy dst, src, len
pub const D1: u64 = BASE + 0x300; // memset destination
pub const D2: u64 = BASE + 0x340; // memcpy destination
pub const SIZE: u64 = 0x400;
const SHA_TAG: u64 = 0x30010;
const ARITH_TAG: u64 = 0x30021;
const MEMSET_TAG: u64 = 0x30002;
const MEMCPY_TAG: u64 = 0x30001;

fn mv(rd: u32, rs1: u32) u32 {
    return (rs1 << 15) | (rd << 7) | 0x13;
}
const ECALL: u32 = 0x73;
/// ld x9, 0(x5)
const LD_S: u32 = (5 << 15) | (3 << 12) | (9 << 7) | 0x03;
pub const WORDS = [_]u32{
    // shard 0
    mv(10, 5), mv(17, 18), ECALL, // SHA-256
    mv(10, 6), mv(17, 19), ECALL, // arith256_mod
    mv(10, 7), mv(17, 20), ECALL, // memset
    // shard 1
    mv(10, 28), mv(17, 21), ECALL, // memcpy
    mv(10, 6), mv(17, 19), ECALL, // arith256_mod
    LD_S,
    mv(10, 5), mv(17, 18), ECALL, // SHA-256
};
pub const SHARD0_STEPS: u32 = 9;
pub const STEPS: u32 = WORDS.len;
pub const CPU_LOG: u32 = 5;
pub const BOUNDARY_LOG: u32 = 6;
const marker: u8 = 0;

fn initialWord(address: u64) u64 {
    if (address >= S and address < S + 96) return ShaFixture.initialWords()[(address - S) / 8];
    if (address >= AR_PACKET and address < AR_PACKET + 160) return ArithFixture.initialWords()[(address - AR_PACKET) / 8];
    return switch (address) {
        SET_PACKET => D1,
        SET_PACKET + 8 => 0x1234_56A7, // fill byte 0xA7 (word1 & 0xff)
        SET_PACKET + 16 => 32,
        COPY_PACKET => D2,
        COPY_PACKET + 8 => S,
        COPY_PACKET + 16 => 32,
        else => address *% 0x9E3779B97F4A7C15,
    };
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < BASE or address >= BASE + SIZE or address & 7 != 0) return error.UntrustedV3FixtureAddress;
    return initialWord(address);
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < BASE or address >= BASE + SIZE) return error.UntrustedV3FixtureAddress;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
pub fn initialRegisters() [32]u64 {
    var r: [32]u64 = @splat(0);
    r[5] = S;
    r[6] = AR_PACKET;
    r[7] = SET_PACKET;
    r[28] = COPY_PACKET;
    r[18] = SHA_TAG;
    r[19] = ARITH_TAG;
    r[20] = MEMSET_TAG;
    r[21] = MEMCPY_TAG;
    return r;
}
/// Final registers after the whole program (x9 holds the loaded SHA word).
pub fn finalRegisters(loaded: u64) [32]u64 {
    var r = initialRegisters();
    r[10] = S;
    r[17] = SHA_TAG;
    r[9] = loaded;
    return r;
}
pub fn expectedFor(identity: [32]u8, loaded: u64) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x76), .initial_pc = 4096, .initial_registers = initialRegisters(), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = STEPS, .max_total_steps = STEPS, .final_pc = 4096 + 4 * STEPS, .final_registers = finalRegisters(loaded) };
}
/// Receiver-chosen bridge roster (minimal bridge logs, bulk desc/set | desc/copy).
pub const BRIDGES = [2]T.Logs{
    .{ .sha256 = 5, .arith256_mod = 5, .bulk = .{ .desc = 5, .set = 5 } },
    .{ .sha256 = 5, .arith256_mod = 5, .bulk = .{ .desc = 5, .copy = 5 } },
};
pub const SHA_LOG: u32 = 5;
pub const ARITH_LOG: u32 = A.crypto.arith256.layout.MIN_LOG;

/// Runs the program on the real v3 executor and captures both shards.
pub const Captured = struct {
    allocator: std.mem.Allocator,
    program: *Program,
    tapes: [2]rv.compact_tape.Tape,
    native: [2]Native,
    advice: C.Advice,
    /// The word LD x9 observed (S word 0 after the first compression).
    loaded: u64,
    pub fn init(a: std.mem.Allocator) !Captured {
        const program = try a.create(Program);
        errdefer a.destroy(program);
        program.* = try Program.init(a, .{ .base = 4096, .words = &WORDS });
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
            std.mem.writeInt(u64, &bytes, initialWord(address), .little);
            try memory.initialize(address, &bytes);
        }
        var cpu = rv.machine.Cpu.init(4096, 0);
        cpu.regs = initialRegisters();
        var session = try rv.ethereum_services.Session.initWithProfile(a, cpu, &memory, .{ .max_retirements = 64 }, .ethereum_services_v3);
        defer session.deinit();
        const sizes = [2]u32{ SHARD0_STEPS, STEPS - SHARD0_STEPS };
        var tapes: [2]rv.compact_tape.Tape = undefined;
        var boundaries: [2]A.word16_execution.types.Boundary = undefined;
        var made: usize = 0;
        errdefer for (tapes[0..made]) |*t| t.deinit();
        for (sizes, &tapes, &boundaries) |steps, *tape, *boundary| {
            const c = &session.keccak.base.cpu;
            tape.* = try rv.compact_tape.Tape.init(a, steps, c.pc, c.retired, .ethereum_services_v3);
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
                // Same register clocks as the native batch (rv64_ethereum_batch).
                const effects = rv.execution_profile.effects(.ethereum_services_v2, record.opcode);
                const tick: u32 = @intCast(4 * local);
                if (effects.reads_rs1 and record.rs1 != 0) boundary.register_clocks[record.rs1] = tick + 1;
                if (effects.reads_rs2 and record.rs2 != 0) boundary.register_clocks[record.rs2] = tick + 2;
                if (effects.writes_rd and record.rd != 0) boundary.register_clocks[record.rd] = tick + 3;
            }
            boundary.final_pc = c.pc;
            boundary.final_registers = c.regs;
        }
        const loaded = session.keccak.base.cpu.regs[9];
        var n0 = try Native.captureForCombinedServicesV3(a, program, boundaries[0], 1, CPU_LOG, &tapes[0], .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, boundaries[1], 2, CPU_LOG, &tapes[1], .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &tapes[0], &tapes[1] }, image());
        errdefer advice.deinit();
        // Chronology: every service family in both shards, the memcpy reads
        // SHA-256's epoch-1 output, the second arith call re-reads its own r.
        if (advice.sha256[0].len != 1 or advice.sha256[1].len != 1 or advice.arith256_mod[0].len != 1 or advice.arith256_mod[1].len != 1) return error.InvalidV3FixtureChronology;
        if (advice.bulk[0].calls.len != 1 or advice.bulk[0].calls[0].op != .set or advice.bulk[1].calls.len != 1 or advice.bulk[1].calls[0].op != .copy) return error.InvalidV3FixtureChronology;
        if (advice.bulk[1].words[0].src.epoch != 1 or advice.bulk[1].words[0].src.value != advice.sha256[0][0].after[0]) return error.InvalidV3FixtureChronology;
        if (advice.arith256_mod[1][0].predecessors[16].epoch != 1 or advice.arith256_mod[1][0].before[16] != advice.arith256_mod[0][0].after[16]) return error.InvalidV3FixtureChronology;
        if (loaded != advice.sha256[0][0].after[0]) return error.InvalidV3FixtureChronology;
        return .{ .allocator = a, .program = program, .tapes = tapes, .native = .{ n0, n1 }, .advice = advice, .loaded = loaded };
    }
    pub fn deinit(self: *Captured) void {
        self.advice.deinit();
        for (&self.native) |*n| n.deinit();
        for (&self.tapes) |*t| t.deinit();
        self.program.deinit();
        self.allocator.destroy(self.program);
    }
};

pub fn truthsFor(sha: *const HR.TruthSetup, arith: *const AR.TruthSetup) [2]R.Truth {
    return .{ .{ .sha256 = .{ .setup = sha, .first_id = 1, .calls = 2 } }, .{ .arith256_mod = .{ .setup = arith, .first_id = 1, .calls = 2 } } };
}

pub const Case = struct {
    allocator: std.mem.Allocator,
    setups: [2]*R.CpuSetup,
    sha: *HR.TruthSetup,
    arith: *AR.TruthSetup,
    loaded: u64,
    bundle: E.Bundle,
    /// Locally valid but false proofs only global closure can reject:
    /// wrong_sha_output / wrong_arith_output (Wire35), wrong_copied_word
    /// (RAM), wrong_fill (RAM + OWNER token), stale_copy_source (RAM).
    pub const Mutation = enum { none, wrong_sha_output, wrong_arith_output, wrong_copied_word, wrong_fill, stale_copy_source };
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn truths(self: *const Case) [2]R.Truth {
        return truthsFor(self.sha, self.arith);
    }
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity, self.loaded);
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
    fn setTerminal(advice: *C.Advice, address: u64, value: u64) void {
        for (advice.terminal) |*cell| if (cell.address == address) {
            cell.state.value = value;
        };
    }
    /// Producer layout options; every one is a Geometry field, so it is
    /// declared in the wire and mixed into each CPU transcript.
    pub const Options = struct { cpu_fused_tail: bool = false };
    pub fn init(a: std.mem.Allocator, mutation: Mutation) !Case {
        return initWith(a, mutation, .{});
    }
    pub fn initWith(a: std.mem.Allocator, mutation: Mutation, options: Options) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        const advice = &captured.advice;
        switch (mutation) {
            .none => {},
            .wrong_sha_output => {
                const c = &advice.sha256[1][0];
                c.after[1] ^= 1;
                setTerminal(advice, S + 8, c.after[1]);
            },
            .wrong_arith_output => {
                const c = &advice.arith256_mod[1][0];
                c.after[16] ^= 1;
                setTerminal(advice, AR_PACKET + 128, c.after[16]);
            },
            .wrong_copied_word => {
                const w = &advice.bulk[1].words[2];
                w.src.value ^= 1;
                setTerminal(advice, D2 + 16, w.src.value);
            },
            .wrong_fill => {
                const set = &advice.bulk[0].calls[0];
                set.word1 ^= 0x01;
                set.packet[1].value ^= 0x01;
            },
            .stale_copy_source => {
                const w = &advice.bulk[1].words[0];
                w.src = .{ .value = initialWord(S), .rights = 3 };
                setTerminal(advice, D2, w.src.value);
            },
        }
        var setups: [2]*R.CpuSetup = undefined;
        var made: usize = 0;
        errdefer for (setups[0..made]) |s| {
            s.deinit();
            a.destroy(s);
        };
        for (&setups, BRIDGES, captured.native) |*out, bridges, native| {
            const s = try a.create(R.CpuSetup);
            errdefer a.destroy(s);
            // 46 touched words: the boundary columns need 2^6 rows.
            var geometry = try native.geometry();
            geometry.initial_log = BOUNDARY_LOG;
            geometry.terminal_log = BOUNDARY_LOG;
            geometry.cpu_fused_tail = options.cpu_fused_tail;
            s.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, geometry, bridges);
            out.* = s;
            made += 1;
        }
        const sha = try a.create(HR.TruthSetup);
        errdefer a.destroy(sha);
        sha.* = try HR.TruthSetup.init(a, SHA_LOG);
        errdefer sha.deinit();
        const arith = try a.create(AR.TruthSetup);
        errdefer a.destroy(arith);
        arith.* = try AR.TruthSetup.init(a, ARITH_LOG);
        errdefer arith.deinit();
        const roster = truthsFor(sha, arith);
        const bundle = try E.produce(a, &.{ setups[0], setups[1] }, &roster, &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity, captured.loaded));
        return .{ .allocator = a, .setups = setups, .sha = sha, .arith = arith, .loaded = captured.loaded, .bundle = bundle };
    }
};
