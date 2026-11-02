//! ethereum_services_v3 Keccak-sponge fixture: real v3 executor tapes in two
//! CPU shards sharing one global RAM chain and one Keccak IO11 ID space.
//!
//! Shard 0 (epoch 1): Keccak-f(KF) (ID 1); sponge A = Keccak-256 of 300
//!   bytes at an address with shift 3 into state SA (fresh + finalize, IDs
//!   2..4).
//! Shard 1 (epoch 2): sponge C = Keccak-256 of A's 32-byte digest read from SA
//!   into SC (fresh + finalize, ID 5); LD x9 <- SA; sponge B absorbs one more
//!   aligned 136-byte block into SA (non-fresh, no finalize, ID 6).
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const rv = front.rv64;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Program = @import("../../word16_execution/program.zig").Program;
const KR = @import("../keccak/shared/roster.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const C = @import("collector.zig");
const E = @import("execution.zig");
const T = @import("types.zig");

pub const BASE: u64 = 0x8000000000002000;
pub const KF: u64 = BASE; // Keccak-f state, 200 bytes
pub const SA: u64 = BASE + 0x100; // sponge A/B state
pub const SC: u64 = BASE + 0x200; // sponge C state
pub const PA: u64 = BASE + 0x300; // packets A, C, B (32 bytes each)
pub const PC: u64 = BASE + 0x320;
pub const PB: u64 = BASE + 0x340;
pub const MA: u64 = BASE + 0x403; // 300-byte message, shift 3
pub const MB: u64 = BASE + 0x600; // 136-byte aligned block
pub const SIZE: u64 = 0x700;
const KECCAK_TAG: u64 = 0x10001;
const SPONGE_TAG: u64 = 0x30130;
pub const LEN_A: u64 = 300;

fn mv(rd: u32, rs1: u32) u32 {
    return (rs1 << 15) | (rd << 7) | 0x13;
}
const ECALL: u32 = 0x73;
/// ld x9, 0(x6)
const LD_SA: u32 = (6 << 15) | (3 << 12) | (9 << 7) | 0x03;
pub const WORDS = [_]u32{
    // shard 0
    mv(10, 5), mv(17, 18), ECALL, // Keccak-f
    mv(10, 7), mv(17, 19), ECALL, // sponge A
    // shard 1
    mv(10, 28), ECALL, // sponge C (a7 still the sponge tag)
    LD_SA,
    mv(10, 29), ECALL, // sponge B
};
pub const SHARD0_STEPS: u32 = 6;
pub const STEPS: u32 = WORDS.len;
pub const CPU_LOG: u32 = 5;
pub const BOUNDARY_LOG: u32 = 8;
const marker: u8 = 0;

pub fn messageByte(i: u64) u8 {
    return @truncate(i *% 0x9D +% 0x41);
}
fn initialWord(address: u64) u64 {
    return switch (address) {
        PA => SA,
        PA + 8 => MA,
        PA + 16 => LEN_A,
        PA + 24 => 3, // fresh | finalize
        PC => SC,
        PC + 8 => SA,
        PC + 16 => 32,
        PC + 24 => 3,
        PB => SA,
        PB + 8 => MB,
        PB + 16 => 136,
        PB + 24 => 0, // absorb only
        else => blk: {
            if (address >= MA & ~@as(u64, 7) and address < MA + LEN_A + 8) {
                var w: u64 = 0;
                for (0..8) |b| {
                    const at = address + b;
                    const byte: u64 = if (at >= MA and at < MA + LEN_A) messageByte(at - MA) else 0xEE;
                    w |= byte << @intCast(8 * b);
                }
                break :blk w;
            }
            break :blk address *% 0x9E3779B97F4A7C15;
        },
    };
}
fn initial(_: *const anyopaque, address: u64) !u64 {
    if (address < BASE or address >= BASE + SIZE or address & 7 != 0) return error.UntrustedSpongeFixtureAddress;
    return initialWord(address);
}
fn rights(_: *const anyopaque, address: u64) !u2 {
    if (address < BASE or address >= BASE + SIZE) return error.UntrustedSpongeFixtureAddress;
    return 3;
}
pub fn image() @import("../../word16_execution/memory/statement.zig").Image {
    return .{ .context = &marker, .initial_word = initial, .rights_at = rights };
}
pub fn initialRegisters() [32]u64 {
    var r: [32]u64 = @splat(0);
    r[5] = KF;
    r[6] = SA;
    r[7] = PA;
    r[28] = PC;
    r[29] = PB;
    r[18] = KECCAK_TAG;
    r[19] = SPONGE_TAG;
    return r;
}
pub fn finalRegisters(loaded: u64) [32]u64 {
    var r = initialRegisters();
    r[10] = PB;
    r[17] = SPONGE_TAG;
    r[9] = loaded;
    return r;
}
pub fn expectedFor(identity: [32]u8, loaded: u64) P.Expected {
    return .{ .admission = .{ .image = image(), .image_identity = @splat(0x4b), .initial_pc = 4096, .initial_registers = initialRegisters(), .max_prefix_steps = 31 }, .program_identity = identity, .total_steps = STEPS, .max_total_steps = STEPS, .final_pc = 4096 + 4 * STEPS, .final_registers = finalRegisters(loaded) };
}
pub const BRIDGES = [2]T.Logs{
    .{ .keccak = 5, .sponge = .{ .call = 5, .perm = 5 } },
    .{ .sponge = .{ .call = 5, .perm = 5 } },
};
pub const KECCAK_LOG: u32 = 7;
pub const KECCAK_IDS: u32 = 6;

pub const Captured = struct {
    allocator: std.mem.Allocator,
    program: *Program,
    tapes: [2]rv.compact_tape.Tape,
    native: [2]Native,
    advice: C.Advice,
    loaded: u64,
    digest_a: [32]u8,
    digest_c: [32]u8,
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
        var digest_a: [32]u8 = undefined;
        for (sizes, &tapes, &boundaries, 0..) |steps, *tape, *boundary, shard| {
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
                const effects = rv.execution_profile.effects(.ethereum_services_v2, record.opcode);
                const tick: u32 = @intCast(4 * local);
                if (effects.reads_rs1 and record.rs1 != 0) boundary.register_clocks[record.rs1] = tick + 1;
                if (effects.reads_rs2 and record.rs2 != 0) boundary.register_clocks[record.rs2] = tick + 2;
                if (effects.writes_rd and record.rd != 0) boundary.register_clocks[record.rd] = tick + 3;
            }
            boundary.final_pc = c.pc;
            boundary.final_registers = c.regs;
            if (shard == 0) for (0..4) |l| std.mem.writeInt(u64, digest_a[8 * l ..][0..8], try memory.load(SA + 8 * l, 8), .little);
        }
        var digest_c: [32]u8 = undefined;
        for (0..4) |l| std.mem.writeInt(u64, digest_c[8 * l ..][0..8], try memory.load(SC + 8 * l, 8), .little);
        const loaded = session.keccak.base.cpu.regs[9];
        var n0 = try Native.captureForCombinedServicesV3(a, program, boundaries[0], 1, CPU_LOG, &tapes[0], .{});
        errdefer n0.deinit();
        var n1 = try Native.captureForCombinedServicesV3(a, program, boundaries[1], 2, CPU_LOG, &tapes[1], .{});
        errdefer n1.deinit();
        var advice = try C.collect(a, &.{ &n0, &n1 }, &.{ &tapes[0], &tapes[1] }, image());
        errdefer advice.deinit();
        if (advice.keccak[0].len != 1 or advice.sponge[0].calls.len != 1 or advice.sponge[0].inputs.len != 3 or advice.sponge[1].calls.len != 2 or advice.sponge[1].inputs.len != 2) return error.InvalidSpongeFixtureChronology;
        // C reads A's epoch-1 output state as its message.
        if (advice.sponge[1].words[0].epoch != 1) return error.InvalidSpongeFixtureChronology;
        return .{ .allocator = a, .program = program, .tapes = tapes, .native = .{ n0, n1 }, .advice = advice, .loaded = loaded, .digest_a = digest_a, .digest_c = digest_c };
    }
    pub fn deinit(self: *Captured) void {
        self.advice.deinit();
        for (&self.native) |*n| n.deinit();
        for (&self.tapes) |*t| t.deinit();
        self.program.deinit();
        self.allocator.destroy(self.program);
    }
};

pub fn truthsFor(k: *const KR.TruthSetup, split: bool, out: *[2]R.Truth) []const R.Truth {
    if (split) {
        out.* = .{ .{ .keccak = .{ .setup = k, .first_id = 1, .calls = 3 } }, .{ .keccak = .{ .setup = k, .first_id = 4, .calls = 3 } } };
        return out;
    }
    out[0] = .{ .keccak = .{ .setup = k, .first_id = 1, .calls = KECCAK_IDS } };
    return out[0..1];
}

pub const Case = struct {
    allocator: std.mem.Allocator,
    setups: [2]*R.CpuSetup,
    keccak: *KR.TruthSetup,
    split: bool,
    loaded: u64,
    captured_digests: [2][32]u8,
    bundle: E.Bundle,
    /// Locally valid but false witnesses only global closure can reject:
    /// wrong_truth_input (IO11), stale_message (RAM), forged_message (RAM).
    pub const Mutation = enum { none, wrong_truth_input, stale_message, forged_message };
    pub fn keys(self: *const Case) [2]*const R.CpuSetup {
        return .{ self.setups[0], self.setups[1] };
    }
    pub fn truths(self: *const Case, out: *[2]R.Truth) []const R.Truth {
        return truthsFor(self.keccak, self.split, out);
    }
    pub fn expected(self: *const Case) P.Expected {
        return expectedFor(self.setups[0].materials.program.identity, self.loaded);
    }
    pub fn deinit(self: *Case) void {
        self.bundle.deinit(self.allocator);
        self.keccak.deinit();
        self.allocator.destroy(self.keccak);
        for (self.setups) |s| {
            s.deinit();
            self.allocator.destroy(s);
        }
    }
    pub fn init(a: std.mem.Allocator, mutation: Mutation, split: bool) !Case {
        return initPolicy(a, mutation, split, .triple_v2);
    }
    /// `policy` selects the Keccak-f truth's lookup profile (v3 throughput or compact).
    pub fn initPolicy(a: std.mem.Allocator, mutation: Mutation, split: bool, policy: KR.TruthSetup.Policy) !Case {
        return initLayout(a, mutation, split, policy, .{});
    }
    /// CPU AIR layout of both shards (the v3 Ethereum route's fused tail and
    /// byte pairs): the sponge's byte-AND service multiplicities then merge
    /// into the pair-capable AND table (services/roster.zig mergeAnd).
    pub const Layout = struct { cpu_fused_tail: bool = false, cpu_u8_pairs: bool = false };
    pub fn initLayout(a: std.mem.Allocator, mutation: Mutation, split: bool, policy: KR.TruthSetup.Policy, layout: Layout) !Case {
        var captured = try Captured.init(a);
        defer captured.deinit();
        const advice = &captured.advice;
        switch (mutation) {
            .none => {},
            // C hashes a different (forged) message word: the bridge and the
            // truth agree, but RAM never held that value.
            .forged_message => advice.sponge[1].words[1].value ^= 0x100,
            // C reads A's digest word before A wrote it (initial image value).
            .stale_message => advice.sponge[1].words[0] = .{ .value = initialWord(SA), .rights = 3 },
            // The Keccak-f truth permutes a different state for A's middle
            // permutation (ID 3) than the bridge consumes: only IO11 sees it.
            .wrong_truth_input => advice.sponge[0].inputs[1][20] ^= 1,
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
            var geometry = try native.geometry();
            geometry.initial_log = BOUNDARY_LOG;
            geometry.terminal_log = BOUNDARY_LOG;
            geometry.cpu_fused_tail = layout.cpu_fused_tail;
            geometry.cpu_u8_pairs = layout.cpu_u8_pairs;
            s.* = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &WORDS }, geometry, bridges);
            out.* = s;
            made += 1;
        }
        const k = try a.create(KR.TruthSetup);
        errdefer a.destroy(k);
        k.* = try KR.TruthSetup.initPolicy(a, KECCAK_LOG, @import("../keccak/shared/key.zig").Key.Suite.production(), policy);
        errdefer k.deinit();
        var buffer: [2]R.Truth = undefined;
        const bundle = try E.produce(a, &.{ setups[0], setups[1] }, truthsFor(k, split, &buffer), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expectedFor(captured.program.identity, captured.loaded));
        return .{ .allocator = a, .setups = setups, .keccak = k, .split = split, .loaded = captured.loaded, .captured_digests = .{ captured.digest_a, captured.digest_c }, .bundle = bundle };
    }
};
