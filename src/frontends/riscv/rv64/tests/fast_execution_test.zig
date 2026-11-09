//! Differential tests: fast_execution.Engine interleaved with reference
//! retirement must equal reference-only execution in every architectural
//! effect (registers, pc, clock, trap, bytes, page set, service counters) and
//! in the per-opcode census, on random RV64IM programs and on every service.
const std = @import("std");
const isa = @import("../decode.zig");
const mem = @import("../memory.zig");
const machine = @import("../machine.zig");
const fast = @import("../fast_execution.zig");
const eth = @import("../ethereum_services/session.zig");
const profile = @import("../execution_profile.zig");
const checkpoint = @import("../checkpoint.zig");
const Base = @import("../session.zig");
const a = std.testing.allocator;

const CODE: u64 = 0x10000;
const DATA: u64 = 0x40000;
const DATA_PAGES = 6;
const SLOTS = 600;

fn rType(f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}
fn iType(imm: i32, rs1: u32, f3: u32, rd: u32, op: u32) u32 {
    return (@as(u32, @bitCast(imm)) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op;
}
fn sType(imm: i32, rs2: u32, rs1: u32, f3: u32) u32 {
    const u: u32 = @bitCast(imm);
    return (((u >> 5) & 127) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((u & 31) << 7) | 0x23;
}
fn bType(imm: i32, rs2: u32, rs1: u32, f3: u32) u32 {
    const u: u32 = @bitCast(imm);
    return (((u >> 12) & 1) << 31) | (((u >> 5) & 63) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (((u >> 1) & 15) << 8) | (((u >> 11) & 1) << 7) | 0x63;
}
fn jType(imm: i32, rd: u32) u32 {
    const u: u32 = @bitCast(imm);
    return (((u >> 20) & 1) << 31) | (((u >> 1) & 1023) << 21) | (((u >> 11) & 1) << 20) | (((u >> 12) & 255) << 12) | (rd << 7) | 0x6f;
}

/// Destination register: mostly free registers, rarely a base register.
fn dest(r: std.Random) u32 {
    if (r.uintLessThan(u32, 64) == 0) return r.uintLessThan(u32, 32);
    const free = [_]u32{ 0, 1, 3, 4, 8, 9, 11, 12, 13, 14, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    return free[r.uintLessThan(usize, free.len)];
}
fn src(r: std.Random) u32 {
    return r.uintLessThan(u32, 32);
}

fn randomWord(r: std.Random, slot: usize, ecalls: bool) u32 {
    const pc: i64 = @intCast(CODE + 4 * slot);
    const kind = r.uintLessThan(u32, 100);
    if (kind < 30) {
        const ops = [_][3]u32{ .{ 0, 0, 0x33 }, .{ 32, 0, 0x33 }, .{ 0, 1, 0x33 }, .{ 0, 2, 0x33 }, .{ 0, 3, 0x33 }, .{ 0, 4, 0x33 }, .{ 0, 5, 0x33 }, .{ 32, 5, 0x33 }, .{ 0, 6, 0x33 }, .{ 0, 7, 0x33 }, .{ 1, 0, 0x33 }, .{ 1, 1, 0x33 }, .{ 1, 2, 0x33 }, .{ 1, 3, 0x33 }, .{ 1, 4, 0x33 }, .{ 1, 5, 0x33 }, .{ 1, 6, 0x33 }, .{ 1, 7, 0x33 }, .{ 0, 0, 0x3b }, .{ 32, 0, 0x3b }, .{ 0, 1, 0x3b }, .{ 0, 5, 0x3b }, .{ 32, 5, 0x3b }, .{ 1, 0, 0x3b }, .{ 1, 4, 0x3b }, .{ 1, 5, 0x3b }, .{ 1, 6, 0x3b }, .{ 1, 7, 0x3b } };
        const o = ops[r.uintLessThan(usize, ops.len)];
        return rType(o[0], src(r), src(r), o[1], dest(r), o[2]);
    }
    if (kind < 50) {
        const imm: i32 = r.intRangeAtMost(i32, -2048, 2047);
        return switch (r.uintLessThan(u32, 13)) {
            0 => iType(imm, src(r), 0, dest(r), 0x13),
            1 => iType(imm, src(r), 2, dest(r), 0x13),
            2 => iType(imm, src(r), 3, dest(r), 0x13),
            3 => iType(imm, src(r), 4, dest(r), 0x13),
            4 => iType(imm, src(r), 6, dest(r), 0x13),
            5 => iType(imm, src(r), 7, dest(r), 0x13),
            6 => iType(@as(i32, @intCast(r.uintLessThan(u32, 64))), src(r), 1, dest(r), 0x13),
            7 => iType(@as(i32, @intCast(r.uintLessThan(u32, 64))), src(r), 5, dest(r), 0x13),
            8 => iType(1024 | @as(i32, @intCast(r.uintLessThan(u32, 64))), src(r), 5, dest(r), 0x13),
            9 => iType(imm, src(r), 0, dest(r), 0x1b),
            10 => iType(@as(i32, @intCast(r.uintLessThan(u32, 32))), src(r), 1, dest(r), 0x1b),
            11 => iType(@as(i32, @intCast(r.uintLessThan(u32, 32))), src(r), 5, dest(r), 0x1b),
            else => iType(1024 | @as(i32, @intCast(r.uintLessThan(u32, 32))), src(r), 5, dest(r), 0x1b),
        };
    }
    if (kind < 70) {
        // Loads/stores off x5 (DATA + 0x800) or x7 (a page edge); mostly aligned.
        const f3 = r.uintLessThan(u32, 7);
        const store = r.boolean();
        const width: i32 = @as(i32, 1) << @intCast(if (store) f3 % 4 else f3 % 4);
        var imm: i32 = r.intRangeAtMost(i32, -2048, 2047);
        if (r.uintLessThan(u32, 40) != 0) imm = @divFloor(imm, width) * width;
        const base: u32 = if (r.uintLessThan(u32, 8) == 0) 7 else 5;
        if (store) return sType(imm, src(r), base, f3 % 4);
        return iType(imm, base, f3, dest(r), 0x03);
    }
    if (kind < 82) {
        const target: i64 = @intCast(CODE + 4 * r.uintLessThan(usize, SLOTS));
        var off: i32 = @intCast(target - pc);
        if (r.uintLessThan(u32, 50) == 0) off += 2; // misaligned target: trap only if taken
        const f3s = [_]u32{ 0, 1, 4, 5, 6, 7 };
        return bType(off, src(r), src(r), f3s[r.uintLessThan(usize, f3s.len)]);
    }
    if (kind < 86) {
        const target: i64 = @intCast(CODE + 4 * r.uintLessThan(usize, SLOTS));
        return jType(@intCast(target - pc), dest(r));
    }
    if (kind < 89) {
        // jalr off x6 = CODE; odd/2-mod-4 offsets exercise bit-0 clearing and traps.
        var imm: i32 = @intCast(4 * r.uintLessThan(u32, 500));
        if (r.uintLessThan(u32, 10) == 0) imm += @as(i32, @intCast(r.uintLessThan(u32, 4)));
        return iType(imm, 6, 0, dest(r), 0x67);
    }
    if (kind == 92) return switch (r.uintLessThan(u32, 7)) {
        0 => rType(0x20, src(r), src(r), 7, dest(r), 0x33), // andn
        1 => rType(0x20, src(r), src(r), 6, dest(r), 0x33), // orn
        2 => rType(0x20, src(r), src(r), 4, dest(r), 0x33), // xnor
        3 => iType(0x604, src(r), 1, dest(r), 0x13), // sext.b
        4 => iType(0x605, src(r), 1, dest(r), 0x13), // sext.h
        5 => iType(0x6b8, src(r), 5, dest(r), 0x13), // rev8
        else => rType(0x04, 0, src(r), 4, dest(r), 0x3b), // zext.h
    };
    if (kind < 93) return (r.int(u32) & 0xfffff000) | (dest(r) << 7) | (if (r.boolean()) @as(u32, 0x37) else 0x17);
    if (kind < 95) return 0x0ff0000f; // fence
    if (kind < 97 and ecalls) return 0x73;
    if (kind == 97) return 0x00100073; // ebreak
    if (kind == 98) return r.int(u32); // anything, usually illegal
    return iType(r.intRangeAtMost(i32, -2048, 2047), src(r), 0, dest(r), 0x13);
}

const Image = struct {
    memory: mem.Memory,
    fn init(words: []const u32, seed: u64) !Image {
        var m = mem.Memory.init(a, .{});
        errdefer m.deinit();
        try m.map(.{ .start = CODE, .size = 4 * words.len, .permissions = .{ .read = true, .execute = true } });
        for (words, 0..) |word, i| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try m.initialize(CODE + 4 * i, &bytes);
        }
        // Writable data with one read-only page and one partial-rights page.
        try m.map(.{ .start = DATA, .size = 2 * mem.PAGE_SIZE, .permissions = .{ .read = true, .write = true } });
        try m.map(.{ .start = DATA + 2 * mem.PAGE_SIZE, .size = mem.PAGE_SIZE, .permissions = .{ .read = true } });
        try m.map(.{ .start = DATA + 3 * mem.PAGE_SIZE, .size = 0x800, .permissions = .{ .read = true, .write = true } });
        try m.map(.{ .start = DATA + 3 * mem.PAGE_SIZE + 0x800, .size = 0x800 + 2 * mem.PAGE_SIZE, .permissions = .{ .read = true, .write = true } });
        var prng = std.Random.DefaultPrng.init(seed);
        var bytes: [mem.PAGE_SIZE]u8 = undefined;
        prng.random().bytes(&bytes);
        // Pages 0 and 2 exist; pages 1, 4 and 5 are absent until written.
        try m.initialize(DATA, &bytes);
        try m.initialize(DATA + 2 * mem.PAGE_SIZE, &bytes);
        try m.initialize(DATA + 3 * mem.PAGE_SIZE + 8, bytes[0..64]);
        return .{ .memory = m };
    }
    fn deinit(self: *Image) void {
        self.memory.deinit();
    }
};

fn initialCpu(r: std.Random) machine.Cpu {
    var cpu = machine.Cpu.init(CODE, 0);
    for (1..32) |i| cpu.regs[i] = switch (r.uintLessThan(u32, 4)) {
        0 => r.int(u64),
        1 => r.int(u8),
        2 => @bitCast(@as(i64, r.intRangeAtMost(i8, -128, 127))),
        else => @as(u64, 0x8000_0000_0000_0000) >> r.int(u6),
    };
    cpu.regs[5] = DATA + 0x800;
    cpu.regs[6] = CODE;
    cpu.regs[7] = DATA + mem.PAGE_SIZE + 0x800;
    return cpu;
}

const Outcome = struct {
    cpu: machine.Cpu,
    stop: ?anyerror,
    counts: [@typeInfo(isa.Opcode).@"enum".fields.len]u64 = @splat(0),
};

fn expectSameMemory(x: *mem.Memory, y: *mem.Memory) !void {
    try std.testing.expectEqual(x.pageCount(), y.pageCount());
    var it = x.backing.table.iterator();
    while (it.next()) |entry| {
        const other = y.backing.table.get(entry.key_ptr.*) orelse return error.TestPageSetDiffers;
        try std.testing.expectEqualSlices(u8, entry.value_ptr.*, other);
    }
}

fn referenceRun(m: *mem.Memory, start: machine.Cpu, limit: u64, set: isa.Isa) !Outcome {
    var out = Outcome{ .cpu = start, .stop = null };
    var session = try Base.Session.init(a, start, m, .{ .max_retirements = limit, .isa = set });
    defer session.deinit();
    while (session.cpu.retired < limit) {
        const row = session.step() catch |err| {
            out.stop = err;
            break;
        };
        out.counts[@intFromEnum(row.opcode)] += 1;
    }
    out.cpu = session.cpu;
    return out;
}

/// Fast engine with random intermediate budgets (checkpoint boundaries).
fn fastRun(m: *mem.Memory, start: machine.Cpu, limit: u64, r: std.Random, engine: *fast.Engine, set: isa.Isa) !Outcome {
    var out = Outcome{ .cpu = start, .stop = null };
    var session = try Base.Session.init(a, start, m, .{ .max_retirements = limit, .isa = set });
    defer session.deinit();
    while (session.cpu.retired < limit) {
        const budget = @min(limit, session.cpu.retired + 1 + r.uintLessThan(u64, 3000));
        if (engine.run(&session.cpu, budget) == .limit) continue;
        const row = session.step() catch |err| {
            out.stop = err;
            break;
        };
        out.counts[@intFromEnum(row.opcode)] += 1;
    }
    out.cpu = session.cpu;
    var loads: u64 = 0;
    var stores: u64 = 0;
    engine.census(&out.counts, &loads, &stores, null);
    return out;
}

test "fast engine: random RV64IM programs equal the reference interpreter" {
    var prng = std.Random.DefaultPrng.init(0xfa57_e9ec);
    const r = prng.random();
    var total_fast: u64 = 0;
    var total: u64 = 0;
    var traps: usize = 0;
    var zbb: u64 = 0;
    for (0..1500) |program| {
        var words: [SLOTS]u32 = undefined;
        for (&words, 0..) |*w, i| w.* = randomWord(r, i, true);
        const seed = r.int(u64);
        const start = initialCpu(r);
        const limit = 1 + r.uintLessThan(u64, 20000);
        var ref = try Image.init(&words, seed);
        defer ref.deinit();
        var subject = try Image.init(&words, seed);
        defer subject.deinit();
        // Half the programs run under the admitted Zbb BINARY ISA.
        const set: isa.Isa = if (program % 2 == 0) .rv64im else .rv64im_zbb_binary;
        const expected = try referenceRun(&ref.memory, start, limit, set);
        var engine = try fast.Engine.init(a, &subject.memory, .{ .counting = true, .isa = set, .watch = if (program % 3 == 0) &.{.{ DATA + 0x100, 8 }} else &.{} });
        defer engine.deinit();
        const actual = try fastRun(&subject.memory, start, limit, r, &engine, set);
        try std.testing.expectEqualDeep(expected.cpu, actual.cpu);
        try std.testing.expectEqual(expected.stop, actual.stop);
        try std.testing.expectEqualSlices(u64, &expected.counts, &actual.counts);
        try expectSameMemory(&ref.memory, &subject.memory);
        total_fast += engine.fast_retired;
        for (expected.counts[isa.BASE_OPCODE_COUNT..]) |n| zbb += n;
        total += actual.cpu.retired;
        if (actual.stop != null) traps += 1;
    }
    // The generator must actually exercise the fast path and the trap path.
    try std.testing.expect(total_fast * 2 > total);
    try std.testing.expect(traps > 100);
    try std.testing.expect(zbb > 1000);
}

test "fast engine: watched stores and stop pcs are left to the caller" {
    // sd x9, 0(x5); addi x9, x9, 1; jal x0, -8 ; stop pc at slot 1.
    const words = [_]u32{ sType(0, 9, 5, 3), iType(1, 9, 0, 9, 0x13), jType(-8, 0) };
    var image = try Image.init(&words, 1);
    defer image.deinit();
    var engine = try fast.Engine.init(a, &image.memory, .{ .watch = &.{.{ DATA + 0x800, 1 }} });
    defer engine.deinit();
    var cpu = machine.Cpu.init(CODE, 0);
    cpu.regs[5] = DATA + 0x800;
    try std.testing.expectEqual(fast.Exit.slow, engine.run(&cpu, 100));
    try std.testing.expectEqual(@as(u64, 0), cpu.retired);
    var stopping = try fast.Engine.init(a, &image.memory, .{ .stop_pcs = &.{CODE + 4} });
    defer stopping.deinit();
    try std.testing.expectEqual(fast.Exit.slow, stopping.run(&cpu, 100));
    try std.testing.expectEqual(@as(u64, 1), cpu.retired);
    try std.testing.expectEqual(CODE + 4, cpu.pc);
    try std.testing.expectEqual(@as(u64, 0), try image.memory.load(DATA + 0x800, 8));
    // Budget stops exactly at the limit, mid-block.
    cpu.pc = CODE;
    try std.testing.expectEqual(fast.Exit.limit, engine.run(&cpu, 1));
}

test "fast engine: dirty set covers every page written by fast or reference stores" {
    var prng = std.Random.DefaultPrng.init(0xd1e7);
    const r = prng.random();
    for (0..300) |_| {
        var words: [SLOTS]u32 = undefined;
        for (&words, 0..) |*w, i| w.* = randomWord(r, i, false);
        var image = try Image.init(&words, r.int(u64));
        defer image.deinit();
        var engine = try fast.Engine.init(a, &image.memory, .{});
        defer engine.deinit();
        engine.attach();
        var before = std.AutoHashMap(u64, [mem.PAGE_SIZE]u8).init(a);
        defer before.deinit();
        var it = image.memory.backing.table.iterator();
        while (it.next()) |e| try before.put(e.key_ptr.*, e.value_ptr.*.*);
        var cpu = initialCpu(r);
        _ = try fastRun(&image.memory, cpu, 1 + r.uintLessThan(u64, 5000), r, &engine, .rv64im);
        cpu = undefined;
        var after = image.memory.backing.table.iterator();
        while (after.next()) |e| {
            const old = before.get(e.key_ptr.*);
            const changed = if (old) |o| !std.mem.eql(u8, &o, e.value_ptr.*) else true;
            if (changed) try std.testing.expect(engine.dirty.isSet(e.key_ptr.*));
        }
        try std.testing.expect(!engine.dirty.overflow);
    }
}

fn servicePacket(m: *mem.Memory, tag: u64, base: u64, r: std.Random) !void {
    var words: [64]u64 = undefined;
    // Small field elements keep curve packets inside their domains.
    for (&words) |*w| w.* = if (profile.isCurveTag(tag)) r.int(u32) | 1 else r.int(u64);
    if (eth.bulk_memory.kindOf(tag)) |kind| switch (kind) {
        .jumpdest => {
            words[0] = base + 0x3e0; // 64-byte aligned code
            words[1] = 8 * (1 + r.uintLessThan(u64, 64));
            words[2] = base + 0x1000;
        },
        else => {
            words[0] = base + 0x400;
            words[1] = switch (kind) {
                .memset => r.int(u8),
                .memcpy => base + 0x800 + if (r.boolean()) @as(u64, 0) else r.uintLessThan(u64, 8),
                else => base + 0x800,
            };
            words[2] = 8 * (1 + r.uintLessThan(u64, 64));
        },
    } else if (tag == profile.KECCAK_SPONGE_TAG) {
        words[0] = base + 0x400;
        words[1] = base + 0x800 + r.uintLessThan(u64, 8);
        words[2] = r.uintLessThan(u64, 300);
        words[3] = eth.keccak_sponge.FINALIZE | if (r.boolean()) eth.keccak_sponge.FRESH else 0;
    }
    try m.storeWords(base, &words);
}

test "fast engine: every Ethereum service interleaves exactly like the reference session" {
    var prng = std.Random.DefaultPrng.init(0x5e71ce);
    const r = prng.random();
    var tags = std.ArrayList(u64).empty;
    defer tags.deinit(a);
    try tags.appendSlice(a, &.{ profile.KECCAK_TAG, profile.SECP_ADD_WORD_TAG, profile.SECP_DOUBLE_WORD_TAG, profile.SHA256_COMPRESS_TAG, profile.ARITH256_MOD_TAG, profile.MEMCPY_TAG, profile.MEMSET_TAG, profile.MEMCMP_TAG, profile.JUMPDEST_TAG, profile.KECCAK_SPONGE_TAG, 0xdead });
    try tags.appendSlice(a, &profile.CURVE_TAGS);
    // Loop: mutate the packet's tail with fast stores, ecall, count, repeat.
    //   ld x12, 64(x10); addi x12, x12, 3; sd x12, 64(x10); ecall;
    //   addi x13, x13, 1; ld x14, 0(x10); add x15, x15, x14; jal x0, -28
    const words = [_]u32{ iType(64, 10, 3, 12, 0x03), iType(3, 12, 0, 12, 0x13), sType(64, 12, 10, 3), 0x73, iType(1, 13, 0, 13, 0x13), iType(0, 10, 3, 14, 0x03), rType(0, 14, 15, 0, 15, 0x33), jType(-28, 0) };
    for (tags.items) |tag| for (0..8) |_| {
        const seed = r.int(u64);
        var images: [2]Image = undefined;
        var sessions: [2]eth.Session = undefined;
        for (&images, &sessions) |*image, *session| {
            image.* = try Image.init(&words, seed);
            var pr = std.Random.DefaultPrng.init(seed);
            try servicePacket(&image.memory, tag, DATA + 0x20, pr.random());
            var cpu = machine.Cpu.init(CODE, 0);
            cpu.regs[10] = DATA + 0x20;
            cpu.regs[17] = tag;
            session.* = try eth.Session.initWithProfile(a, cpu, &image.memory, .{ .max_retirements = 4000 }, .ethereum_services_v3);
        }
        defer for (&images, &sessions) |*image, *session| {
            session.deinit();
            image.deinit();
        };
        var event: eth.Event = undefined;
        var ref_stop: ?anyerror = null;
        while (true) _ = sessions[0].step(&event) catch |err| {
            ref_stop = err;
            break;
        };
        var engine = try fast.Engine.init(a, &images[1].memory, .{});
        defer engine.deinit();
        var fast_stop: ?anyerror = null;
        const cpu = &sessions[1].keccak.base.cpu;
        while (true) {
            _ = engine.run(cpu, @min(4000, cpu.retired + 1 + r.uintLessThan(u64, 50)));
            _ = sessions[1].step(&event) catch |err| {
                fast_stop = err;
                break;
            };
        }
        try std.testing.expectEqual(ref_stop, fast_stop);
        try std.testing.expectEqualDeep(sessions[0].keccak.base.cpu, cpu.*);
        try std.testing.expectEqual(sessions[0].keccak.calls, sessions[1].keccak.calls);
        inline for (.{ "add_calls", "double_calls", "sha256_calls", "arith256_mod_calls", "bulk_calls", "sponge_calls", "curve_calls" }) |field|
            try std.testing.expectEqualDeep(@field(sessions[0], field), @field(sessions[1], field));
        try expectSameMemory(&images[0].memory, &images[1].memory);
        if (fast_stop) |e| if (e == error.StepLimit) try std.testing.expect(engine.fast_retired > 0);
        // Packets built for these services are valid: they must run to the budget.
        const must_complete = [_]u64{ profile.KECCAK_TAG, profile.SECP_ADD_WORD_TAG, profile.SECP_DOUBLE_WORD_TAG, profile.SHA256_COMPRESS_TAG, profile.ARITH256_MOD_TAG, profile.MEMCPY_TAG, profile.MEMSET_TAG, profile.MEMCMP_TAG, profile.JUMPDEST_TAG, profile.KECCAK_SPONGE_TAG } ++ profile.CURVE_TAGS;
        if (std.mem.indexOfScalar(u64, &must_complete, tag) != null) try std.testing.expectEqual(@as(?anyerror, error.StepLimit), fast_stop);
        if (std.process.hasEnvVarConstant("FAST_TEST_VERBOSE")) std.debug.print("tag {x} stop {?} fast {d} retired {d}\n", .{ tag, fast_stop, engine.fast_retired, cpu.retired });
    };
}

test "checkpoints: every segment re-executed by the reference from its image meets the next checkpoint" {
    var prng = std.Random.DefaultPrng.init(0xc4ec);
    const r = prng.random();
    var segments_checked: usize = 0;
    for (0..500) |_| {
        var words: [SLOTS]u32 = undefined;
        // Mostly ECALL-free so programs run long; ECALL traps under v3 tag 0.
        for (&words, 0..) |*w, i| w.* = randomWord(r, i, r.uintLessThan(u32, 4) == 0);
        var image = try Image.init(&words, r.int(u64));
        defer image.deinit();
        const total = 1 + r.uintLessThan(u64, 20000);
        const step = 1 + r.uintLessThan(u64, 3000);
        var session = try eth.Session.initWithProfile(a, initialCpu(r), &image.memory, .{ .max_retirements = total }, .ethereum_services_v3);
        defer session.deinit();
        var engine = try fast.Engine.init(a, &image.memory, .{});
        defer engine.deinit();
        engine.attach();
        var recorder = try checkpoint.Recorder.init(a, &engine);
        defer recorder.deinit();
        var cps = std.ArrayList(checkpoint.Checkpoint).empty;
        defer {
            for (cps.items) |*cp| recorder.release(cp);
            cps.deinit(a);
        }
        const cpu = &session.keccak.base.cpu;
        var event: eth.Event = undefined;
        var stopped = false;
        while (!stopped) {
            try cps.append(a, try recorder.take(&session));
            const limit = @min(total, cpu.retired + step);
            while (cpu.retired < limit) {
                if (engine.run(cpu, limit) == .limit) break;
                _ = session.step(&event) catch {
                    stopped = true;
                    break;
                };
            }
            if (cpu.retired == total) stopped = true;
        }
        try cps.append(a, try recorder.take(&session));
        // Re-execute each complete segment from its checkpoint with the reference only.
        for (cps.items[0 .. cps.items.len - 1], cps.items[1..]) |*from, *to| {
            if (to.cpu.retired - from.cpu.retired != step and to.cpu.retired != total) continue;
            var m = try checkpoint.materialize(a, &image.memory, from);
            defer m.deinit();
            var dirty = checkpoint.Dirty{ .bits = try a.alloc(u64, engine.dirty.bits.len) };
            defer a.free(dirty.bits);
            @memset(dirty.bits, 0);
            m.backing.dirty = &dirty;
            var seg = try eth.Session.initWithProfile(a, from.cpu, &m, .{ .max_retirements = to.cpu.retired }, .ethereum_services_v3);
            defer seg.deinit();
            from.counters.apply(&seg);
            while (seg.keccak.base.cpu.retired < to.cpu.retired) _ = seg.step(&event) catch break;
            try std.testing.expect(checkpoint.matches(&seg, &dirty, to));
            segments_checked += 1;
            // Adversarial: a single flipped byte on any page, or a clock off by one, is rejected.
            var it = m.backing.table.iterator();
            if (it.next()) |e| {
                const off = r.uintLessThan(usize, mem.PAGE_SIZE);
                e.value_ptr.*[off] ^= 0x40;
                const was = dirty.isSet(e.key_ptr.*);
                dirty.mark(e.key_ptr.*);
                try std.testing.expect(!checkpoint.matches(&seg, &dirty, to));
                e.value_ptr.*[off] ^= 0x40;
                if (!was) dirty.bits[@intCast(e.key_ptr.* / 64)] &= ~(@as(u64, 1) << @intCast(e.key_ptr.* % 64));
            }
            try std.testing.expect(checkpoint.matches(&seg, &dirty, to));
            seg.keccak.base.cpu.retired += 1;
            try std.testing.expect(!checkpoint.matches(&seg, &dirty, to));
            seg.keccak.base.cpu.retired -= 1;
            seg.keccak.calls += 1;
            try std.testing.expect(!checkpoint.matches(&seg, &dirty, to));
        }
    }
    try std.testing.expect(segments_checked > 300);
}

test {
    _ = @import("stwo_riscv_precompiles");
    _ = @import("stwo_riscv_precompiles");
}

// M6 capture: the traced fast engine (`Engine.runTraced`) interleaved with
// reference traced steps must produce exactly the reference compact tape,
// memory_before words, boundary capture, register clocks and request
// counts (what `Native.captureNext` + `Batch.observe` record), the same
// architectural state and the same stop, on random programs.
const compact_tape = @import("../compact_tape.zig");
const boundary_capture = @import("../boundary_capture.zig");
const Traced = struct {
    tape: compact_tape.Tape,
    capture: boundary_capture.Capture,
    clocks: [32]u32 = @splat(0),
    divisions: u32 = 0,
    multiplications: u32 = 0,
    stop: ?anyerror = null,
    cpu: machine.Cpu = undefined,
    fn init(limit: u64, pc: u64) !Traced {
        var tape = try compact_tape.Tape.init(a, @intCast(limit), pc, 0, .rv64im);
        errdefer tape.deinit();
        return .{ .tape = tape, .capture = try boundary_capture.Capture.init(a, 0, @intCast(limit), 1 << 24) };
    }
    fn deinit(self: *Traced) void {
        self.capture.deinit();
        self.tape.deinit();
    }
    /// One reference traced step; false once stopped.
    fn referenceStep(self: *Traced, session: *Base.Session) bool {
        const tick: u32 = @intCast(4 * self.tape.len);
        const row = session.step() catch |err| {
            self.stop = err;
            return false;
        };
        self.tape.append(row) catch |err| {
            self.stop = err;
            return false;
        };
        self.capture.append(row, session.memory) catch |err| {
            self.stop = err;
            return false;
        };
        const fx = isa.effects(row.opcode);
        if (fx.reads_rs1 and row.rs1 != 0) self.clocks[row.rs1] = tick + 1;
        if (fx.reads_rs2 and row.rs2 != 0) self.clocks[row.rs2] = tick + 2;
        if (fx.writes_rd and row.rd != 0) self.clocks[row.rd] = tick + 3;
        switch (row.opcode) {
            .DIV, .DIVU, .REM, .REMU, .DIVW, .DIVUW, .REMW, .REMUW => self.divisions += 1,
            .MUL, .MULH, .MULHSU, .MULHU, .MULW => self.multiplications += 1,
            else => {},
        }
        return true;
    }
    fn expectEqual(x: *Traced, y: *Traced) !void {
        try std.testing.expectEqual(x.stop, y.stop);
        try std.testing.expectEqualDeep(x.cpu, y.cpu);
        try std.testing.expectEqual(x.tape.len, y.tape.len);
        try std.testing.expectEqualSlices(compact_tape.Step, x.tape.steps(), y.tape.steps());
        try std.testing.expectEqualSlices(u64, x.tape.memory_before.items, y.tape.memory_before.items);
        try std.testing.expectEqual(x.capture.steps, y.capture.steps);
        const cx = try x.capture.sorted(a);
        defer a.free(cx);
        const cy = try y.capture.sorted(a);
        defer a.free(cy);
        try std.testing.expectEqualSlices(boundary_capture.Cell, cx, cy);
        try std.testing.expectEqualSlices(u32, &x.clocks, &y.clocks);
        try std.testing.expectEqual(x.divisions, y.divisions);
        try std.testing.expectEqual(x.multiplications, y.multiplications);
    }
};
const Refuse = struct {
    salt: u64,
    fn admit(self: *const Refuse, pc: u64, raw: u32, inst: isa.Instruction) bool {
        _ = raw;
        _ = inst;
        return std.hash.Wyhash.hash(self.salt, std.mem.asBytes(&pc)) % 16 != 0;
    }
};

test "traced fast engine: tape, boundary capture and batch counters equal the reference traced walk" {
    var prng = std.Random.DefaultPrng.init(0x7aced_e9e);
    const r = prng.random();
    var total_fast: u64 = 0;
    var total: u64 = 0;
    var traps: usize = 0;
    var memory_words: usize = 0;
    for (0..800) |program| {
        var words: [SLOTS]u32 = undefined;
        for (&words, 0..) |*w, i| w.* = randomWord(r, i, true);
        const seed = r.int(u64);
        const start = initialCpu(r);
        const limit = 1 + r.uintLessThan(u64, 20000);
        const set: isa.Isa = if (program % 2 == 0) .rv64im else .rv64im_zbb_binary;
        var ref = try Image.init(&words, seed);
        defer ref.deinit();
        var subject = try Image.init(&words, seed);
        defer subject.deinit();
        var expected = try Traced.init(limit, start.pc);
        defer expected.deinit();
        {
            var session = try Base.Session.init(a, start, &ref.memory, .{ .max_retirements = limit, .isa = set });
            defer session.deinit();
            while (session.cpu.retired < limit and expected.referenceStep(&session)) {}
            expected.cpu = session.cpu;
        }
        var actual = try Traced.init(limit, start.pc);
        defer actual.deinit();
        var base_engine = try fast.Engine.init(a, &subject.memory, .{ .isa = set });
        defer base_engine.deinit();
        // A third of the programs also refuse random pcs (authority restriction).
        var program_engine = try fast.Engine.cloneProgram(a, &base_engine);
        defer program_engine.deinit();
        if (program % 3 == 1) program_engine.restrict(@as(*const Refuse, &.{ .salt = seed }), Refuse.admit);
        var engine = try fast.Engine.initBorrowing(a, &subject.memory, &program_engine);
        defer engine.deinit();
        {
            var session = try Base.Session.init(a, start, &subject.memory, .{ .max_retirements = limit, .isa = set });
            defer session.deinit();
            while (session.cpu.retired < limit) {
                const budget = @min(limit, session.cpu.retired + 1 + r.uintLessThan(u64, 3000));
                try actual.tape.memory_before.ensureUnusedCapacity(a, @intCast(budget - session.cpu.retired));
                var trace = fast.Trace{ .steps = actual.tape.storage, .len = actual.tape.len, .memory_before = &actual.tape.memory_before, .capture = &actual.capture, .clocks = undefined };
                trace.clocks[0..32].* = actual.clocks;
                trace.clocks[32] = 0;
                const exit = engine.runTraced(&session.cpu, budget, &trace);
                actual.tape.len = trace.len;
                actual.clocks = trace.clocks[0..32].*;
                actual.divisions += trace.divisions;
                actual.multiplications += trace.multiplications;
                if (exit == .limit) continue;
                if (!actual.referenceStep(&session)) break;
            }
            actual.cpu = session.cpu;
        }
        try Traced.expectEqual(&expected, &actual);
        try expectSameMemory(&ref.memory, &subject.memory);
        total_fast += engine.fast_retired;
        total += actual.cpu.retired;
        memory_words += actual.tape.memory_before.items.len;
        if (actual.stop != null) traps += 1;
    }
    try std.testing.expect(total_fast * 2 > total);
    try std.testing.expect(traps > 50);
    try std.testing.expect(memory_words > 10000);
}

test "traced fast engine: a discontinuous boundary word stops before the instruction" {
    // ld x9, 0(x5); beq x0, x0, +4; ld x9, 0(x5). The branch ends the first
    // block (limits are checked per block). The capture cell of DATA+0x800
    // is made stale after the first load, so the second load must be left
    // to the reference path (whose Capture.append reports the discontinuity).
    const words = [_]u32{ iType(0, 5, 3, 9, 0x03), bType(4, 0, 0, 0), iType(0, 5, 3, 9, 0x03) };
    var image = try Image.init(&words, 3);
    defer image.deinit();
    var base_engine = try fast.Engine.init(a, &image.memory, .{});
    defer base_engine.deinit();
    var engine = try fast.Engine.initBorrowing(a, &image.memory, &base_engine);
    defer engine.deinit();
    var t = try Traced.init(3, CODE);
    defer t.deinit();
    var cpu = machine.Cpu.init(CODE, 0);
    cpu.regs[5] = DATA + 0x800;
    try t.tape.memory_before.ensureUnusedCapacity(a, 3);
    var trace = fast.Trace{ .steps = t.tape.storage, .len = 0, .memory_before = &t.tape.memory_before, .capture = &t.capture, .clocks = @splat(0) };
    try std.testing.expectEqual(fast.Exit.limit, engine.runTraced(&cpu, 2, &trace));
    try std.testing.expectEqual(@as(usize, 2), trace.len);
    try std.testing.expectEqual(@as(u32, 2), t.capture.steps);
    try std.testing.expectEqual(@as(u32, 1), trace.steps[1].flags);
    t.capture.cells.getPtr(DATA + 0x800).?.final +%= 1;
    try std.testing.expectEqual(fast.Exit.slow, engine.runTraced(&cpu, 3, &trace));
    try std.testing.expectEqual(@as(usize, 2), trace.len);
    try std.testing.expectEqual(@as(u64, 2), cpu.retired);
    try std.testing.expectEqual(CODE + 8, cpu.pc);
    try std.testing.expectEqual(@as(usize, 1), t.tape.memory_before.items.len);
}

test "minimal fast first-pass records equal reference PC result and branch polarity" {
    var prng = std.Random.DefaultPrng.init(0x1675_09a7);
    const r = prng.random();
    var fast_steps: u64 = 0;
    var total: u64 = 0;
    var traps: usize = 0;
    for (0..1000) |program| {
        var words: [SLOTS]u32 = undefined;
        for (&words, 0..) |*w, i| w.* = randomWord(r, i, true);
        const seed = r.int(u64);
        const start = initialCpu(r);
        const limit = 1 + r.uintLessThan(u64, 20000);
        const set: isa.Isa = if (program % 2 == 0) .rv64im else .rv64im_zbb_binary;
        var ref = try Image.init(&words, seed);
        defer ref.deinit();
        var subject = try Image.init(&words, seed);
        defer subject.deinit();
        const ref_records = try a.alloc(fast.MinimalRecord, @intCast(limit));
        defer a.free(ref_records);
        const seed_count = std.math.divCeil(usize, @intCast(limit), fast.MINIMAL_CHUNK_ROWS) catch unreachable;
        const ref_seeds = try a.alloc(fast.MinimalSeed, seed_count);
        defer a.free(ref_seeds);
        const actual_seeds = try a.alloc(fast.MinimalSeed, seed_count);
        defer a.free(actual_seeds);
        var expected = fast.MinimalTrace{ .records = ref_records, .seeds = if (program % 2 == 0) ref_seeds else &.{} };
        var ref_stop: ?anyerror = null;
        var expected_cpu: machine.Cpu = undefined;
        {
            var session = try Base.Session.init(a, start, &ref.memory, .{ .max_retirements = limit, .isa = set });
            defer session.deinit();
            while (session.cpu.retired < limit) {
                expected.prepareReference(&session.cpu.regs);
                const row = session.step() catch |err| {
                    ref_stop = err;
                    break;
                };
                expected.appendRetirement(row) catch |err| {
                    ref_stop = err;
                    break;
                };
            }
            expected_cpu = session.cpu;
        }
        const actual_records = try a.alloc(fast.MinimalRecord, @intCast(limit));
        defer a.free(actual_records);
        var actual = fast.MinimalTrace{ .records = actual_records, .seeds = if (program % 2 == 0) actual_seeds else &.{} };
        var engine = try fast.Engine.init(a, &subject.memory, .{ .counting = program % 2 == 0, .isa = set, .watch = if (program % 3 == 0) &.{.{ DATA + 0x100, 8 }} else &.{} });
        defer engine.deinit();
        var actual_stop: ?anyerror = null;
        {
            var session = try Base.Session.init(a, start, &subject.memory, .{ .max_retirements = limit, .isa = set });
            defer session.deinit();
            while (session.cpu.retired < limit) {
                const budget = @min(limit, session.cpu.retired + 1 + r.uintLessThan(u64, 3000));
                if (try engine.runMinimal(&session.cpu, budget, &actual) == .limit) continue;
                actual.prepareReference(&session.cpu.regs);
                const row = session.step() catch |err| {
                    actual_stop = err;
                    break;
                };
                actual.appendRetirement(row) catch |err| {
                    actual_stop = err;
                    break;
                };
            }
            try std.testing.expectEqualDeep(expected_cpu, session.cpu);
        }
        try std.testing.expectEqual(ref_stop, actual_stop);
        try std.testing.expectEqualSlices(fast.MinimalRecord, expected.records[0..expected.len], actual.records[0..actual.len]);
        if (program % 2 == 0) {
            const used = std.math.divCeil(usize, actual.len, fast.MINIMAL_CHUNK_ROWS) catch unreachable;
            try std.testing.expectEqualSlices(fast.MinimalSeed, ref_seeds[0..used], actual_seeds[0..used]);
            try std.testing.expectEqualSlices(u32, &expected.clocks, &actual.clocks);
        }
        try expectSameMemory(&ref.memory, &subject.memory);
        fast_steps += engine.fast_retired;
        total += actual.len;
        if (actual_stop != null) traps += 1;
    }
    try std.testing.expect(fast_steps * 2 > total);
    try std.testing.expect(traps > 50);
}

test "minimal fast first-pass refuses high PC and bounds record capacity before retirement" {
    const words = [_]u32{ iType(1, 0, 0, 9, 0x13), jType(-4, 0) };
    var image = try Image.init(&words, 1);
    defer image.deinit();
    var engine = try fast.Engine.init(a, &image.memory, .{});
    defer engine.deinit();
    var cpu = machine.Cpu.init(CODE, 0);
    var records: [2]fast.MinimalRecord = undefined;
    var trace = fast.MinimalTrace{ .records = &records };
    const high = engine.code_hi;
    engine.code_hi = @as(u64, std.math.maxInt(u32)) + 1;
    try std.testing.expectError(error.MinimalTracePcRange, engine.runMinimal(&cpu, 2, &trace));
    try std.testing.expectEqual(@as(u64, 0), cpu.retired);
    try std.testing.expectEqual(@as(usize, 0), trace.len);
    engine.code_hi = high;
    try std.testing.expectEqual(fast.Exit.limit, try engine.runMinimal(&cpu, 2, &trace));
    try std.testing.expectEqual(@as(u64, 2), cpu.retired);
    try std.testing.expectEqual(@as(usize, 2), trace.len);
    const saved = cpu;
    try std.testing.expectEqual(fast.Exit.limit, try engine.runMinimal(&cpu, 4, &trace));
    try std.testing.expectEqualDeep(saved, cpu);
    trace.len = 3;
    try std.testing.expectError(error.MinimalTraceFull, engine.runMinimal(&cpu, 4, &trace));
}

test "RAM-key fast first pass equals reference on 1000 random programs without instruction fetches" {
    const Words = @import("../ram_word_set.zig").Set;
    var prng = std.Random.DefaultPrng.init(0x9a77_6c31);
    const r = prng.random();
    var total_fast: u64 = 0;
    var all_words: usize = 0;
    for (0..1000) |program| {
        var instructions: [SLOTS]u32 = undefined;
        for (&instructions, 0..) |*w, i| w.* = randomWord(r, i, true);
        const seed = r.int(u64);
        const start = initialCpu(r);
        const limit = 1 + r.uintLessThan(u64, 20000);
        const set: isa.Isa = if (program % 2 == 0) .rv64im else .rv64im_zbb_binary;
        var ref = try Image.init(&instructions, seed);
        defer ref.deinit();
        var subject = try Image.init(&instructions, seed);
        defer subject.deinit();
        var expected = try Words.init(a, 1 << 20);
        defer expected.deinit();
        var actual = try Words.init(a, 1 << 20);
        defer actual.deinit();
        var expected_cpu: machine.Cpu = undefined;
        var expected_stop: ?anyerror = null;
        {
            var session = try Base.Session.init(a, start, &ref.memory, .{ .max_retirements = limit, .isa = set });
            defer session.deinit();
            while (session.cpu.retired < limit) {
                const row = session.step() catch |err| {
                    expected_stop = err;
                    break;
                };
                try expected.observeRetirement(row);
            }
            expected_cpu = session.cpu;
        }
        var engine = try fast.Engine.init(a, &subject.memory, .{ .isa = set, .watch = if (program % 3 == 0) &.{.{ DATA + 0x100, 8 }} else &.{} });
        defer engine.deinit();
        var actual_stop: ?anyerror = null;
        {
            var session = try Base.Session.init(a, start, &subject.memory, .{ .max_retirements = limit, .isa = set });
            defer session.deinit();
            while (session.cpu.retired < limit) {
                const budget = @min(limit, session.cpu.retired + 1 + r.uintLessThan(u64, 3000));
                if (try engine.runRam(&session.cpu, budget, &actual) == .limit) continue;
                const row = session.step() catch |err| {
                    actual_stop = err;
                    break;
                };
                try actual.observeRetirement(row);
            }
            try std.testing.expectEqualDeep(expected_cpu, session.cpu);
        }
        try std.testing.expectEqual(expected_stop, actual_stop);
        const want = try expected.sorted(a);
        defer a.free(want);
        const got = try actual.sorted(a);
        defer a.free(got);
        try std.testing.expectEqualSlices(u64, want, got);
        try expectSameMemory(&ref.memory, &subject.memory);
        total_fast += engine.fast_retired;
        all_words += got.len;
    }
    try std.testing.expect(total_fast > 10000);
    try std.testing.expect(all_words > 1000);
}
