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

fn referenceRun(m: *mem.Memory, start: machine.Cpu, limit: u64) Outcome {
    var out = Outcome{ .cpu = start, .stop = null };
    while (out.cpu.retired < limit) {
        const row = out.cpu.step(m) catch |err| {
            out.stop = err;
            break;
        };
        out.counts[@intFromEnum(row.opcode)] += 1;
    }
    return out;
}

/// Fast engine with random intermediate budgets (checkpoint boundaries).
fn fastRun(m: *mem.Memory, start: machine.Cpu, limit: u64, r: std.Random, engine: *fast.Engine) Outcome {
    var out = Outcome{ .cpu = start, .stop = null };
    while (out.cpu.retired < limit) {
        const budget = @min(limit, out.cpu.retired + 1 + r.uintLessThan(u64, 3000));
        if (engine.run(&out.cpu, budget) == .limit) continue;
        const row = out.cpu.step(m) catch |err| {
            out.stop = err;
            break;
        };
        out.counts[@intFromEnum(row.opcode)] += 1;
    }
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
        const expected = referenceRun(&ref.memory, start, limit);
        var engine = try fast.Engine.init(a, &subject.memory, .{ .counting = true, .watch = if (program % 3 == 0) &.{.{ DATA + 0x100, 8 }} else &.{} });
        defer engine.deinit();
        const actual = fastRun(&subject.memory, start, limit, r, &engine);
        try std.testing.expectEqualDeep(expected.cpu, actual.cpu);
        try std.testing.expectEqual(expected.stop, actual.stop);
        try std.testing.expectEqualSlices(u64, &expected.counts, &actual.counts);
        try expectSameMemory(&ref.memory, &subject.memory);
        total_fast += engine.fast_retired;
        total += actual.cpu.retired;
        if (actual.stop != null) traps += 1;
    }
    // The generator must actually exercise the fast path and the trap path.
    try std.testing.expect(total_fast * 2 > total);
    try std.testing.expect(traps > 100);
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
        _ = fastRun(&image.memory, cpu, 1 + r.uintLessThan(u64, 5000), r, &engine);
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

test {
    _ = @import("../ethereum_services/secp256k1.zig");
    _ = @import("../ethereum_services/arith256.zig");
}
