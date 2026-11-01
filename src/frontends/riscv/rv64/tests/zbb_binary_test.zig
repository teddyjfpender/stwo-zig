//! Admitted Zbb BINARY subset (decode.Isa.rv64im_zbb_binary, profile
//! ethereum_services_v3_zbb): exact decode, exhaustive near-miss rejection,
//! semantics against the independent candidate executor, profile gating.
const std = @import("std");
const isa = @import("../decode.zig");
const cisa = @import("../candidate_isa.zig");
const profile = @import("../execution_profile.zig");
const memory = @import("../memory.zig");
const machine = @import("../machine.zig");
const eth = @import("../ethereum_services/session.zig");
const t = std.testing;

const Pin = struct { op: isa.Opcode, cand: cisa.Op, word: u32, unary: bool };
// LLVM encodings with rd = a0, rs1 = a1, rs2 = a2 (candidate_isa_test.zig).
const PINS = [_]Pin{
    .{ .op = .ANDN, .cand = .andn, .word = 0x40c5f533, .unary = false },
    .{ .op = .ORN, .cand = .orn, .word = 0x40c5e533, .unary = false },
    .{ .op = .XNOR, .cand = .xnor, .word = 0x40c5c533, .unary = false },
    .{ .op = .REV8, .cand = .rev8, .word = 0x6b85d513, .unary = true },
    .{ .op = .SEXT_B, .cand = .sext_b, .word = 0x60459513, .unary = true },
    .{ .op = .SEXT_H, .cand = .sext_h, .word = 0x60559513, .unary = true },
    .{ .op = .ZEXT_H, .cand = .zext_h, .word = 0x0805c53b, .unary = true },
};

fn subsetOp(op: cisa.Op) ?isa.Opcode {
    for (PINS) |p| if (p.cand == op) return p.op;
    return null;
}

test "pinned encodings decode exactly under the Zbb BINARY ISA and are illegal under RV64IM" {
    for (PINS) |p| {
        try t.expectError(error.IllegalInstruction, isa.Instruction.decode(p.word));
        try t.expectError(error.IllegalInstruction, isa.decodeFor(.rv64im, p.word));
        const d = try isa.decodeFor(.rv64im_zbb_binary, p.word);
        try t.expectEqual(p.op, d.opcode);
        try t.expectEqual(@as(u5, 10), d.rd);
        try t.expectEqual(@as(u5, 11), d.rs1);
        try t.expectEqual(@as(u5, if (p.unary) 0 else 12), d.rs2);
        try t.expectEqual(@as(i64, 0), d.imm);
        const e = isa.effects(p.op);
        try t.expect(e.reads_rs1 and e.writes_rd and e.reads_rs2 == !p.unary and e.memory_width == 0);
        try t.expect(!isa.isBase(p.op));
    }
}

test "exhaustive: over every OP, OP-IMM and OP-32 word, the subset is exactly the candidate subset ops" {
    // Bits [6:0] fixed per major opcode; bits [31:7] swept completely (2^25 each).
    for ([_]u32{ 0x33, 0x13, 0x3b }) |major| {
        var high: u32 = 0;
        while (high < (1 << 25)) : (high += 1) {
            const word = (high << 7) | major;
            const base_ok = if (isa.Instruction.decode(word)) |_| true else |_| false;
            const zbb = isa.decodeZbbBinary(word);
            const cand_subset: ?isa.Opcode = if (cisa.decode(word)) |c| subsetOp(c.op) else null;
            if (zbb) |z| {
                // Never shadows an RV64IM encoding, and agrees with the independent decoder.
                try t.expect(!base_ok);
                try t.expectEqual(cand_subset.?, z.opcode);
                try t.expectEqual(@as(u5, @truncate(word >> 7)), z.rd);
                try t.expectEqual(@as(u5, @truncate(word >> 15)), z.rs1);
            } else try t.expect(cand_subset == null);
            // decodeFor never changes an RV64IM decode.
            if (base_ok) try t.expectEqual((try isa.Instruction.decode(word)).opcode, (try isa.decodeFor(.rv64im_zbb_binary, word)).opcode);
        }
    }
}

test "near misses stay illegal under the Zbb BINARY ISA" {
    const words = [_]u32{
        0x60059513, // clz
        0x60259513, // cpop
        0x0ac5f533, // maxu
        0x60c59533, // rol
        0x63f5d513, // rori
        0x2875d513, // orc.b
        0x6985d513, // rev8, RV32 encoding
        0x0805c53b | (1 << 20), // packw a0,a1,x1 (Zbkb)
        0x08c5c533, // pack (Zbkb)
        0x08c5f533, // packh (Zbkb)
        0x20c5e533, // sh3add (Zba)
        0x60359513, // unassigned OP-IMM imm 0x603
        0x40c5a533, // OP f7=0100000 f3=010 (unassigned)
        0x6045951b, // sext.b imm on OP-IMM-32 (illegal)
        0x0805c533, // zext.h encoding on OP (RV32 form = pack rd,rs1,x0, not RV64 zext.h)
    };
    for (words) |w| try t.expectError(error.IllegalInstruction, isa.decodeFor(.rv64im_zbb_binary, w));
}

test "semantics match the independent candidate executor on edge and random operands" {
    var prng = std.Random.DefaultPrng.init(0x7a6262);
    const r = prng.random();
    const edges = [_]u64{ 0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x8000_0000, ~@as(u64, 0), 1 << 63, 0x0123_4567_89ab_cdef };
    for (PINS) |p| {
        for (0..2000) |i| {
            const a = if (i < edges.len) edges[i] else r.int(u64);
            const b = if (i < edges.len) edges[edges.len - 1 - i] else r.int(u64);
            var mem = memory.Memory.init(t.allocator, .{});
            defer mem.deinit();
            try mem.map(.{ .start = 0x1000, .size = 4, .permissions = .{ .read = true, .execute = true } });
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, p.word, .little);
            try mem.initialize(0x1000, &bytes);
            var c = machine.Cpu.init(0x1000, 0);
            c.regs[11] = a;
            c.regs[12] = b;
            var cache = try @import("../decode_cache.zig").Cache.initIsa(t.allocator, 1, .rv64im_zbb_binary);
            defer cache.deinit();
            const row = try c.stepCached(&mem, &cache);
            const want = cisa.execute(.{ .op = p.cand, .rd = 10, .rs1 = 11, .rs2 = 12 }, a, b);
            try t.expectEqual(want, c.regs[10]);
            try t.expectEqual(want, row.result.toInt());
            try t.expectEqual(p.op, row.opcode);
            try t.expectEqual(@as(u5, if (p.unary) 0 else 12), row.rs2);
            try t.expectEqual(if (p.unary) @as(u64, 0) else b, row.rhs.toInt());
        }
    }
}

test "profile gating: only ethereum_services_v3_zbb decodes and admits the subset" {
    for (std.enums.values(profile.Profile)) |p| {
        const zbb = p == .ethereum_services_v3_zbb;
        try t.expectEqual(if (zbb) isa.Isa.rv64im_zbb_binary else isa.Isa.rv64im, profile.isaOf(p));
        for (PINS) |pin| {
            try t.expectEqual(zbb, profile.admitted(p, pin.op));
            if (zbb) {
                try t.expectEqual(pin.op, (try profile.decode(p, pin.word)).opcode);
            } else try t.expectError(error.IllegalInstruction, profile.decode(p, pin.word));
        }
    }
    try t.expect(profile.isV3(.ethereum_services_v3_zbb) and profile.isV3(.ethereum_services_v3));
    try t.expect(profile.admitsV3(.ethereum_services_v3_zbb, profile.SHA256_COMPRESS_TAG));
    try t.expect(profile.secpWords(.ethereum_services_v3_zbb));
}

fn sessionRun(p: profile.Profile) !u64 {
    var mem = memory.Memory.init(t.allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 8, .permissions = .{ .read = true, .execute = true } });
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u32, bytes[0..4], 0x6b85d513, .little); // rev8 a0,a1
    std.mem.writeInt(u32, bytes[4..8], 0x40c5f533, .little); // andn a0,a1,a2
    try mem.initialize(0x1000, &bytes);
    var c = machine.Cpu.init(0x1000, 0);
    c.regs[11] = 0x0102_0304_0506_0708;
    c.regs[12] = 0xff;
    var s = try eth.Session.initWithProfile(t.allocator, c, &mem, .{ .cache_entries = 4, .max_retirements = 2 }, p);
    defer s.deinit();
    var event: eth.Event = undefined;
    _ = try s.step(&event);
    try t.expectEqual(@as(u64, 0x0807_0605_0403_0201), s.keccak.base.cpu.regs[10]);
    _ = try s.step(&event);
    return s.keccak.base.cpu.regs[10];
}

test "v3_zbb session retires the subset; v3 traps without any state change" {
    try t.expectEqual(@as(u64, 0x0102_0304_0506_0700), try sessionRun(.ethereum_services_v3_zbb));
    try t.expectError(error.IllegalInstruction, sessionRun(.ethereum_services_v3));
    // A caller cannot widen a pre-Zbb profile through Options.isa.
    var mem = memory.Memory.init(t.allocator, .{});
    defer mem.deinit();
    try t.expectError(error.UnsupportedService, eth.Session.initWithProfile(t.allocator, machine.Cpu.init(0x1000, 0), &mem, .{ .isa = .rv64im_zbb_binary }, .ethereum_services_v3));
}
