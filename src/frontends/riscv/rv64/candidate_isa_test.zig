//! Tests for the execution-only candidate Zbb/Zba subset (candidate_isa.zig).
//! Encodings were produced by LLVM 22 (`llvm-mc`/`zig cc` with
//! `.option arch, +zba, +zbb`, rd = a0, rs1 = a1, rs2 = a2) and cross-checked
//! with `llvm-objdump --mattr=+zba,+zbb`.
const std = @import("std");
const cisa = @import("candidate_isa.zig");
const admitted = @import("decode.zig");
const machine = @import("machine.zig");
const Op = cisa.Op;

const Enc = struct { op: Op, word: u32, shamt: u6 = 0 };
const ENCODINGS = [_]Enc{
    .{ .op = .andn, .word = 0x40c5f533 },
    .{ .op = .orn, .word = 0x40c5e533 },
    .{ .op = .xnor, .word = 0x40c5c533 },
    .{ .op = .clz, .word = 0x60059513 },
    .{ .op = .clzw, .word = 0x6005951b },
    .{ .op = .ctz, .word = 0x60159513 },
    .{ .op = .ctzw, .word = 0x6015951b },
    .{ .op = .cpop, .word = 0x60259513 },
    .{ .op = .cpopw, .word = 0x6025951b },
    .{ .op = .max, .word = 0x0ac5e533 },
    .{ .op = .maxu, .word = 0x0ac5f533 },
    .{ .op = .min, .word = 0x0ac5c533 },
    .{ .op = .minu, .word = 0x0ac5d533 },
    .{ .op = .sext_b, .word = 0x60459513 },
    .{ .op = .sext_h, .word = 0x60559513 },
    .{ .op = .zext_h, .word = 0x0805c53b },
    .{ .op = .rol, .word = 0x60c59533 },
    .{ .op = .rolw, .word = 0x60c5953b },
    .{ .op = .ror, .word = 0x60c5d533 },
    .{ .op = .rori, .word = 0x63f5d513, .shamt = 63 },
    .{ .op = .roriw, .word = 0x61f5d51b, .shamt = 31 },
    .{ .op = .rorw, .word = 0x60c5d53b },
    .{ .op = .orc_b, .word = 0x2875d513 },
    .{ .op = .rev8, .word = 0x6b85d513 },
    .{ .op = .sh1add, .word = 0x20c5a533 },
    .{ .op = .sh2add, .word = 0x20c5c533 },
    .{ .op = .sh3add, .word = 0x20c5e533 },
    .{ .op = .add_uw, .word = 0x08c5853b },
    .{ .op = .sh1add_uw, .word = 0x20c5a53b },
    .{ .op = .sh2add_uw, .word = 0x20c5c53b },
    .{ .op = .sh3add_uw, .word = 0x20c5e53b },
    .{ .op = .slli_uw, .word = 0x0bf5951b, .shamt = 63 },
};

fn isUnary(op: Op) bool {
    return switch (op) {
        .clz, .clzw, .ctz, .ctzw, .cpop, .cpopw, .sext_b, .sext_h, .zext_h, .orc_b, .rev8, .rori, .roriw, .slli_uw => true,
        else => false,
    };
}

test "every candidate op has an assembler encoding, decodes exactly, and is illegal in the admitted decoder" {
    try std.testing.expectEqual(@typeInfo(Op).@"enum".fields.len, ENCODINGS.len);
    for (ENCODINGS) |e| {
        const d = cisa.decode(e.word) orelse return error.NotDecoded;
        try std.testing.expectEqual(e.op, d.op);
        try std.testing.expectEqual(@as(u5, 10), d.rd);
        try std.testing.expectEqual(@as(u5, 11), d.rs1);
        if (!isUnary(e.op)) try std.testing.expectEqual(@as(u5, 12), d.rs2);
        try std.testing.expectEqual(e.shamt, d.shamt);
        try std.testing.expectError(error.IllegalInstruction, admitted.Instruction.decode(e.word));
    }
}

test "admitted RV64IM encodings and near misses are not candidate instructions" {
    const not_candidate = [_]u32{
        0x00c58533, // add a0,a1,a2
        0x40c58533, // sub
        0x40c5d533, // sra
        0x02c58533, // mul
        0x02c5c533, // div
        0x00c5f533, // and
        0x00c5e533, // or
        0x00c5c533, // xor
        0x00c5953b, // sllw
        0x40c5d53b, // sraw
        0x00359513, // slli a0,a1,3
        0x4035d513, // srai a0,a1,3
        0x0035d513, // srli
        0x0035951b, // slliw
        0x4035d51b, // sraiw
        0x0805c53b | (1 << 20), // packw a0,a1,x1 (Zbkb, not zext.h)
        0x08c5c533, // pack (Zbkb, OP f7=0000100 f3=100)
        0x60359513, // OP-IMM f3=1 imm 0x603 (unassigned)
        0x60659513, // imm 0x606
        0x6035951b, // OP-IMM-32 imm 0x603
        0x6985d513, // rev8 RV32 encoding (0x698)
        0x48c59533, // bclr (Zbs, excluded)
        0x2885d513, // orc.b with imm 0x288 (unassigned)
        0x40c5a533, // OP f7=0100000 f3=010 (unassigned)
        0x0ac5a533, // OP f7=0000101 f3=010 (clmulr, Zbc, excluded)
        0x0ac59533, // clmul (Zbc)
        0x20c59533, // OP f7=0010000 f3=001 (unassigned)
        0x20c5953b, // OP-32 f7=0010000 f3=001
        0x60c5a533, // OP f7=0110000 f3=010
        0x0805d51b | (0b000011 << 26), // OP-IMM-32 f3=5 funct6 000011
        0x0005951b | (0b000011 << 26), // OP-IMM-32 f3=1 funct6 000011 (not slli.uw)
        0x6205d51b, // roriw with shamt bit 5 set (f7 = 0110001): illegal on RV64
    };
    for (not_candidate) |word| {
        if (cisa.decode(word)) |d| {
            std.debug.print("unexpected candidate decode of 0x{x:0>8}: {s}\n", .{ word, @tagName(d.op) });
            return error.UnexpectedCandidate;
        }
    }
}

test "shift-immediate fields" {
    // rori by 0 and by 63; roriw by 0 and 31; slli.uw by 0 and 63.
    try std.testing.expectEqual(@as(u6, 0), cisa.decode(0x6005d513).?.shamt);
    try std.testing.expectEqual(Op.rori, cisa.decode(0x6005d513).?.op);
    try std.testing.expectEqual(@as(u6, 0), cisa.decode(0x6005d51b).?.shamt);
    try std.testing.expectEqual(Op.roriw, cisa.decode(0x6005d51b).?.op);
    try std.testing.expectEqual(@as(u6, 0), cisa.decode(0x0805951b).?.shamt);
    try std.testing.expectEqual(Op.slli_uw, cisa.decode(0x0805951b).?.op);
    try std.testing.expectEqual(@as(u6, 32), cisa.decode(0x0a05951b).?.shamt);
}

fn run(op: Op, a: u64, b: u64, shamt: u6) u64 {
    return cisa.execute(.{ .op = op, .rd = 1, .rs1 = 2, .rs2 = 3, .shamt = shamt }, a, b);
}
const t = std.testing;

test "logic with negate" {
    try t.expectEqual(@as(u64, 0x0f0f_0000_0000_0000), run(.andn, 0xffff_0000_0000_0000, 0xf0f0_ffff_ffff_ffff, 0));
    try t.expectEqual(@as(u64, 0xffff_ffff_ffff_fffe), run(.orn, 0, 1, 0));
    try t.expectEqual(@as(u64, 0xffff_ffff_ffff_ffff), run(.xnor, 0x1234, 0x1234, 0));
    try t.expectEqual(@as(u64, 0), run(.xnor, 0, ~@as(u64, 0), 0));
}

test "count leading/trailing zeros and population" {
    try t.expectEqual(@as(u64, 64), run(.clz, 0, 0, 0));
    try t.expectEqual(@as(u64, 32), run(.clzw, 0, 0, 0));
    try t.expectEqual(@as(u64, 32), run(.clzw, 0xffff_ffff_0000_0000, 0, 0)); // upper half ignored
    try t.expectEqual(@as(u64, 0), run(.clz, 1 << 63, 0, 0));
    try t.expectEqual(@as(u64, 63), run(.clz, 1, 0, 0));
    try t.expectEqual(@as(u64, 0), run(.clzw, 0x8000_0000, 0, 0));
    try t.expectEqual(@as(u64, 64), run(.ctz, 0, 0, 0));
    try t.expectEqual(@as(u64, 32), run(.ctzw, 0, 0, 0));
    try t.expectEqual(@as(u64, 32), run(.ctzw, 0x1_0000_0000, 0, 0));
    try t.expectEqual(@as(u64, 63), run(.ctz, 1 << 63, 0, 0));
    try t.expectEqual(@as(u64, 0), run(.cpop, 0, 0, 0));
    try t.expectEqual(@as(u64, 64), run(.cpop, ~@as(u64, 0), 0, 0));
    try t.expectEqual(@as(u64, 32), run(.cpopw, ~@as(u64, 0), 0, 0));
    try t.expectEqual(@as(u64, 1), run(.cpopw, 0xffff_ffff_0000_0001, 0, 0));
}

test "min and max, signed and unsigned" {
    const neg: u64 = @bitCast(@as(i64, -5));
    try t.expectEqual(@as(u64, 3), run(.max, neg, 3, 0));
    try t.expectEqual(neg, run(.min, neg, 3, 0));
    try t.expectEqual(neg, run(.maxu, neg, 3, 0));
    try t.expectEqual(@as(u64, 3), run(.minu, neg, 3, 0));
    const smin: u64 = 1 << 63;
    try t.expectEqual(smin, run(.min, smin, 0x7fff_ffff_ffff_ffff, 0));
    try t.expectEqual(@as(u64, 0x7fff_ffff_ffff_ffff), run(.max, smin, 0x7fff_ffff_ffff_ffff, 0));
    try t.expectEqual(@as(u64, 7), run(.max, 7, 7, 0));
}

test "sign and zero extension" {
    try t.expectEqual(@as(u64, 0xffff_ffff_ffff_ff80), run(.sext_b, 0x1234_5680, 0, 0));
    try t.expectEqual(@as(u64, 0x7f), run(.sext_b, 0xffff_ff7f, 0, 0));
    try t.expectEqual(@as(u64, 0xffff_ffff_ffff_8000), run(.sext_h, 0xabcd_8000, 0, 0));
    try t.expectEqual(@as(u64, 0x7fff), run(.sext_h, 0xffff_7fff, 0, 0));
    try t.expectEqual(@as(u64, 0x8000), run(.zext_h, 0xffff_ffff_ffff_8000, 0, 0));
}

test "rotates including amounts 0, 31, 32 and 63 and w-form sign extension" {
    const x: u64 = 0x8123_4567_89ab_cdef;
    try t.expectEqual(x, run(.rol, x, 0, 0));
    try t.expectEqual(x, run(.ror, x, 64, 0)); // only rs2[5:0] counts
    try t.expectEqual(x, run(.rori, x, 0, 0));
    try t.expectEqual(std.math.rotr(u64, x, 63), run(.rori, x, 0, 63));
    try t.expectEqual(@as(u64, 0x0246_8acf_1357_9bdf), run(.rol, x, 1, 0));
    try t.expectEqual(@as(u64, 0xc091_a2b3_c4d5_e6f7), run(.ror, x, 1, 0));
    try t.expectEqual(run(.rol, x, 1, 0), run(.ror, x, 63, 0));
    // w forms: operate on the low 32 bits, sign-extend bit 31 of the result.
    try t.expectEqual(@as(u64, 0xffff_ffff_8000_0000), run(.rorw, 0xdead_beef_0000_0001, 1, 0));
    try t.expectEqual(@as(u64, 0x0000_0000_0000_0001), run(.rolw, 0xdead_beef_8000_0000, 1, 0));
    try t.expectEqual(@as(u64, 0xffff_ffff_89ab_cdef), run(.rolw, x, 32, 0)); // rs2[4:0] = 0
    try t.expectEqual(@as(u64, 0xffff_ffff_89ab_cdef), run(.roriw, x, 0, 0));
    try t.expectEqual(@as(u64, 0x1357_9bdf), run(.roriw, x, 0, 31));
}

test "orc.b and rev8" {
    try t.expectEqual(@as(u64, 0xff00_ff00_00ff_00ff), run(.orc_b, 0x8000_0100_0001_0080, 0, 0));
    try t.expectEqual(@as(u64, 0), run(.orc_b, 0, 0, 0));
    try t.expectEqual(~@as(u64, 0), run(.orc_b, 0x0101_0101_0101_0101, 0, 0));
    try t.expectEqual(@as(u64, 0xefcd_ab89_6745_2381), run(.rev8, 0x8123_4567_89ab_cdef, 0, 0));
}

test "Zba shift-add and unsigned-word forms" {
    try t.expectEqual(@as(u64, 100 + 2 * 7), run(.sh1add, 7, 100, 0));
    try t.expectEqual(@as(u64, 100 + 4 * 7), run(.sh2add, 7, 100, 0));
    try t.expectEqual(@as(u64, 100 + 8 * 7), run(.sh3add, 7, 100, 0));
    try t.expectEqual(@as(u64, 2), run(.sh1add, 1 << 63 | 1, 0, 0)); // wraps
    const hi: u64 = 0xffff_ffff_8000_0000;
    try t.expectEqual(@as(u64, 0x8000_0000 + 5), run(.add_uw, hi, 5, 0));
    try t.expectEqual(@as(u64, 0x1_0000_0000 + 5), run(.sh1add_uw, hi, 5, 0));
    try t.expectEqual(@as(u64, 0x2_0000_0000 + 5), run(.sh2add_uw, hi, 5, 0));
    try t.expectEqual(@as(u64, 0x4_0000_0000 + 5), run(.sh3add_uw, hi, 5, 0));
    try t.expectEqual(@as(u64, 0x8000_0000), run(.slli_uw, hi, 0, 0));
    try t.expectEqual(@as(u64, 0x8000_0000_0000_0000), run(.slli_uw, 0xffff_ffff_0000_0001, 0, 63));
    try t.expectEqual(@as(u64, 0x8000_0000_0000_0000), run(.slli_uw, hi, 0, 32));
}

/// Independent bit-loop reference for the randomized differential.
fn reference(op: Op, a: u64, b: u64, shamt: u6) u64 {
    const lo: u64 = a & 0xffff_ffff;
    const sx32 = struct {
        fn f(v: u64) u64 {
            const v32 = v & 0xffff_ffff;
            return if (v32 & 0x8000_0000 != 0) v32 | 0xffff_ffff_0000_0000 else v32;
        }
    }.f;
    return switch (op) {
        .andn => a & (b ^ ~@as(u64, 0)),
        .orn => a | (b ^ ~@as(u64, 0)),
        .xnor => (a ^ b) ^ ~@as(u64, 0),
        .clz, .clzw => blk: {
            const width: u7 = if (op == .clz) 64 else 32;
            var n: u64 = 0;
            var i: i32 = width - 1;
            while (i >= 0 and (a >> @intCast(i)) & 1 == 0) : (i -= 1) n += 1;
            break :blk n;
        },
        .ctz, .ctzw => blk: {
            const width: u7 = if (op == .ctz) 64 else 32;
            var n: u64 = 0;
            while (n < width and (a >> @intCast(n)) & 1 == 0) n += 1;
            break :blk n;
        },
        .cpop, .cpopw => blk: {
            const v = if (op == .cpop) a else lo;
            var n: u64 = 0;
            for (0..64) |i| n += (v >> @intCast(i)) & 1;
            break :blk n;
        },
        .max, .min => blk: {
            // signed compare via bias
            const lt = (a ^ (1 << 63)) < (b ^ (1 << 63));
            break :blk if (op == .max) (if (lt) b else a) else (if (lt) a else b);
        },
        .maxu => if (a < b) b else a,
        .minu => if (a < b) a else b,
        .sext_b => if (a & 0x80 != 0) (a & 0xff) | ~@as(u64, 0xff) else a & 0xff,
        .sext_h => if (a & 0x8000 != 0) (a & 0xffff) | ~@as(u64, 0xffff) else a & 0xffff,
        .zext_h => a % 0x1_0000,
        .rol, .ror, .rori => blk: {
            const s: u64 = if (op == .rori) shamt else b & 63;
            const left = if (op == .rol) s else (64 - s) & 63;
            if (left == 0) break :blk a;
            break :blk (a << @intCast(left)) | (a >> @intCast(64 - left));
        },
        .rolw, .rorw, .roriw => blk: {
            const s: u64 = if (op == .roriw) shamt & 31 else b & 31;
            const left = if (op == .rolw) s else (32 - s) & 31;
            const r = if (left == 0) lo else ((lo << @intCast(left)) | (lo >> @intCast(32 - left))) & 0xffff_ffff;
            break :blk sx32(r);
        },
        .orc_b => blk: {
            var r: u64 = 0;
            for (0..8) |i| {
                const byte = (a >> @intCast(8 * i)) & 0xff;
                if (byte != 0) r += @as(u64, 0xff) << @intCast(8 * i);
            }
            break :blk r;
        },
        .rev8 => blk: {
            var r: u64 = 0;
            for (0..8) |i| r = (r << 8) | ((a >> @intCast(8 * i)) & 0xff);
            break :blk r;
        },
        .sh1add => b +% a *% 2,
        .sh2add => b +% a *% 4,
        .sh3add => b +% a *% 8,
        .add_uw => b +% lo,
        .sh1add_uw => b +% lo *% 2,
        .sh2add_uw => b +% lo *% 4,
        .sh3add_uw => b +% lo *% 8,
        .slli_uw => if (shamt == 0) lo else lo *% (@as(u64, 1) << shamt),
    };
}

test "randomized differential against a bit-loop reference" {
    var prng = std.Random.DefaultPrng.init(0x5a5a_2026_1101);
    const r = prng.random();
    const specials = [_]u64{ 0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1_0000_0000, 1 << 63, (1 << 63) - 1, ~@as(u64, 0) };
    inline for (@typeInfo(Op).@"enum".fields) |f| {
        const op: Op = @enumFromInt(f.value);
        var i: usize = 0;
        while (i < 4000) : (i += 1) {
            const a = if (i < specials.len * specials.len) specials[i % specials.len] else r.int(u64) >> @intCast(r.int(u6));
            const b = if (i < specials.len * specials.len) specials[i / specials.len] else r.int(u64);
            const shamt: u6 = if (op == .roriw) r.int(u5) else r.int(u6);
            const got = run(op, a, b, shamt);
            const want = reference(op, a, b, shamt);
            if (got != want) {
                std.debug.print("{s} a=0x{x} b=0x{x} shamt={d}: got 0x{x} want 0x{x}\n", .{ f.name, a, b, shamt, got, want });
                return error.Mismatch;
            }
        }
    }
}

test "step retires exactly one instruction, writes rd, honours x0, counts per op" {
    var cpu = machine.Cpu.init(0x1000, 0x8000);
    var counts: cisa.Counts = .{};
    cpu.regs[11] = 0x8123_4567_89ab_cdef;
    cpu.regs[12] = 8;
    try t.expectEqual(Op.rev8, cisa.step(&cpu, 0x6b85d513, &counts).?); // rev8 a0, a1
    try t.expectEqual(@as(u64, 0xefcd_ab89_6745_2381), cpu.regs[10]);
    try t.expectEqual(@as(u64, 0x1004), cpu.pc);
    try t.expectEqual(@as(u64, 1), cpu.retired);
    _ = cisa.step(&cpu, 0x60c59533, &counts).?; // rol a0, a1, a2
    try t.expectEqual(@as(u64, 0x2345_6789_abcd_ef81), cpu.regs[10]);
    // rd = x0: rev8 x0, a1 -> 0x6b85d013
    _ = cisa.step(&cpu, 0x6b85d013, &counts).?;
    try t.expectEqual(@as(u64, 0), cpu.read(0));
    try t.expectEqual(@as(u64, 3), cpu.retired);
    try t.expectEqual(@as(u64, 2), counts.rev8);
    try t.expectEqual(@as(u64, 1), counts.rol);
    // Not a candidate: CPU untouched.
    const before = cpu;
    try t.expect(cisa.step(&cpu, 0x00c58533, &counts) == null);
    try t.expectEqual(before, cpu);
}

test "counts serialize as a flat name -> count object" {
    var counts: cisa.Counts = .{};
    cisa.bump(&counts, .sh3add_uw);
    const s = try std.json.Stringify.valueAlloc(t.allocator, counts, .{});
    defer t.allocator.free(s);
    try t.expect(std.mem.indexOf(u8, s, "\"sh3add_uw\":1") != null);
    try t.expect(std.mem.indexOf(u8, s, "\"andn\":0") != null);
}
