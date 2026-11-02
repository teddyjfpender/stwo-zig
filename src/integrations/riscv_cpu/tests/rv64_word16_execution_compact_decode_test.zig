//! Opt-in compact decode CPU MAIN (Geometry.cpu_compact_decode, 37 MAIN, 32
//! residuals): degree, lane parity, honest tuple equivalence with the legacy
//! layout, ROM decode admission and the local residuals that replace the
//! committed PC and immediate columns.
const std = @import("std");
const core = @import("stwo_core");
const air = @import("stwo_riscv_frontend").rv64_air;
const X = air.word16_execution;
const E = air.evaluation;
const Tables = air.providers.tables;
const Q = E.Q;
const M = core.fields.m31.M31;
const L = X.layout;
const K = L.compact;
const Eq = X.equations;
const U = X.tuples;
const W = L.pairs.COUNT;
const N = Eq.COMPACT_CONSTRAINTS;
comptime {
    std.debug.assert(K.COUNT == 37 and N == 32 and Eq.COMPACT_MAIN_CONSTRAINTS == 23);
}
fn challenges(channel: *core.channel.blake2s.Blake2sChannel) X.types.Challenges {
    var out: X.types.Challenges = undefined;
    inline for (.{ "register", "function", "rom", "owner" }) |field| {
        @field(out, field).offset = channel.drawSecureFelt();
        for (&@field(out, field).coefficients) |*value| value.* = channel.drawSecureFelt();
    }
    inline for (.{ "range16", "range8" }) |field| @field(out, field) = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    return out;
}
fn inputs() X.types.Inputs {
    return .{ .steps = 1, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x1004, 0, 0, 0 }, .epoch = 1 };
}
fn same(x: []const M, y: []const M) bool {
    if (x.len != y.len) return false;
    for (x, y) |u, v| if (u.v != v.v) return false;
    return true;
}
fn toQ(comptime C: usize, values: [C]M) [C]Q {
    var out: [C]Q = undefined;
    for (values, &out) |v, *o| o.* = Q.fromBase(v);
    return out;
}

test "compact CPU residuals are cubic over dense full-extension coordinates (all32)" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    const pc = Tables.Challenges.draw(&channel);
    const claim = channel.drawSecureFelt();
    var constants: [5][L.main.COUNT]Q = undefined;
    var slopes: [5][L.main.COUNT]Q = undefined;
    for (&constants, &slopes) |*a, *b| for (a, b) |*x, *y| {
        x.* = channel.drawSecureFelt();
        y.* = channel.drawSecureFelt();
    };
    var result: [5][N]Q = undefined;
    for (0..5) |point| {
        var data: [5][L.main.COUNT]Q = undefined;
        for (&data, constants, slopes) |*row, a, b| {
            for (row, a, b) |*v, c, s| v.* = c.add(s.mulM31(M.fromCanonical(@intCast(point))));
        }
        var sink = E.Sink{ .values = &result[point] };
        Eq.emitCompactFor(Q, data[0][0..3], data[1][0..K.COUNT], data[2][0..K.COUNT], data[3][0..W], data[4][0..W], inputs(), claim, ch, pc, &sink);
        try std.testing.expectEqual(@as(usize, N), sink.count);
    }
    var cubic_rom = false;
    for (0..N) |i| {
        const fourth = result[0][i].sub(result[1][i].mulM31(M.fromCanonical(4))).add(result[2][i].mulM31(M.fromCanonical(6))).sub(result[3][i].mulM31(M.fromCanonical(4))).add(result[4][i]);
        try std.testing.expect(fourth.isZero());
        const third = result[3][i].sub(result[2][i].mulM31(M.fromCanonical(3))).add(result[1][i].mulM31(M.fromCanonical(3))).sub(result[0][i]);
        // The ROM fraction H*d_rom - active: d_rom quadratic (previous-row pc).
        if (i == Eq.COMPACT_MAIN_CONSTRAINTS + 4) cubic_rom = !third.isZero();
    }
    try std.testing.expect(cubic_rom);
}

test "compact CPU packed lanes equal QM31" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    const pc = Tables.Challenges.draw(&channel);
    const claim = channel.drawSecureFelt();
    const B = E.PackedBase;
    var data: [5][K.COUNT][16]M = undefined;
    var simd: [5][K.COUNT]B = undefined;
    for (&data, &simd) |*a, *b| for (a, b) |*lanes, *v| {
        for (lanes) |*lane| lane.* = channel.drawSecureFelt().toM31Array()[0];
        v.* = B.fromLanes(lanes.*);
    };
    var packed_result: [N]E.PackedSecure = undefined;
    var sink = E.PackedSink{ .values = &packed_result };
    Eq.emitCompactFor(B, simd[0][0..3], &simd[1], &simd[2], simd[3][0..W], simd[4][0..W], inputs(), claim, ch, pc, &sink);
    try std.testing.expectEqual(@as(usize, N), sink.count);
    for (0..16) |lane| {
        var q: [5][K.COUNT]Q = undefined;
        for (&q, data) |*a, b| {
            for (a, b) |*v, lanes| v.* = Q.fromBase(lanes[lane]);
        }
        var residuals: [N]Q = undefined;
        var out = E.Sink{ .values = &residuals };
        Eq.emitCompactFor(Q, q[0][0..3], &q[1], &q[2], q[3][0..W], q[4][0..W], inputs(), claim, ch, pc, &out);
        for (residuals, packed_result) |wanted, got| try std.testing.expect(wanted.eql(got.lane(lane)));
    }
}

/// One instruction with honest legacy and compact rows built from the same
/// decoded entry and the same values.
const Case = struct { raw: u32, pc: u64, values: X.row.Values, next: u64 };
const cases = [_]Case{
    .{ .raw = 0x001080b3, .pc = 0x1000, .values = .{ .a = 7, .b = 7, .c = 14, .previous_rd = 7 }, .next = 0x1004 }, // add x1,x1,x1
    .{ .raw = 0x00008033, .pc = 0x1000, .values = .{ .a = 7, .b = 0, .c = 7, .previous_rd = 0 }, .next = 0x1004 }, // add x0,x1,x0
    .{ .raw = 0xfef00113, .pc = 0x1000, .values = .{ .a = 0, .b = 0, .c = @bitCast(@as(i64, -17)), .previous_rd = 3 }, .next = 0x1004 }, // addi x2,x0,-17
    .{ .raw = 0x021000b7, .pc = 0x1000, .values = .{ .a = 0, .b = 0, .c = 0x2100000, .previous_rd = 0 }, .next = 0x1004 }, // lui x1
    .{ .raw = 0x00001797, .pc = 0x2000, .values = .{ .a = 0, .b = 0, .c = 0x3000, .previous_rd = 0 }, .next = 0x2004 }, // auipc x15,1
    .{ .raw = 0x0080086f, .pc = 0x2000, .values = .{ .a = 0, .b = 0, .c = 0x2004, .previous_rd = 9 }, .next = 0x2008 }, // jal x16,+8
    .{ .raw = 0x00c80867, .pc = 0x2000, .values = .{ .a = 0x3000, .b = 0, .c = 0x2004, .previous_rd = 9 }, .next = 0x300c }, // jalr x16,12(x16)
    .{ .raw = 0x00080867, .pc = 0x2000, .values = .{ .a = 0x3001, .b = 0, .c = 0x2004, .previous_rd = 9 }, .next = 0x3000 }, // jalr x16,0(x16)
    .{ .raw = 0x0080b583, .pc = 0x2000, .values = .{ .a = 0x5000, .b = 0, .c = 99, .previous_rd = 5 }, .next = 0x2004 }, // ld x11,8(x1)
    .{ .raw = 0xfe80bc23, .pc = 0x2000, .values = .{ .a = 0x5000, .b = 0, .c = 0, .previous_rd = 0 }, .next = 0x2004 }, // sd x8,-8(x1)
    .{ .raw = 0x0006d463, .pc = 0x2000, .values = .{ .a = 5, .b = 0, .c = 1, .previous_rd = 0 }, .next = 0x2008 }, // bge x13,x0,+8 taken
    .{ .raw = 0x0006d463, .pc = 0x2000, .values = .{ .a = @bitCast(@as(i64, -5)), .b = 0, .c = 0, .previous_rd = 0 }, .next = 0x2004 }, // not taken
    .{ .raw = 0x00000073, .pc = 0x2000, .values = .{ .a = 0x7000, .b = 3, .c = 0, .previous_rd = 0 }, .next = 0x2004 }, // ecall
};
fn rows(c: Case) ![2]X.row.Main {
    const entry = X.Entry.fromDecoded(c.raw, c.pc);
    try std.testing.expect(entry.valid and entry.compactValid());
    const clocks = [3]u32{ @intFromBool(entry.ids[0] != 0), 2 * @as(u32, @intFromBool(entry.ids[1] != 0)), 3 * @as(u32, @intFromBool(entry.ids[2] != 0)) };
    return .{ try X.row.active(entry, 4, c.next, c.values, clocks), try X.row.compact.active(entry, 4, c.next, c.values, clocks) };
}
fn previousWithNext(next: u64) X.row.Main {
    return X.row.compact.padding(0, next) catch unreachable;
}

test "compact rows: honest REG, FUNCTION, OWNER tuples equal the legacy ones and ROM equals the compact ROM fact" {
    const fixed = [_]M{ M.fromCanonical(4), M.zero(), M.zero() };
    for (cases) |c| {
        const entry = X.Entry.fromDecoded(c.raw, c.pc);
        const both = try rows(c);
        const legacy = &both[0];
        const compact = &both[1];
        const immediate_in_b = entry.use_immediate;
        for (0..3) |slot| for ([_]bool{ false, true }) |after| {
            const lt = U.register(M, &fixed, legacy, slot, after);
            const ct = U.compact.register(M, &fixed, compact[0..K.COUNT], slot, after);
            // An immediate in B rides on the unused (weight-zero) rs2 slot.
            if (slot == 1 and immediate_in_b) {
                try std.testing.expect(compact[K.enabled + 1].isZero());
            } else try std.testing.expectEqualSlices(M, &lt, &ct);
        };
        const lf = U.function(M, legacy);
        const cf = U.compact.function(M, compact[0..K.COUNT]);
        if (entry.use_pc) {
            // AUIPC/JAL: ADD(pc, imm) becomes ADD(0, pc+imm); same result C.
            var want = lf;
            for (0..4) |i| want[1 + i] = M.zero();
            X.features.put(want[5..9], 0, c.pc +% entry.immediate);
            try std.testing.expectEqualSlices(M, &want, &cf);
        } else try std.testing.expectEqualSlices(M, &lf, &cf);
        // OWNER weight is active-function: only LS/ECALL rows carry the tuple
        // (FUNCTION rows have weight zero; legacy put their IMM there too).
        if (!entry.function) try std.testing.expectEqualSlices(M, &U.owner(M, &fixed, legacy, M.one(), false), &U.compact.owner(M, &fixed, compact[0..K.COUNT], M.one()));
        const prior = previousWithNext(c.pc);
        const taken = entry.branch and c.values.c != 0;
        try std.testing.expectEqualSlices(M, &entry.romTupleCompact(taken), &U.compact.rom(M, &fixed, compact[0..K.COUNT], prior[0..K.COUNT], M.zero()));
        // Row 0 reads the public initial PC instead of the previous row.
        const first = [_]M{ M.zero(), M.one(), M.zero() };
        try std.testing.expectEqualSlices(M, &entry.romTupleCompact(taken), &U.compact.rom(M, &first, compact[0..K.COUNT], &previousWithNext(0x7777000), M.fromCanonical(@intCast(c.pc))));
        // Weights agree.
        const lw = Eq.weightsFor(M, legacy);
        const cw = Eq.compactWeightsFor(M, compact[0..K.COUNT]);
        try std.testing.expect(std.meta.eql(lw, cw));
    }
}

test "compact MAIN-only residuals: honest rows vanish; x0 A/RD values, padding PC drift, final PC and clocks are rejected" {
    const fixed = [_]M{ M.fromCanonical(4), M.zero(), M.zero() };
    const public = X.types.Inputs{ .steps = 9, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x2008, 0, 0, 0 }, .epoch = 1 };
    const Res = [Eq.COMPACT_MAIN_CONSTRAINTS]Q;
    const residuals = struct {
        fn of(f: []const M, row: []const M, prior: []const M, p: X.types.Inputs) Res {
            var out: Res = undefined;
            var sink = E.Sink{ .values = &out };
            const fq = toQ(3, f[0..3].*);
            const rq = toQ(K.COUNT, row[0..K.COUNT].*);
            const pq = toQ(K.COUNT, prior[0..K.COUNT].*);
            Eq.emitCompactMainFor(Q, &fq, &rq, &pq, p, &sink);
            return out;
        }
        fn zero(r: Res) bool {
            for (r) |v| if (!v.isZero()) return false;
            return true;
        }
    };
    for (cases) |c| {
        const both = try rows(c);
        const prior = blk: {
            var p = previousWithNext(c.pc);
            p[K.active] = M.one();
            break :blk p;
        };
        const honest_res = residuals.of(&fixed, &both[1], &prior, public);
        if (!residuals.zero(honest_res)) {
            for (honest_res, 0..) |v, i| if (!v.isZero()) std.debug.print("case {x}: residual {d}\n", .{ c.raw, i });
            return error.TestUnexpectedResult;
        }
        const entry = X.Entry.fromDecoded(c.raw, c.pc);
        // A nonzero A on an unread rs1 (AUIPC/LUI/JAL) is a local violation.
        if (entry.ids[0] == 0) {
            var forged = both[1];
            forged[K.a + 2] = M.one();
            if (residuals.zero(residuals.of(&fixed, &forged, &prior, public))) {
                std.debug.print("main-only check 36 failed\n", .{});
                return error.TestUnexpectedResult;
            }
        }
        if (entry.ids[2] == 0) {
            var forged = both[1];
            forged[K.previous_rd] = M.one();
            if (residuals.zero(residuals.of(&fixed, &forged, &prior, public))) {
                std.debug.print("main-only check 41 failed\n", .{});
                return error.TestUnexpectedResult;
            }
        }
        // B carries no local guard; the ROM binds it (see the ROM test).
        var b = both[1];
        b[K.b + 3] = M.fromCanonical(77);
        if (!residuals.zero(residuals.of(&fixed, &b, &prior, public))) {
            std.debug.print("main-only check 46 failed\n", .{});
            return error.TestUnexpectedResult;
        }
    }
    // Padding: next must equal the predecessor's next and, on the last row, final.
    const pad = try X.row.compact.padding(20, 0x2008);
    const pad_fixed = [_]M{ M.fromCanonical(20), M.zero(), M.zero() };
    if (!residuals.zero(residuals.of(&pad_fixed, &pad, &pad, public))) {
        std.debug.print("main-only check 51 failed\n", .{});
        return error.TestUnexpectedResult;
    }
    const drift = try X.row.compact.padding(20, 0x200c);
    if (residuals.zero(residuals.of(&pad_fixed, &drift, &pad, public))) {
        std.debug.print("main-only check 53 failed\n", .{});
        return error.TestUnexpectedResult;
    }
    const last_fixed = [_]M{ M.fromCanonical(31), M.zero(), M.one() };
    const pad31 = try X.row.compact.padding(31, 0x2008);
    const drift31 = try X.row.compact.padding(31, 0x200c);
    if (!residuals.zero(residuals.of(&last_fixed, &pad31, &pad31, public))) {
        std.debug.print("main-only check 55 failed\n", .{});
        return error.TestUnexpectedResult;
    }
    if (residuals.zero(residuals.of(&last_fixed, &drift31, &drift31, public))) {
        std.debug.print("main-only check 56 failed\n", .{});
        return error.TestUnexpectedResult;
    }
}

test "compact ROM: forged immediates, x0 operands, wrong slots, LS offsets and AUIPC/JAL constants never equal the decoded fact" {
    const fixed = [_]M{ M.fromCanonical(4), M.zero(), M.zero() };
    for (cases) |c| {
        const entry = X.Entry.fromDecoded(c.raw, c.pc);
        const taken = entry.branch and c.values.c != 0;
        const want = entry.romTupleCompact(taken);
        const honest = (try rows(c))[1];
        const prior = previousWithNext(c.pc);
        try std.testing.expect(same(&want, &U.compact.rom(M, &fixed, honest[0..K.COUNT], prior[0..K.COUNT], M.zero())));
        const romOf = struct {
            fn of(f: []const M, row: X.row.Main, p: X.row.Main) [30]M {
                return U.compact.rom(M, f, row[0..K.COUNT], p[0..K.COUNT], M.zero());
            }
        }.of;
        // B is bound whenever rs2 is not a live register: immediate rows and x0 reads.
        if (honest[K.enabled + 1].isZero()) {
            var forged = honest;
            forged[K.b] = forged[K.b].add(M.one());
            if (same(&want, &romOf(&fixed, forged, prior))) {
                std.debug.print("case {x} line 250: forged ROM tuple accepted\n", .{c.raw});
                return error.TestUnexpectedResult;
            }
        }
        // Wrong slot: an immediate moved from B to the LS-offset slot.
        if (entry.use_immediate) {
            var forged = honest;
            forged[K.ls_imm] = honest[K.b];
            forged[K.ls_imm + 1] = honest[K.b + 1];
            for (0..4) |i| forged[K.b + i] = M.zero();
            if (same(&want, &romOf(&fixed, forged, prior))) {
                std.debug.print("case {x} line 257: forged ROM tuple accepted\n", .{c.raw});
                return error.TestUnexpectedResult;
            }
        }
        // LS offset limbs are bound for every row (zero off LS).
        for (0..2) |limb| {
            var forged = honest;
            forged[K.ls_imm + limb] = forged[K.ls_imm + limb].add(M.fromCanonical(4));
            if (same(&want, &romOf(&fixed, forged, prior))) {
                std.debug.print("case {x} line 263: forged ROM tuple accepted\n", .{c.raw});
                return error.TestUnexpectedResult;
            }
        }
        // Wrong row PC (previous next) or wrong static next.
        if (same(&want, &romOf(&fixed, honest, previousWithNext(c.pc + 4)))) {
            std.debug.print("case {x} line 266: forged ROM tuple accepted\n", .{c.raw});
            return error.TestUnexpectedResult;
        }
        if (!entry.dynamic_next) {
            var forged = honest;
            forged[K.next] = forged[K.next].add(M.fromCanonical(4));
            if (same(&want, &romOf(&fixed, forged, prior))) {
                std.debug.print("case {x} line 270: forged ROM tuple accepted\n", .{c.raw});
                return error.TestUnexpectedResult;
            }
        }
        // Flag forgeries.
        for ([_]usize{ K.branch, K.dynamic_next, K.function }) |flag| {
            var forged = honest;
            forged[flag] = M.one().sub(forged[flag]);
            if (same(&want, &romOf(&fixed, forged, prior))) {
                std.debug.print("case {x} line 276: forged ROM tuple accepted\n", .{c.raw});
                return error.TestUnexpectedResult;
            }
        }
    }
}

test "compact decode admission: PCs and successors below 2^31, LS offsets as (low16, sign), immediates never share a read rs2" {
    const add = X.Entry.fromDecoded(0x001080b3, 0x1000);
    try std.testing.expect(add.compactValid());
    // PC at/above 2^31: the compact ROM fact is invalid (all zero).
    const high = X.Entry.fromDecoded(0x001080b3, 1 << 31);
    try std.testing.expect(high.valid and !high.compactValid());
    try std.testing.expect(high.romTupleCompact(false)[0].isZero());
    // Successor at 2^31 (pc + 4 = 2^31): invalid.
    const edge = X.Entry.fromDecoded(0x001080b3, (1 << 31) - 4);
    try std.testing.expect(!edge.compactValid());
    // JAL whose target crosses 2^31: invalid.
    const jal = X.Entry.fromDecoded(0x7fcff06f, (1 << 31) - 0x1000); // jal x0,+0xffffc
    try std.testing.expect(jal.valid and jal.staticNext(false) >= 1 << 31 and !jal.compactValid());
    // Branch whose taken target crosses 2^31: the taken edge is absent.
    const branch = X.Entry.fromDecoded(0x0006d863, (1 << 31) - 0x10); // bge x13,x0,+16
    try std.testing.expect(branch.compactValid() and branch.hasTakenEdge() and !branch.compactTakenEdge());
    try std.testing.expect(branch.romTupleCompact(true)[0].isZero());
    try std.testing.expect(!branch.romTupleCompact(false)[0].isZero());
    // Negative and positive LS offsets.
    const sd = X.Entry.fromDecoded(0xfe80bc23, 0x2000);
    try std.testing.expectEqual([2]u16{ 0xfff8, 0xffff }, sd.compactLs().?);
    const ld = X.Entry.fromDecoded(0x0080b583, 0x2000);
    try std.testing.expectEqual([2]u16{ 8, 0 }, ld.compactLs().?);
    // AUIPC/JAL fold to static constants.
    const auipc = X.Entry.fromDecoded(0x00001797, 0x2000);
    try std.testing.expectEqual(@as(u64, 0x3000), auipc.compactB());
    try std.testing.expectEqual(@as(u64, 0x2004), X.Entry.fromDecoded(0x0080086f, 0x2000).compactB());
    // Every admitted opcode class: an immediate row never reads rs2.
    for (std.enums.values(@import("stwo_riscv_frontend").rv64.decode.Opcode)) |op| {
        const entry = X.Entry.fromInstruction(0, 0x1000, .{ .opcode = op, .rs1 = 1, .rs2 = 2, .rd = 3, .imm = -16 });
        if (!entry.valid) continue;
        try std.testing.expect(entry.compactValid());
        if (entry.use_immediate) try std.testing.expectEqual(@as(u5, 0), entry.ids[1]);
    }
    // Endpoints: limbs 2..3 zero and below 2^31.
    var public = inputs();
    try X.types.validateCompactInputs(public, 5);
    public.final_pc[1] = 0x8000;
    try std.testing.expectError(error.InvalidExecutionInputs, X.types.validateCompactInputs(public, 5));
    public = inputs();
    public.initial_pc[2] = 1;
    try std.testing.expectError(error.InvalidExecutionInputs, X.types.validateCompactInputs(public, 5));
    try X.types.validateInputs(public, 5);
    try std.testing.expectError(error.InvalidExecutionNextPc, X.row.compact.padding(3, 1 << 31));
}

test "JALR alias: a target T + p has the same felt but is odd, so no AND16(x, ~1) output equals it" {
    // v is a ROM pc (< 2^31, 4-aligned); T = v + p < 2^32 is the only other
    // u32 with felt(T) = v, and it is odd because p is odd.
    const p: u64 = (1 << 31) - 1;
    for ([_]u64{ 0, 4, 0x1000, 0x7ffffffc }) |v| {
        const t = v + p;
        try std.testing.expect(t < 1 << 32 and t & 1 == 1);
        const lo = M.fromCanonical(@as(u16, @truncate(t)));
        const hi = M.fromCanonical(@as(u16, @truncate(t >> 16)));
        try std.testing.expectEqual(@as(u32, @intCast(v % p)), lo.add(M.fromCanonical(65536).mul(hi)).v);
        // AND16 low limb of any x & ~1 is even.
        try std.testing.expect(@as(u16, @truncate(t)) & 1 == 1);
    }
}
