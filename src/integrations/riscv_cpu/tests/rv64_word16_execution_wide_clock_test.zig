//! Wide-clock CPU encoding (log 23, fused tail): 25-bit REG gaps through the
//! scaled U16 query 128*gap8, OWNER tick row+1, exhaustive bound on every
//! value the U16 lookup can accept, forged-clock rejection, and the
//! geometry/component admission that keeps logs <= 22 byte-identical.
const std = @import("std");
const core = @import("stwo_core");
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const E = @import("stwo_riscv_frontend").rv64_air.evaluation;
const G = @import("../word16_execution/geometry.zig");
const Coverage = @import("../word16_execution/coverage.zig");
const Q = E.Q;
const M = core.fields.m31.M31;
const L = X.layout;
const Eq = X.equations;
const W = L.fused.COUNT;
const N = Eq.FUSED_CONSTRAINTS;
const REG = Eq.MAIN_CONSTRAINTS;
const U8 = REG + 7;
const FUSED = REG + 8;
/// Rows sit at the top of a 2^23 CPU, so every register tick exceeds 2^24.
const BASE: u32 = (1 << 23) - 64;

fn challenges(channel: *core.channel.blake2s.Blake2sChannel) X.types.Challenges {
    var out: X.types.Challenges = undefined;
    inline for (.{ "register", "function", "rom", "owner" }) |field| {
        @field(out, field).offset = channel.drawSecureFelt();
        for (&@field(out, field).coefficients) |*value| value.* = channel.drawSecureFelt();
    }
    inline for (.{ "range16", "range8" }) |field| @field(out, field) = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    return out;
}
fn inputs(wide: bool) X.types.Inputs {
    return .{ .steps = BASE + 1, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x1004, 0, 0, 0 }, .epoch = 1, .wide_clock = wide };
}
fn toQ(comptime K: usize, values: [K]M) [K]Q {
    var out: [K]Q = undefined;
    for (values, &out) |v, *o| o.* = Q.fromBase(v);
    return out;
}
fn put(row: *[W]M, column: usize, value: Q) void {
    @memcpy(row[column..][0..4], &value.toM31Array());
}
fn get(row: [W]M, column: usize) Q {
    return Q.fromM31Array(row[column..][0..4].*);
}
fn range16(ch: X.types.Challenges, value: u32) Q {
    return ch.range16.offset.sub(ch.range16.coefficient.mulM31(M.fromCanonical(value)));
}

const Trace = struct {
    fixed: [32][3]M,
    main: [32][L.main.COUNT]M,
    inter: [32][W]M,
    claim: Q,
    ch: X.types.Challenges,
    /// Row 0 is `add x1,x1,x1` at CPU row BASE whose rs1 read follows the
    /// boundary write at tick 0: gap 4*BASE (>= 2^24, gap8 = 511).
    fn init() !Trace {
        var channel = core.channel.blake2s.Blake2sChannel{};
        var self: Trace = undefined;
        self.ch = challenges(&channel);
        var contributions: [32]Q = undefined;
        self.claim = Q.zero();
        const entry = X.Entry.fromDecoded(0x001080b3, 0x1000);
        for (0..32) |row| {
            const index: u32 = BASE + @as(u32, @intCast(row));
            self.fixed[row] = .{ M.fromCanonical(index), M.fromCanonical(@intFromBool(row == 0)), M.fromCanonical(@intFromBool(row == 31)) };
            self.main[row] = if (row == 0) try X.row.active(entry, index, 0x1004, .{ .a = 7, .b = 7, .c = 14, .previous_rd = 7 }, .{ 0, 4 * index + 1, 4 * index + 2 }) else try X.row.padding(index, 0x1004);
            const ds = Eq.nativeDenominators(&self.fixed[row], &self.main[row], inputs(true), self.ch);
            const witnesses = try Eq.nativeFusedWitnesses(ds, &self.main[row]);
            for (witnesses, 0..) |value, i| put(&self.inter[row], 4 * i, value);
            contributions[row] = try Eq.nativeFusedContribution(ds, &self.main[row], witnesses);
            self.claim = self.claim.add(contributions[row]);
        }
        var sum = self.claim.neg();
        for (0..32) |row| {
            sum = sum.add(contributions[row]);
            put(&self.inter[row], L.fused.sum, sum);
        }
        return self;
    }
    fn residualsWith(self: *const Trace, row: usize, main: [L.main.COUNT]M, current: [W]M, previous: [W]M, wide: bool) [N]Q {
        const prior = (row + 31) % 32;
        var out: [N]Q = undefined;
        var sink = E.Sink{ .values = &out };
        Eq.emitFusedFor(Q, &toQ(3, self.fixed[row]), &toQ(L.main.COUNT, main), &toQ(L.main.COUNT, self.main[prior]), &toQ(W, current), &toQ(W, previous), inputs(wide), self.claim, self.ch, &sink);
        return out;
    }
    fn at(self: *const Trace, row: usize) [N]Q {
        return self.residualsWith(row, self.main[row], self.inter[row], self.inter[(row + 31) % 32], true);
    }
};
fn allZero(values: [N]Q) bool {
    for (values) |value| if (!value.isZero()) return false;
    return true;
}

test "wide clock: honest 25-bit register gaps satisfy all 51 fused residuals" {
    const t = try Trace.init();
    for (0..32) |row| try std.testing.expect(allZero(t.at(row)));
    // The rs1 gap really exceeds the 24-bit clock: gap8 is a 9-bit limb.
    const gap = 4 * BASE;
    try std.testing.expect(gap >= 1 << 24);
    try std.testing.expectEqual(@as(u32, gap >> 16), t.main[0][L.main.gap8].v);
    try std.testing.expect(t.main[0][L.main.gap8].v >= 256 and t.main[0][L.main.gap8].v < 512);
    // Padding rows carry gap 4*index+slot up to 2^25 as well.
    try std.testing.expect(t.main[31][L.main.gap8 + 2].v >= 256);
    // The gap8 lookups are U16 queries of 128*gap8 (all inside the table).
    const ds = Eq.nativeDenominators(&t.fixed[0], &t.main[0], inputs(true), t.ch);
    for (0..3) |slot| {
        const scaled = L.WIDE_GAP_SCALE * t.main[0][L.main.gap8 + slot].v;
        try std.testing.expect(scaled < 65536);
        try std.testing.expect(ds.affine[4 + slot].eql(range16(t.ch, scaled)));
    }
}

test "wide clock: every U16-accepted gap8 limb bounds the gap below 2^26 (exhaustive)" {
    // A U16 lookup accepts 128*g8 = y (mod p) for y < 2^16 only. Then
    // 65536*g8 = 512*y (mod p) because 128*512 = 65536, so the committed
    // gap gap16 + 65536*g8 equals the INTEGER gap16 + 512*y < 2^16 + 2^25.
    // Hence tick - previous - 1 is never a wrapped negative (>= p - 2^25).
    const inv128 = try M.fromCanonical(L.WIDE_GAP_SCALE).inv();
    for (0..65536) |y| {
        const g8 = M.fromCanonical(@intCast(y)).mul(inv128);
        const high = M.fromCanonical(65536).mul(g8);
        try std.testing.expectEqual(@as(u32, @intCast(512 * y)), high.v);
        try std.testing.expect(@as(u64, 65535) + high.v < 1 << 26);
    }
    // Margin: a wrapped (backward) gap is at least p - 2^25 > 2^26.
    try std.testing.expect(@as(u64, core.fields.m31.Modulus) - (1 << 25) > 1 << 26);
}

test "wide clock: forged previous clocks and gap limbs are rejected" {
    const t = try Trace.init();
    // (1) Claim slot 0's predecessor is the CURRENT tick (a self-cycle):
    // gap = -1 needs gap16 + 65536*g8 = p - 1, i.e. g8 = (p-1-gap16)/65536.
    // Honest gap16 = 65535 gives g8 = (p - 65536)/65536 = 2^15 - 1 - 2^-16...
    // whatever field value it takes, its scaled U16 query 128*g8 is not a
    // table value, and the previous-clock tuple moves, so REG/U8 reject.
    var forged = t.main[0];
    const target = M.fromCanonical(core.fields.m31.Modulus - 1).sub(forged[L.main.gap16]);
    forged[L.main.gap8] = target.mul(try M.fromCanonical(65536).inv());
    try std.testing.expect(forged[L.main.gap8].mul(M.fromCanonical(L.WIDE_GAP_SCALE)).v >= 65536);
    try std.testing.expect(!allZero(t.residualsWith(0, forged, t.inter[0], t.inter[31], true)));
    // (2) A 10-bit limb (gap8 = 512, a 2^25 gap) has no U16 query: 128*512 = 2^16.
    forged = t.main[0];
    forged[L.main.gap8 + 1] = M.fromCanonical(512);
    try std.testing.expectEqual(@as(u32, 65536), forged[L.main.gap8 + 1].v * L.WIDE_GAP_SCALE);
    try std.testing.expect(!allZero(t.residualsWith(0, forged, t.inter[0], t.inter[31], true)));
    // (3) The same honest wide row under the legacy encoding queries U8 at
    // gap8 >= 256 (no table value) and moves the OWNER tick: rejected.
    try std.testing.expect(!allZero(t.residualsWith(0, t.main[0], t.inter[0], t.inter[31], false)));
    // (4) A perturbed U8 witness slot (scaled U16 pair) keeps rejecting.
    var inter = t.inter[0];
    put(&inter, 4 * 7, get(inter, 4 * 7).add(Q.one()));
    try std.testing.expect(!t.residualsWith(0, t.main[0], inter, t.inter[31], true)[U8].isZero());
    // (5) Tail fusion still strict at a range16 pole of the scaled query.
    var pole = t;
    pole.ch.range16.offset = pole.ch.range16.coefficient.mulM31(t.main[3][L.main.gap8 + 2].mul(M.fromCanonical(L.WIDE_GAP_SCALE)));
    try std.testing.expect(!pole.residualsWith(3, t.main[3], t.inter[3], t.inter[2], true)[FUSED].isZero());
}

test "wide clock: OWNER tick is row+1 and stays 24-bit; legacy keeps 4*row+4" {
    const index = M.fromCanonical((1 << 23) - 2);
    try std.testing.expectEqual(@as(u32, (1 << 23) - 1), X.tuples.ownerTick(M, index, true).v);
    try std.testing.expect(X.tuples.ownerTick(M, index, true).v < 1 << 24);
    const small = M.fromCanonical((1 << 22) - 2);
    try std.testing.expectEqual(@as(u32, 4 * ((1 << 22) - 1)), X.tuples.ownerTick(M, small, false).v);
    try std.testing.expectEqual(@as(u32, 1), L.ramStride(23));
    try std.testing.expectEqual(@as(u32, 4), L.ramStride(22));
    try std.testing.expect(L.wideClock(23) and !L.wideClock(22) and !L.wideClock(5));
    // Prefix capacity: the CPU admits 2^23-1 steps; other prefixes stay 2^22.
    try std.testing.expectEqual(@as(u32, 23), try Coverage.minimalCpuLog((1 << 23) - 1));
    try std.testing.expectEqual(@as(u32, 22), try Coverage.minimalCpuLog((1 << 22) - 1));
    try std.testing.expectError(error.ExecutionCapacityExceeded, Coverage.minimalCpuLog(1 << 23));
    try std.testing.expectError(error.ExecutionCapacityExceeded, Coverage.minimalPrefixLog(1 << 22));
}

fn component(log: u32, fused: bool, pairs: bool, wide: bool) X.component.Component {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = challenges(&channel);
    var public = inputs(wide);
    public.steps = 5;
    return .{ .log_size = log, .offsets = .{ 0, 0, 0 }, .public = public, .claim = Q.zero(), .challenges = ch, .fused = fused, .pairs = if (pairs) .{ .offset = Q.one(), .coefficients = @splat(Q.one()) } else null };
}
test "wide clock: component and geometry admission (log 23 fused-only, logs <= 22 unchanged)" {
    try component(23, true, false, true).validateEncoding();
    try std.testing.expectError(error.InvalidExecutionGeometry, component(23, false, false, true).validateEncoding());
    try std.testing.expectError(error.InvalidExecutionGeometry, component(23, true, true, true).validateEncoding());
    try std.testing.expectError(error.InvalidExecutionGeometry, component(23, true, false, false).validateEncoding());
    try std.testing.expectError(error.InvalidExecutionGeometry, component(22, true, true, true).validateEncoding());
    try std.testing.expectError(error.InvalidExecutionGeometry, component(24, true, false, true).validateEncoding());
    try component(22, true, true, false).validateEncoding();
    try std.testing.expectError(error.InvalidExecutionInputs, X.types.validateInputs(inputs(false), 23));
    try std.testing.expectError(error.InvalidExecutionInputs, X.types.validateInputs(inputs(true), 22));
    const boundary = X.types.Boundary{ .steps = 5, .initial_pc = 0x1000, .final_pc = 0x1004, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    try std.testing.expect((try X.types.inputs(boundary, 1, 23)).wide_clock);
    try std.testing.expect(!(try X.types.inputs(boundary, 1, 22)).wide_clock);

    var g = G.Geometry{ .cpu_log = 23, .cpu_fused_tail = true };
    try g.validate();
    try std.testing.expect(g.wideClock());
    // Range masses: six U16 and no U8 queries per wide CPU row.
    var legacy = g;
    legacy.cpu_log = 22;
    try legacy.validate();
    try std.testing.expectEqual(6 * G.rows(23) - 3 * G.rows(22), (try g.range16Mass()) - (try legacy.range16Mass()));
    try std.testing.expectEqual(3 * G.rows(22), (try legacy.range8Mass()) - (try g.range8Mass()));
    g.cpu_u8_pairs = true;
    try std.testing.expectError(error.InvalidExecutionGeometry, g.validate());
    g.cpu_u8_pairs = false;
    g.cpu_fused_tail = false;
    try std.testing.expectError(error.InvalidExecutionGeometry, g.validate());
    g = .{ .cpu_log = 24, .cpu_fused_tail = true };
    try std.testing.expectError(error.InvalidExecutionGeometry, g.validate());
    // Every non-CPU role stays capped at 22.
    g = .{ .cpu_log = 23, .cpu_fused_tail = true, .ls_log = 23 };
    try std.testing.expectError(error.InvalidExecutionGeometry, g.validate());
    // Identity: the wide-clock domain is separate from the fused tail's.
    try std.testing.expect(!std.mem.eql(u8, &X.features.wideClockIdentity(), &X.features.fusedTailIdentity()));
}
