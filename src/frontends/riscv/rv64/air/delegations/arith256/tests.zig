//! Constraint-level authority tests for the arith256_mod truth AIR.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const L = @import("layout.zig");
const N = @import("native.zig");
const Eq = @import("equations.zig");
const T = @import("trace.zig");
const Candidate = @import("../../../ethereum_services/candidate_services.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const MAX: u256 = std.math.maxInt(u256);

/// Mutable QM31 view, so adversarial tests can place arbitrary field values.
const View = struct {
    fixed_values: [L.FIXED]Q,
    main_values: []Q,
    previous_active: Q,
    inter: [L.INTERACTION]Q = @splat(Q.zero()),
    previous_inter: [L.INTERACTION]Q = @splat(Q.zero()),
    pub fn fixed(self: *const View, c: usize) Q {
        return self.fixed_values[c];
    }
    pub fn main(self: *const View, c: usize) Q {
        return self.main_values[c];
    }
    pub fn previousActive(self: *const View) Q {
        return self.previous_active;
    }
    pub fn interaction(self: *const View, c: usize) Q {
        return self.inter[c];
    }
    pub fn previousInteraction(self: *const View, c: usize) Q {
        return self.previous_inter[c];
    }
};
fn q(v: u32) Q {
    return Q.fromBase(M.fromCanonical(v));
}
fn qi(v: i64) Q {
    return Q.fromBase(M.fromU64(@intCast(@mod(v, core.fields.m31.Modulus))));
}
const Case = struct {
    main: [L.MAIN]Q,
    view: View,
    fn init(self: *Case, input: N.Input) void {
        var row: N.Row = undefined;
        _ = N.fill(&row, input);
        for (&self.main, row) |*dst, v| dst.* = q(v);
        self.view = .{ .fixed_values = .{ q(0), q(1), q(0), q(0) }, .main_values = &self.main, .previous_active = q(0) };
    }
    fn residuals(self: *Case, out: *[L.MAIN_CONSTRAINTS]Q) void {
        self.view.main_values = &self.main;
        var sink = E.Sink{ .values = out };
        Eq.emitMain(Q, &self.view, .{ .calls = 1000, .first_id = 1 }, &sink);
        std.debug.assert(sink.count == L.MAIN_CONSTRAINTS);
    }
    /// Index of the first nonzero MAIN residual (activity uses calls = 1000).
    fn firstFailure(self: *Case) ?usize {
        var values: [L.MAIN_CONSTRAINTS]Q = undefined;
        self.residuals(&values);
        for (values, 0..) |v, i| if (!v.isZero()) return i;
        return null;
    }
    /// Replaces q, r, z (and recomputes inv, carries, d and borrows exactly as
    /// a cheating prover would) from signed limb values, which may be
    /// non-canonical. Returns false when the carried identity has no integer
    /// solution for these limbs (a non-multiple of 65536 at some group).
    fn forge(self: *Case, qb: *const [L.Q_LIMBS]i64, rb: *const [L.LIMBS]i64, z: u1) bool {
        var a: [L.LIMBS]i64 = undefined;
        var b: [L.LIMBS]i64 = undefined;
        var c: [L.LIMBS]i64 = undefined;
        var m: [L.LIMBS]i64 = undefined;
        for (0..L.LIMBS) |i| {
            a[i] = (self.main[L.A + i].tryIntoM31() catch unreachable).v;
            b[i] = (self.main[L.B + i].tryIntoM31() catch unreachable).v;
            c[i] = (self.main[L.C + i].tryIntoM31() catch unreachable).v;
            m[i] = (self.main[L.M + i].tryIntoM31() catch unreachable).v;
        }
        for (0..L.Q_LIMBS) |i| self.main[L.QUOTIENT + i] = qi(qb[i]);
        for (0..L.LIMBS) |i| self.main[L.R + i] = qi(rb[i]);
        self.main[L.Z] = q(z);
        var sum_m: i64 = 0;
        for (m) |x| sum_m += x;
        self.main[L.INV] = if (sum_m == 0) Q.zero() else Q.fromBase(M.fromU64(@intCast(sum_m)).inv() catch unreachable);
        var p: [L.COEFFICIENTS + 1]i64 = @splat(0);
        if (z == 0) {
            for (0..L.LIMBS) |i| for (0..L.LIMBS) |j| {
                p[i + j] += a[i] * b[j];
            };
            for (0..L.LIMBS) |k| p[k] += c[k];
        }
        for (0..L.Q_LIMBS) |i| for (0..L.LIMBS) |j| {
            p[i + j] -= qb[i] * m[j];
        };
        for (0..L.LIMBS) |k| p[k] -= rb[k];
        var carry: i64 = 0;
        var exact = true;
        for (0..L.GROUPS) |j| {
            const g = p[2 * j] + 256 * p[2 * j + 1] + carry;
            if (@mod(g, 65536) != 0) exact = false;
            carry = @divFloor(g, 65536);
            if (j == L.CARRIES) break;
            const encoded = carry + L.CARRY_OFFSET;
            self.main[L.CARRY_LO + j] = qi(@mod(encoded, 256));
            self.main[L.CARRY_HI + j] = qi(@divFloor(encoded, 256));
        }
        // d = m - r - s over 16-bit chunks, borrows Boolean, last chunk free.
        var borrow: i64 = 0;
        for (0..L.CHUNKS) |i| {
            const mi = m[2 * i] + 256 * m[2 * i + 1];
            const ri = rb[2 * i] + 256 * rb[2 * i + 1];
            const s: i64 = if (i == 0) 1 - @as(i64, z) else 0;
            var diff = mi - ri - s - borrow;
            borrow = 0;
            if (i < L.BORROWS and diff < 0) {
                diff += 65536;
                borrow = 1;
            }
            self.main[L.D + 2 * i] = qi(@mod(diff, 256));
            self.main[L.D + 2 * i + 1] = qi(@divFloor(diff, 256));
            if (i < L.BORROWS) self.main[L.BORROW + i] = q(@intCast(borrow));
        }
        return exact;
    }
    /// Values of every BYTE query of the current row, as field elements.
    fn outOfRangeQuery(self: *Case) bool {
        self.view.main_values = &self.main;
        for (0..L.BYTE_QUERIES) |i| {
            const v = Eq.byteQuery(Q, &self.view, i).tryIntoM31() catch return true;
            if (v.v > 255) return true;
        }
        return false;
    }
};
fn limbs64(value: u512) [L.Q_LIMBS]i64 {
    var out: [L.Q_LIMBS]i64 = undefined;
    for (&out, 0..) |*x, i| x.* = @intCast((value >> @intCast(8 * i)) & 0xff);
    return out;
}
fn limbs32(value: u256) [L.LIMBS]i64 {
    var out: [L.LIMBS]i64 = undefined;
    for (&out, 0..) |*x, i| x.* = @intCast((value >> @intCast(8 * i)) & 0xff);
    return out;
}
fn quotient(input: N.Input) u512 {
    return (@as(u512, input.a) * input.b + input.c) / input.m;
}
fn randomValue(rng: std.Random) u256 {
    return switch (rng.uintLessThan(u8, 6)) {
        0 => rng.int(u64),
        1 => rng.int(u128),
        2 => MAX - rng.int(u16),
        3 => @as(u256, 1) << rng.int(u8),
        else => rng.int(u256),
    };
}
fn randomInput(rng: std.Random) N.Input {
    return .{ .a = randomValue(rng), .b = randomValue(rng), .c = randomValue(rng), .m = randomValue(rng), .r_before = rng.int(u256) };
}
const P256: u256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
const SECP_N: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
const BN254: u256 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

test "known answers: edge and random values agree with independent big-integer references" {
    const edges = [_]u256{ 0, 1, 2, 255, 256, 65535, 1 << 64, (1 << 128) - 1, 1 << 255, MAX - 1, MAX, P256, SECP_N, BN254, BN254 - 1 };
    var case: Case = undefined;
    var count: usize = 0;
    var row: N.Row = undefined;
    for (edges) |a| for (edges) |m| for ([_]u256{ 0, 1, MAX }) |b| for ([_]u256{ 0, MAX, m -% 1 }) |c| {
        const input = N.Input{ .a = a, .b = b, .c = c, .m = m };
        const r = N.fill(&row, input);
        try std.testing.expectEqual(Candidate.mulAddMod(a, b, c, m), r);
        try std.testing.expectEqual(N.reference(a, b, c, m), r);
        if (m != 0) try std.testing.expect(r < m) else try std.testing.expectEqual(@as(u256, 0), r);
        case.init(input);
        try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
        try std.testing.expect(!case.outOfRangeQuery());
        count += 1;
    };
    // Squares of m - 1 plus m - 1: (m-1)^2 + (m-1) = m(m-1), so r = 0.
    for (edges) |m| if (m != 0) {
        const input = N.Input{ .a = m - 1, .b = m - 1, .c = m - 1, .m = m };
        try std.testing.expectEqual(@as(u256, 0), N.fill(&row, input));
        case.init(input);
        try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
    };
    var prng = std.Random.DefaultPrng.init(0xa256);
    const rng = prng.random();
    for (0..400) |_| {
        const input = randomInput(rng);
        const r = N.fill(&row, input);
        // Independent reference: schoolbook u512 via two u256 halves.
        const product = std.math.mulWide(u256, input.a, input.b);
        const total = @as(u512, product) + input.c;
        try std.testing.expectEqual(if (input.m == 0) @as(u256, 0) else @as(u256, @truncate(total % input.m)), r);
        case.init(input);
        try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
        try std.testing.expect(!case.outOfRangeQuery());
        count += 1;
    }
    try std.testing.expect(count > 1000);
}

test "adversarial: wrong r, r >= m, wrong q with wraparound" {
    var prng = std.Random.DefaultPrng.init(0xbad256);
    const rng = prng.random();
    var case: Case = undefined;
    var exercised = [_]usize{0} ** 3;
    for (0..64) |_| {
        var input = randomInput(rng);
        if (input.m == 0) input.m = 1 + rng.int(u64);
        const r = N.reference(input.a, input.b, input.c, input.m);
        const qv = quotient(input);
        // Wrong r: any other r with the honest q leaves the identity unsolvable.
        case.init(input);
        const wrong = r +% (1 + rng.int(u32));
        _ = case.forge(&limbs64(qv), &limbs32(wrong), 0);
        try std.testing.expect(case.firstFailure() != null);
        exercised[0] += 1;
        // r >= m: (q - 1, r + m) satisfies the identity exactly. The r < m
        // chain then needs d = m - r - 1 < 0: its top chunk (no final
        // borrow) can only hold a negative field value, outside the BYTE table.
        if (qv > 0 and @as(u512, r) + input.m <= MAX) {
            case.init(input);
            try std.testing.expect(case.forge(&limbs64(qv - 1), &limbs32(r + input.m), 0));
            try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
            try std.testing.expect(case.outOfRangeQuery());
            // With canonical d bytes instead, the top chunk equation fails.
            case.main[L.D + 31] = q(0);
            const failure = case.firstFailure() orelse return error.AcceptedNonCanonicalRemainder;
            try std.testing.expectEqual(@as(usize, L.BOOLEANS + L.ZERO_TEST + L.GROUPS + L.CHUNKS - 1), failure);
            exercised[1] += 1;
        }
        // Wrong q with wraparound: q + 2^k m' changes q*m only above 2^256
        // (a mod-2^256 check would accept); the 512-bit identity rejects it.
        case.init(input);
        const shift: u16 = 256 - @as(u16, @min(255, @ctz(input.m)));
        const forged_q = qv +% (@as(u512, 1) << @intCast(shift));
        // forged_q * m == q * m (mod 2^256): equal low halves, wrong product.
        try std.testing.expectEqual(@as(u256, @truncate(forged_q *% input.m)), @as(u256, @truncate(qv *% input.m)));
        _ = case.forge(&limbs64(forged_q), &limbs32(r), 0);
        try std.testing.expect(case.firstFailure() != null);
        exercised[2] += 1;
    }
    for (exercised) |e| try std.testing.expect(e > 8);
}

test "adversarial: m = 0 indicator cannot be forged" {
    var prng = std.Random.DefaultPrng.init(0x2e60);
    const rng = prng.random();
    var case: Case = undefined;
    for (0..32) |_| {
        var input = randomInput(rng);
        input.m = 0;
        // Honest: r = 0, q = 0, z = 1.
        case.init(input);
        try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
        try std.testing.expect(case.main[L.Z].eql(q(1)));
        // m = 0 with any nonzero r and z = 1: identity 0 = r rejects.
        case.init(input);
        const r: u256 = 1 + rng.int(u255);
        _ = case.forge(&limbs64(0), &limbs32(r), 1);
        try std.testing.expect(case.firstFailure() != null);
        // m = 0 claimed live (z = 0): sum(m) * inv = 1 is impossible.
        case.init(input);
        _ = case.forge(&limbs64(0), &limbs32(0), 0);
        try std.testing.expect(case.firstFailure() != null);
        // q is unconstrained but bounded when m = 0: any q passes MAIN.
        case.init(input);
        try std.testing.expect(case.forge(&limbs64(rng.int(u512)), &limbs32(0), 1));
        try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
        // Non-Boolean z: z = 2 with m = 0 fails z * sum(m) = 0 only if m != 0,
        // so it is caught by Booleanity and sum(m) * inv = 1 - z.
        case.init(input);
        case.main[L.Z] = q(2);
        try std.testing.expect(case.firstFailure() != null);
        // m != 0 but z = 1 (claiming r = 0 for free): z * sum(m) = 0 rejects.
        input.m = 1 + rng.int(u64);
        case.init(input);
        _ = case.forge(&limbs64(0), &limbs32(0), 1);
        try std.testing.expect(case.firstFailure() != null);
    }
}

test "adversarial: non-canonical limbs and carry forgery reach an out-of-range BYTE query" {
    var prng = std.Random.DefaultPrng.init(0xca77);
    const rng = prng.random();
    var case: Case = undefined;
    var forged: usize = 0;
    for (0..64) |_| {
        var input = randomInput(rng);
        if (input.m == 0) input.m = 3;
        const r = N.reference(input.a, input.b, input.c, input.m);
        const qv = quotient(input);
        // Non-canonical q limb: q_i + 256, q_{i+1} - 1 keeps the integer q.
        var qb = limbs64(qv);
        const i = rng.uintLessThan(usize, L.Q_LIMBS - 1);
        if (qb[i + 1] > 0) {
            qb[i] += 256;
            qb[i + 1] -= 1;
            case.init(input);
            try std.testing.expect(case.forge(&qb, &limbs32(r), 0));
            // MAIN accepts (the integer identity is unchanged) ...
            try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
            // ... and the q byte is outside the BYTE table.
            try std.testing.expect(case.outOfRangeQuery());
            forged += 1;
        }
        // Carry forgery: move 1 from carry j into 65536 in group j: the honest
        // carry changes by one, so group j or j + 1 fails.
        case.init(input);
        const j = rng.uintLessThan(usize, L.CARRIES);
        case.main[L.CARRY_LO + j] = case.main[L.CARRY_LO + j].add(q(1));
        try std.testing.expect(case.firstFailure() != null);
        // A high carry byte of 128 or more (|carry| >= 2^14) is out of range
        // through the hi + 128 query even when the hi byte itself is a byte.
        case.init(input);
        case.main[L.CARRY_HI + j] = q(200);
        try std.testing.expect(case.outOfRangeQuery());
        // A d byte above 255 (borrowing through d instead of the chain).
        case.init(input);
        case.main[L.D] = case.main[L.D].add(q(65536));
        case.main[L.D + 1] = case.main[L.D + 1].sub(q(256));
        try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
        try std.testing.expect(case.outOfRangeQuery());
    }
    try std.testing.expect(forged > 16);
}

test "every single-cell perturbation of an honest row violates a MAIN residual or a lookup" {
    var prng = std.Random.DefaultPrng.init(0xce11);
    const rng = prng.random();
    var case: Case = undefined;
    const input = randomInput(rng);
    for (0..L.MAIN) |c| {
        case.init(input);
        case.main[c] = case.main[c].add(q(1));
        // R_BEFORE is bound only by Wire35; MULT only by the BYTE chain.
        if (c >= L.R_BEFORE and c < L.R or c == L.MULT) {
            try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
            continue;
        }
        try std.testing.expect(case.firstFailure() != null);
    }
}

test "activity prefix: exactly rows 0..calls-1 may be active" {
    var case: Case = undefined;
    const input = N.Input{ .a = 3, .b = 5, .c = 7, .m = 11 };
    var zero: N.Row = @splat(0);
    _ = &zero;
    // Row 0 must be active.
    for (&case.main) |*v| v.* = Q.zero();
    case.view = .{ .fixed_values = .{ q(0), q(1), q(0), q(0) }, .main_values = &case.main, .previous_active = q(0) };
    try std.testing.expect(case.firstFailure() != null);
    // 0 -> 1 transitions after row 0 are forbidden.
    case.init(input);
    case.view.fixed_values = .{ q(5), q(0), q(0), q(5) };
    try std.testing.expect(case.firstFailure() != null);
    // A 1 -> 0 transition only at row == calls (1000 in the helper).
    for (&case.main) |*v| v.* = Q.zero();
    case.view = .{ .fixed_values = .{ q(999), q(0), q(0), q(999 & 255) }, .main_values = &case.main, .previous_active = q(1) };
    try std.testing.expect(case.firstFailure() != null);
    case.view.fixed_values = .{ q(1000), q(0), q(0), q(1000 & 255) };
    try std.testing.expectEqual(@as(?usize, null), case.firstFailure());
    // The last row is never active.
    case.init(input);
    case.view.fixed_values = .{ q(4), q(0), q(1), q(4) };
    case.view.previous_active = q(1);
    try std.testing.expect(case.firstFailure() != null);
}

fn challenges() Eq.Challenges {
    var wire: Eq.Wire = undefined;
    wire.offset = q(0x1234567).add(Q.fromPartialEvals(.{ q(1), q(2), q(3), q(4) }));
    for (&wire.coefficients, 0..) |*c, i| c.* = Q.fromPartialEvals(.{ q(@intCast(i + 9)), q(@intCast(3 * i + 1)), q(77), q(@intCast(i * i + 5)) });
    return .{ .bytes = Q.fromPartialEvals(.{ q(0x51), q(0x7abc), q(0x1010), q(0x3) }), .wire = wire };
}

test "interaction: Wire35 claim equals the native sum and every residual vanishes" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x1a7e);
    const rng = prng.random();
    var inputs: [9]N.Input = undefined;
    for (&inputs) |*input| input.* = randomInput(rng);
    inputs[0].m = 0;
    inputs[1] = .{ .a = MAX, .b = MAX, .c = MAX, .m = 1, .r_before = MAX };
    var source = try T.Source.init(a, &inputs, 11, L.MIN_LOG);
    defer source.deinit();
    const ch = challenges();
    const claim = try source.generateInteraction(ch);
    var expected = Q.zero();
    for (inputs, 0..) |input, r| {
        const out = N.reference(input.a, input.b, input.c, input.m);
        for (0..L.WIRE_FRACTIONS) |id| {
            const d = ch.wire.denominator(&T.externalTuple(11 + @as(u32, @intCast(r)), @intCast(id), N.wireBytes(input, out, @intCast(id))));
            const inv = try d.inv();
            expected = if (id == L.OUTPUT_WIRE) expected.add(inv) else expected.sub(inv);
        }
    }
    try std.testing.expect(claim.eql(expected));
    const n = source.size();
    const R = @import("../../memory/closed_ram/mod.zig");
    var main: [L.MAIN]Q = undefined;
    for (0..n) |r| {
        const p = R.trace.physical(r, L.MIN_LOG);
        const prev = (r + n - 1) % n;
        const pp = R.trace.physical(prev, L.MIN_LOG);
        for (&main, 0..) |*dst, c| dst.* = Q.fromBase(source.main[c * n + p]);
        var view = View{ .fixed_values = undefined, .main_values = &main, .previous_active = Q.fromBase(source.main[L.ACTIVE * n + pp]) };
        for (&view.fixed_values, 0..) |*f, c| f.* = Q.fromBase(source.fixed[c * n + p]);
        for (0..L.INTERACTION) |c| {
            view.inter[c] = Q.fromBase(source.interaction[c * n + p]);
            view.previous_inter[c] = Q.fromBase(source.interaction[c * n + pp]);
        }
        var values: [L.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &values };
        Eq.emit(Q, &view, .{ .calls = inputs.len, .first_id = 11 }, claim, ch, &sink);
        for (values, 0..) |v, i| if (!v.isZero()) {
            std.debug.print("row {d} constraint {d}\n", .{ r, i });
            return error.NonzeroResidual;
        };
    }
}

test "interaction: a forged BYTE multiplicity or claim leaves a nonzero residual" {
    const a = std.testing.allocator;
    var inputs = [_]N.Input{ .{ .a = 5, .b = 7, .c = 1, .m = 13 }, .{ .a = MAX, .b = 2, .c = 0, .m = BN254 } };
    var source = try T.Source.init(a, &inputs, 1, L.MIN_LOG);
    defer source.deinit();
    // Shifting one multiplicity breaks the BYTE chain's closure to zero.
    source.counts[3] += 1;
    source.counts[4] -= 1;
    try std.testing.expectError(error.InvalidArith256ByteCounts, source.generateInteraction(challenges()));
}
