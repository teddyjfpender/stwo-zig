const std = @import("std");
const m31 = @import("fields/m31.zig");
const qm31 = @import("fields/qm31.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub fn CirclePoint(comptime F: type) type {
    return struct {
        x: F,
        y: F,

        const Self = @This();

        pub inline fn zero() Self {
            return .{ .x = F.one(), .y = F.zero() };
        }

        pub inline fn identity() Self {
            return zero();
        }

        pub inline fn eql(lhs: Self, rhs: Self) bool {
            return lhs.x.eql(rhs.x) and lhs.y.eql(rhs.y);
        }

        pub inline fn add(lhs: Self, rhs: Self) Self {
            const x = lhs.x.mul(rhs.x).sub(lhs.y.mul(rhs.y));
            const y = lhs.x.mul(rhs.y).add(lhs.y.mul(rhs.x));
            return .{ .x = x, .y = y };
        }

        pub inline fn neg(self: Self) Self {
            return self.conjugate();
        }

        pub inline fn sub(lhs: Self, rhs: Self) Self {
            return lhs.add(rhs.neg());
        }

        pub inline fn double(self: Self) Self {
            return self.add(self);
        }

        /// Applies the circle x-coordinate doubling map.
        pub inline fn doubleX(x: F) F {
            const sx = x.square();
            return sx.add(sx).sub(F.one());
        }

        /// Returns the binary-log order of this point.
        pub fn logOrder(self: Self) u32 {
            var res: u32 = 0;
            var cur = self.x;
            while (!cur.eql(F.one())) : (res += 1) {
                cur = Self.doubleX(cur);
            }
            return res;
        }

        /// Scalar multiplication by repeated doubling.
        pub fn mul(self: Self, scalar: u128) Self {
            var res = Self.zero();
            var cur = self;
            var s = scalar;
            while (s > 0) : (s >>= 1) {
                if ((s & 1) == 1) {
                    res = res.add(cur);
                }
                cur = cur.double();
            }
            return res;
        }

        pub fn pow(self: Self, exponent: u64) Self {
            return self.mul(exponent);
        }

        pub fn repeatedDouble(self: Self, n: u32) Self {
            var out = self;
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                out = out.double();
            }
            return out;
        }

        pub inline fn conjugate(self: Self) Self {
            return .{ .x = self.x, .y = self.y.neg() };
        }

        pub inline fn complexConjugate(self: Self) Self {
            return .{
                .x = self.x.complexConjugate(),
                .y = self.y.complexConjugate(),
            };
        }

        pub inline fn inv(self: Self) Self {
            return self.conjugate();
        }

        pub inline fn antipode(self: Self) Self {
            return .{ .x = self.x.neg(), .y = self.y.neg() };
        }

        pub fn mulSigned(self: Self, off: isize) Self {
            if (off >= 0) return self.mul(@intCast(off));
            return self.conjugate().mul(@intCast(-off));
        }

        pub inline fn isOnCircle(self: Self) bool {
            const lhs = self.x.square().add(self.y.square());
            return lhs.eql(F.one());
        }

        pub fn format(
            self: Self,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;
            try writer.print("({}, {})", .{ self.x, self.y });
        }
    };
}

pub const CirclePointM31 = CirclePoint(M31);
pub const CirclePointQM31 = CirclePoint(QM31);

/// Backwards-compatible alias for the M31 circle point type.
pub const Point = CirclePointM31;

/// Generator for the circle group over M31.
pub const M31_CIRCLE_GEN: CirclePointM31 = .{
    .x = M31.fromCanonical(2),
    .y = M31.fromCanonical(1_268_011_823),
};

/// Binary-log order of `M31_CIRCLE_GEN`.
pub const M31_CIRCLE_LOG_ORDER: u32 = 31;

/// Generator for the circle group over QM31.
pub const SECURE_FIELD_CIRCLE_GEN: CirclePointQM31 = .{
    .x = QM31.fromU32Unchecked(1, 0, 478_637_715, 513_582_971),
    .y = QM31.fromU32Unchecked(992_285_211, 649_143_431, 740_191_619, 1_186_584_352),
};

/// Order of `SECURE_FIELD_CIRCLE_GEN`.
pub const SECURE_FIELD_CIRCLE_ORDER: u128 = qm31.P4 - 1;

pub fn secureFieldPoint(index: u128) CirclePointQM31 {
    std.debug.assert(index < SECURE_FIELD_CIRCLE_ORDER);
    return SECURE_FIELD_CIRCLE_GEN.mul(index);
}

pub fn randomSecureFieldPoint(channel: anytype) CirclePointQM31 {
    const t = channel.drawSecureFelt();
    const t_square = t.square();
    const one_plus_t_square_inv = t_square.add(QM31.one()).inv() catch unreachable;

    const x = QM31.one().sub(t_square).mul(one_plus_t_square_inv);
    const y = t.add(t).mul(one_plus_t_square_inv);
    return .{ .x = x, .y = y };
}

/// Backwards-compatible alias for the M31 generator.
pub const GENERATOR: CirclePointM31 = M31_CIRCLE_GEN;

pub const CirclePointIndex = struct {
    v: usize,

    pub inline fn zero() CirclePointIndex {
        return .{ .v = 0 };
    }

    pub inline fn generator() CirclePointIndex {
        return .{ .v = 1 };
    }

    pub inline fn eql(lhs: CirclePointIndex, rhs: CirclePointIndex) bool {
        return lhs.v == rhs.v;
    }

    pub inline fn reduce(self: CirclePointIndex) CirclePointIndex {
        return .{ .v = self.v & (circleOrder() - 1) };
    }

    pub fn subgroupGen(log_size: u32) CirclePointIndex {
        std.debug.assert(log_size <= M31_CIRCLE_LOG_ORDER);
        return .{
            .v = @as(usize, 1) << @intCast(M31_CIRCLE_LOG_ORDER - log_size),
        };
    }

    pub fn toPoint(self: CirclePointIndex) CirclePointM31 {
        var acc = CirclePointM31.zero();
        var bits = self.v & CIRCLE_ORDER_MASK;
        var bit: usize = 0;
        while (bits != 0) : (bit += 1) {
            if ((bits & 1) == 1) {
                acc = acc.add(GENERATOR_DOUBLES[bit]);
            }
            bits >>= 1;
        }
        return acc;
    }

    pub fn half(self: CirclePointIndex) CirclePointIndex {
        std.debug.assert((self.v & 1) == 0);
        return .{ .v = self.v >> 1 };
    }

    pub fn add(lhs: CirclePointIndex, rhs: CirclePointIndex) CirclePointIndex {
        return (CirclePointIndex{ .v = lhs.v + rhs.v }).reduce();
    }

    pub fn sub(lhs: CirclePointIndex, rhs: CirclePointIndex) CirclePointIndex {
        return (CirclePointIndex{ .v = lhs.v + circleOrder() - rhs.v }).reduce();
    }

    pub fn mul(lhs: CirclePointIndex, rhs: usize) CirclePointIndex {
        return (CirclePointIndex{ .v = lhs.v *% rhs }).reduce();
    }

    pub fn neg(self: CirclePointIndex) CirclePointIndex {
        return (CirclePointIndex{ .v = circleOrder() - self.v }).reduce();
    }
};

const CIRCLE_ORDER_MASK: usize = (@as(usize, 1) << @intCast(M31_CIRCLE_LOG_ORDER)) - 1;
const GENERATOR_DOUBLES = initGeneratorDoubles();

fn initGeneratorDoubles() [M31_CIRCLE_LOG_ORDER]CirclePointM31 {
    var out: [M31_CIRCLE_LOG_ORDER]CirclePointM31 = undefined;
    var current = M31_CIRCLE_GEN;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        out[i] = current;
        current = current.double();
    }
    return out;
}

pub const Coset = struct {
    initial_index: CirclePointIndex,
    initial: CirclePointM31,
    step_size: CirclePointIndex,
    step: CirclePointM31,
    half_step: CirclePointM31,
    log_size: u32,

    pub fn eql(lhs: Coset, rhs: Coset) bool {
        return lhs.initial_index.eql(rhs.initial_index) and
            lhs.initial.eql(rhs.initial) and
            lhs.step_size.eql(rhs.step_size) and
            lhs.step.eql(rhs.step) and
            lhs.half_step.eql(rhs.half_step) and
            lhs.log_size == rhs.log_size;
    }

    pub fn new(initial_index: CirclePointIndex, log_size: u32) Coset {
        std.debug.assert(log_size <= M31_CIRCLE_LOG_ORDER);
        const step_size = CirclePointIndex.subgroupGen(log_size);
        const half_step_size = step_size.half();
        return .{
            .initial_index = initial_index,
            .initial = initial_index.toPoint(),
            .step_size = step_size,
            .step = step_size.toPoint(),
            .half_step = half_step_size.toPoint(),
            .log_size = log_size,
        };
    }

    pub fn subgroup(log_size: u32) Coset {
        return new(CirclePointIndex.zero(), log_size);
    }

    pub fn odds(log_size: u32) Coset {
        return new(CirclePointIndex.subgroupGen(log_size + 1), log_size);
    }

    pub fn halfOdds(log_size: u32) Coset {
        return new(CirclePointIndex.subgroupGen(log_size + 2), log_size);
    }

    pub inline fn size(self: Coset) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }

    pub inline fn logSize(self: Coset) u32 {
        return self.log_size;
    }

    pub fn iter(self: Coset) CosetPointIterator {
        return .{
            .cur = self.initial,
            .step = self.step,
            .remaining = self.size(),
        };
    }

    pub fn iterIndices(self: Coset) CosetIndexIterator {
        return .{
            .cur = self.initial_index,
            .step = self.step_size,
            .remaining = self.size(),
        };
    }

    pub fn double(self: Coset) Coset {
        std.debug.assert(self.log_size > 0);
        return .{
            .initial_index = self.initial_index.mul(2),
            .initial = self.initial.double(),
            .step_size = self.step_size.mul(2),
            .step = self.step.double(),
            .half_step = self.step,
            .log_size = self.log_size - 1,
        };
    }

    pub fn repeatedDouble(self: Coset, n_doubles: u32) Coset {
        var out = self;
        var i: u32 = 0;
        while (i < n_doubles) : (i += 1) {
            out = out.double();
        }
        return out;
    }

    pub fn isDoublingOf(self: Coset, other: Coset) bool {
        if (self.log_size > other.log_size) return false;
        return self.eql(other.repeatedDouble(other.log_size - self.log_size));
    }

    pub inline fn initialPoint(self: Coset) CirclePointM31 {
        return self.initial;
    }

    pub fn indexAt(self: Coset, index: usize) CirclePointIndex {
        return self.initial_index.add(self.step_size.mul(index));
    }

    pub fn at(self: Coset, index: usize) CirclePointM31 {
        return self.indexAt(index).toPoint();
    }

    pub fn shift(self: Coset, shift_size: CirclePointIndex) Coset {
        const initial_index = self.initial_index.add(shift_size);
        return .{
            .initial_index = initial_index,
            .initial = initial_index.toPoint(),
            .step_size = self.step_size,
            .step = self.step,
            .half_step = self.half_step,
            .log_size = self.log_size,
        };
    }

    pub fn conjugate(self: Coset) Coset {
        const initial_index = self.initial_index.neg();
        const step_size = self.step_size.neg();
        return .{
            .initial_index = initial_index,
            .initial = initial_index.toPoint(),
            .step_size = step_size,
            .step = step_size.toPoint(),
            .half_step = self.half_step.conjugate(),
            .log_size = self.log_size,
        };
    }
};

pub const CosetPointIterator = struct {
    cur: CirclePointM31,
    step: CirclePointM31,
    remaining: usize,

    pub fn next(self: *CosetPointIterator) ?CirclePointM31 {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        const out = self.cur;
        self.cur = self.cur.add(self.step);
        return out;
    }
};

pub const CosetIndexIterator = struct {
    cur: CirclePointIndex,
    step: CirclePointIndex,
    remaining: usize,

    pub fn next(self: *CosetIndexIterator) ?CirclePointIndex {
        if (self.remaining == 0) return null;
        self.remaining -= 1;
        const out = self.cur;
        self.cur = self.cur.add(self.step);
        return out;
    }
};

fn circleOrder() usize {
    return @as(usize, 1) << @intCast(M31_CIRCLE_LOG_ORDER);
}

test "circle: generator order checks" {
    const p30 = M31_CIRCLE_GEN.repeatedDouble(30);
    const p31 = M31_CIRCLE_GEN.repeatedDouble(31);
    try std.testing.expect(!p30.eql(CirclePointM31.zero()));
    try std.testing.expect(p31.eql(CirclePointM31.zero()));
}

test "circle: log order and double_x consistency" {
    const p = M31_CIRCLE_GEN.mul(17);
    try std.testing.expectEqual(M31_CIRCLE_LOG_ORDER, M31_CIRCLE_GEN.logOrder());
    try std.testing.expect(CirclePointM31.doubleX(p.x).eql(p.double().x));
}

test "circle: generator on-curve and scalar-add law" {
    try std.testing.expect(M31_CIRCLE_GEN.isOnCircle());
    const g = M31_CIRCLE_GEN;
    const a: u128 = 1_234_567;
    const b: u128 = 42_424_242;
    const lhs = g.mul(a).add(g.mul(b));
    const rhs = g.mul((a + b) & (circleOrder() - 1));
    try std.testing.expect(lhs.eql(rhs));
}

test "circle: point index arithmetic" {
    const g = CirclePointIndex.generator();
    try std.testing.expect(g.add(g).eql(CirclePointIndex{ .v = 2 }));
    try std.testing.expect(g.sub(g).eql(CirclePointIndex.zero()));
    try std.testing.expect(g.mul(8).half().eql(CirclePointIndex{ .v = 4 }));
    try std.testing.expect(g.neg().add(g).eql(CirclePointIndex.zero()));
}

test "circle: coset iterator consistency" {
    const coset = Coset.new(.{ .v = 1 }, 3);
    const step = CirclePointIndex.subgroupGen(3);

    var idx_it = coset.iterIndices();
    var i: usize = 0;
    const base = CirclePointIndex{ .v = 1 };
    while (idx_it.next()) |idx| : (i += 1) {
        const expected = base.add(step.mul(i));
        try std.testing.expect(idx.eql(expected));
    }
    try std.testing.expectEqual(@as(usize, 8), i);

    var pt_it = coset.iter();
    i = 0;
    while (pt_it.next()) |pt| : (i += 1) {
        try std.testing.expect(pt.eql(coset.at(i)));
    }
    try std.testing.expectEqual(@as(usize, 8), i);
}

test "circle: half-odds plus conjugate equals odds(parent)" {
    const half = Coset.halfOdds(8);
    const conj = half.conjugate();
    const odds_parent = Coset.odds(9);

    var seen = std.AutoHashMap(usize, void).init(std.testing.allocator);
    defer seen.deinit();

    var it = half.iterIndices();
    while (it.next()) |idx| {
        try seen.put(idx.v, {});
    }

    var conj_it = conj.iterIndices();
    while (conj_it.next()) |idx| {
        try std.testing.expect(!seen.contains(idx.v));
        try seen.put(idx.v, {});
    }

    var odds_seen = std.AutoHashMap(usize, void).init(std.testing.allocator);
    defer odds_seen.deinit();
    var odds_it = odds_parent.iterIndices();
    while (odds_it.next()) |idx| {
        try odds_seen.put(idx.v, {});
    }

    try std.testing.expectEqual(odds_seen.count(), seen.count());
    var seen_it = seen.keyIterator();
    while (seen_it.next()) |k| {
        try std.testing.expect(odds_seen.contains(k.*));
    }
}

test "circle: random secure point is deterministic and on-curve" {
    const Channel = @import("channel/blake2s.zig").Blake2sChannel;
    var channel0 = Channel{};
    var channel1 = Channel{};

    const p0 = randomSecureFieldPoint(&channel0);
    const p1 = randomSecureFieldPoint(&channel1);
    try std.testing.expect(p0.eql(p1));
    try std.testing.expect(p0.isOnCircle());
}

test "circle: coset cached half-step invariants" {
    const coset = Coset.new(.{ .v = 13 }, 8);
    try std.testing.expect(coset.half_step.double().eql(coset.step));

    const shifted = coset.shift(.{ .v = 17 });
    try std.testing.expect(shifted.half_step.eql(coset.half_step));
    try std.testing.expect(shifted.half_step.double().eql(shifted.step));

    const conjugated = coset.conjugate();
    try std.testing.expect(conjugated.half_step.double().eql(conjugated.step));
    try std.testing.expect(conjugated.half_step.eql(coset.half_step.conjugate()));

    const doubled = coset.double();
    try std.testing.expect(doubled.half_step.eql(coset.step));
    try std.testing.expect(doubled.half_step.double().eql(doubled.step));
}
