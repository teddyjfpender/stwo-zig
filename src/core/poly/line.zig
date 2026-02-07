const std = @import("std");
const circle = @import("../circle.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const core_utils = @import("../utils.zig");
const poly_utils = @import("utils.zig");
const circle_domain = @import("circle/domain.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const Coset = circle.Coset;

/// Domain comprising x-coordinates of points in a circle coset.
pub const LineDomain = struct {
    coset_value: Coset,

    pub const Error = error{
        NonUniqueXCoordinates,
    };

    /// Creates a line domain from a coset.
    ///
    /// Failure modes:
    /// - `NonUniqueXCoordinates` when coset points do not have unique x-coordinates.
    pub fn init(c: Coset) Error!LineDomain {
        switch (c.size()) {
            0, 1 => {},
            2 => {
                if (c.initial.x.isZero()) return Error.NonUniqueXCoordinates;
            },
            else => {
                if (c.initial.logOrder() < c.step.logOrder() + 2) {
                    return Error.NonUniqueXCoordinates;
                }
            },
        }
        return .{ .coset_value = c };
    }

    pub fn fromCircleDomain(domain: circle_domain.CircleDomain) LineDomain {
        return .{ .coset_value = domain.half_coset };
    }

    pub fn at(self: LineDomain, index: usize) M31 {
        return self.coset_value.at(index).x;
    }

    pub inline fn size(self: LineDomain) usize {
        return self.coset_value.size();
    }

    pub inline fn logSize(self: LineDomain) u32 {
        return self.coset_value.logSize();
    }

    pub fn iter(self: LineDomain) LineDomainIterator {
        return .{ .inner = self.coset_value.iter() };
    }

    pub fn double(self: LineDomain) LineDomain {
        return .{ .coset_value = self.coset_value.double() };
    }

    pub inline fn coset(self: LineDomain) Coset {
        return self.coset_value;
    }
};

pub const LineDomainIterator = struct {
    inner: circle.CosetPointIterator,

    pub fn next(self: *LineDomainIterator) ?M31 {
        const point = self.inner.next() orelse return null;
        return point.x;
    }
};

/// Univariate polynomial over line-domain FFT basis.
pub const LinePoly = struct {
    coeffs: []QM31,
    log_size: u32,

    pub fn initOwned(coeffs: []QM31) LinePoly {
        std.debug.assert(coeffs.len != 0 and (coeffs.len & (coeffs.len - 1)) == 0);
        return .{
            .coeffs = coeffs,
            .log_size = @intCast(std.math.log2_int(usize, coeffs.len)),
        };
    }

    pub fn deinit(self: *LinePoly, allocator: std.mem.Allocator) void {
        allocator.free(self.coeffs);
        self.* = undefined;
    }

    pub fn evalAtPoint(self: LinePoly, allocator: std.mem.Allocator, x: QM31) !QM31 {
        const doublings = try allocator.alloc(QM31, self.log_size);
        defer allocator.free(doublings);

        var cur = x;
        for (doublings) |*d| {
            d.* = cur;
            cur = circle.CirclePoint(QM31).doubleX(cur);
        }
        return poly_utils.fold(QM31, self.coeffs, doublings);
    }

    pub fn len(self: LinePoly) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }

    pub fn coefficients(self: LinePoly) []const QM31 {
        return self.coeffs;
    }

    pub fn coefficientsMut(self: *LinePoly) []QM31 {
        return self.coeffs;
    }

    pub fn intoOrderedCoefficients(self: *LinePoly) []QM31 {
        core_utils.bitReverse(QM31, self.coeffs);
        return self.coeffs;
    }

    pub fn fromOrderedCoefficients(coeffs: []QM31) LinePoly {
        core_utils.bitReverse(QM31, coeffs);
        return initOwned(coeffs);
    }
};

test "line domain: invalid coset with non-unique x coordinates" {
    const coset = Coset.odds(2);
    try std.testing.expectError(LineDomain.Error.NonUniqueXCoordinates, LineDomain.init(coset));
}

test "line domain: size 2 works" {
    const coset = Coset.subgroup(1);
    _ = try LineDomain.init(coset);
}

test "line domain: size 1 works" {
    const coset = Coset.subgroup(0);
    _ = try LineDomain.init(coset);
}

test "line domain: size matches 2^log_size" {
    const log_size: u32 = 8;
    const coset = Coset.halfOdds(log_size);
    const domain = try LineDomain.init(coset);
    try std.testing.expectEqual(@as(usize, 1) << @intCast(log_size), domain.size());
}

test "line domain: coset getter" {
    const coset = Coset.halfOdds(5);
    const domain = try LineDomain.init(coset);
    try std.testing.expect(domain.coset().eql(coset));
}

test "line domain: double maps x by circle double map" {
    const log_size: u32 = 8;
    const coset = Coset.halfOdds(log_size);
    const domain = try LineDomain.init(coset);
    const doubled = domain.double();

    try std.testing.expectEqual(@as(usize, 1) << @intCast(log_size - 1), doubled.size());
    try std.testing.expect(doubled.at(0).eql(circle.CirclePointM31.doubleX(domain.at(0))));
    try std.testing.expect(doubled.at(1).eql(circle.CirclePointM31.doubleX(domain.at(1))));
}

test "line domain: iterator matches at(i)" {
    const log_size: u32 = 8;
    const domain = try LineDomain.init(Coset.halfOdds(log_size));
    var it = domain.iter();
    var i: usize = 0;
    while (it.next()) |x| : (i += 1) {
        try std.testing.expect(x.eql(domain.at(i)));
    }
    try std.testing.expectEqual(domain.size(), i);
}

test "line poly: len and ordered roundtrip" {
    const alloc = std.testing.allocator;
    const expected = [_]QM31{
        QM31.fromBase(M31.fromCanonical(1)),
        QM31.fromBase(M31.fromCanonical(2)),
        QM31.fromBase(M31.fromCanonical(3)),
        QM31.fromBase(M31.fromCanonical(4)),
    };

    const coeffs = try alloc.alloc(QM31, expected.len);
    @memcpy(coeffs, expected[0..]);

    var poly = LinePoly.fromOrderedCoefficients(coeffs);
    defer poly.deinit(alloc);

    try std.testing.expectEqual(expected.len, poly.len());
    const ordered = poly.intoOrderedCoefficients();
    for (expected, 0..) |e, idx| {
        try std.testing.expect(ordered[idx].eql(e));
    }
}

test "line poly: constant polynomial evaluates to constant" {
    const alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(QM31, 4);
    coeffs[0] = QM31.fromBase(M31.fromCanonical(19));
    coeffs[1] = QM31.zero();
    coeffs[2] = QM31.zero();
    coeffs[3] = QM31.zero();

    var poly = LinePoly.fromOrderedCoefficients(coeffs);
    defer poly.deinit(alloc);

    const point = QM31.fromU32Unchecked(1, 2, 3, 4);
    const value = try poly.evalAtPoint(alloc, point);
    try std.testing.expect(value.eql(QM31.fromBase(M31.fromCanonical(19))));
}
