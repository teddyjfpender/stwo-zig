const std = @import("std");
const circle = @import("../../circle.zig");

const CirclePointM31 = circle.CirclePointM31;
const CirclePointIndex = circle.CirclePointIndex;
const Coset = circle.Coset;

pub const MAX_CIRCLE_DOMAIN_LOG_SIZE: u32 = circle.M31_CIRCLE_LOG_ORDER - 1;
pub const MIN_CIRCLE_DOMAIN_LOG_SIZE: u32 = 1;

pub const SplitResult = struct {
    subdomain: CircleDomain,
    shifts: []CirclePointIndex,

    pub fn deinit(self: *SplitResult, allocator: std.mem.Allocator) void {
        allocator.free(self.shifts);
        self.* = undefined;
    }
};

/// Domain that is a disjoint union of a half-coset and its conjugate.
pub const CircleDomain = struct {
    half_coset: Coset,

    pub inline fn new(half_coset: Coset) CircleDomain {
        return .{ .half_coset = half_coset };
    }

    pub fn iter(self: CircleDomain) CircleDomainIterator {
        return .{
            .first = self.half_coset.iter(),
            .second = self.half_coset.conjugate().iter(),
            .in_second = false,
        };
    }

    pub fn iterIndices(self: CircleDomain) CircleDomainIndexIterator {
        return .{
            .first = self.half_coset.iterIndices(),
            .second = self.half_coset.conjugate().iterIndices(),
            .in_second = false,
        };
    }

    pub inline fn size(self: CircleDomain) usize {
        return @as(usize, 1) << @intCast(self.logSize());
    }

    pub inline fn logSize(self: CircleDomain) u32 {
        return self.half_coset.log_size + 1;
    }

    pub fn at(self: CircleDomain, i: usize) CirclePointM31 {
        return self.indexAt(i).toPoint();
    }

    pub fn indexAt(self: CircleDomain, i: usize) CirclePointIndex {
        const half_size = self.half_coset.size();
        if (i < half_size) return self.half_coset.indexAt(i);
        return self.half_coset.indexAt(i - half_size).neg();
    }

    pub fn isCanonic(self: CircleDomain) bool {
        return self.half_coset.initial_index.mul(4).eql(self.half_coset.step_size);
    }

    pub fn split(self: CircleDomain, allocator: std.mem.Allocator, log_parts: u32) !SplitResult {
        std.debug.assert(log_parts <= self.half_coset.log_size);
        const subdomain = CircleDomain.new(Coset.new(
            self.half_coset.initial_index,
            self.half_coset.log_size - log_parts,
        ));

        const n_shifts: usize = @as(usize, 1) << @intCast(log_parts);
        const shifts = try allocator.alloc(CirclePointIndex, n_shifts);
        for (shifts, 0..) |*s, i| {
            s.* = self.half_coset.step_size.mul(i);
        }
        return .{
            .subdomain = subdomain,
            .shifts = shifts,
        };
    }

    pub fn shift(self: CircleDomain, shift_value: CirclePointIndex) CircleDomain {
        return CircleDomain.new(self.half_coset.shift(shift_value));
    }
};

pub const CircleDomainIterator = struct {
    first: circle.CosetPointIterator,
    second: circle.CosetPointIterator,
    in_second: bool,

    pub fn next(self: *CircleDomainIterator) ?CirclePointM31 {
        if (!self.in_second) {
            if (self.first.next()) |p| return p;
            self.in_second = true;
        }
        return self.second.next();
    }
};

pub const CircleDomainIndexIterator = struct {
    first: circle.CosetIndexIterator,
    second: circle.CosetIndexIterator,
    in_second: bool,

    pub fn next(self: *CircleDomainIndexIterator) ?CirclePointIndex {
        if (!self.in_second) {
            if (self.first.next()) |p| return p;
            self.in_second = true;
        }
        return self.second.next();
    }
};

test "circle domain: iterator matches at(i)" {
    const domain = CircleDomain.new(Coset.new(CirclePointIndex.generator(), 2));
    var it = domain.iter();
    var i: usize = 0;
    while (it.next()) |point| : (i += 1) {
        try std.testing.expect(point.eql(domain.at(i)));
    }
    try std.testing.expectEqual(domain.size(), i);
}

test "circle domain: non-canonic domain detection" {
    const half_coset = Coset.new(CirclePointIndex.generator(), 4);
    const domain = CircleDomain.new(half_coset);
    try std.testing.expect(!domain.isCanonic());
}

test "circle domain: at/index conjugate relation" {
    const CanonicCoset = @import("canonic.zig").CanonicCoset;
    const domain = CanonicCoset.new(7).circleDomain();
    const half = domain.size() / 2;
    var i: usize = 0;
    while (i < half) : (i += 1) {
        try std.testing.expect(domain.indexAt(i).eql(domain.indexAt(i + half).neg()));
        try std.testing.expect(domain.at(i).eql(domain.at(i + half).conjugate()));
    }
}

test "circle domain: split preserves point order via interleaving" {
    const CanonicCoset = @import("canonic.zig").CanonicCoset;
    const domain = CanonicCoset.new(5).circleDomain();
    var split_res = try domain.split(std.testing.allocator, 2);
    defer split_res.deinit(std.testing.allocator);

    var domain_points = std.ArrayList(CirclePointM31).init(std.testing.allocator);
    defer domain_points.deinit();
    var dit = domain.iter();
    while (dit.next()) |p| try domain_points.append(p);

    const n_shifts = split_res.shifts.len;
    const sub_size = split_res.subdomain.size();
    var points_for_shift = try std.testing.allocator.alloc([]CirclePointM31, n_shifts);
    defer std.testing.allocator.free(points_for_shift);
    for (split_res.shifts, 0..) |shift, i| {
        points_for_shift[i] = try std.testing.allocator.alloc(CirclePointM31, sub_size);
        var sit = split_res.subdomain.shift(shift).iter();
        var j: usize = 0;
        while (sit.next()) |p| : (j += 1) {
            points_for_shift[i][j] = p;
        }
    }
    defer for (points_for_shift) |pts| std.testing.allocator.free(pts);

    var extended = std.ArrayList(CirclePointM31).init(std.testing.allocator);
    defer extended.deinit();
    var point_idx: usize = 0;
    while (point_idx < sub_size) : (point_idx += 1) {
        var shift_idx: usize = 0;
        while (shift_idx < n_shifts) : (shift_idx += 1) {
            try extended.append(points_for_shift[shift_idx][point_idx]);
        }
    }

    try std.testing.expectEqual(domain_points.items.len, extended.items.len);
    for (domain_points.items, 0..) |p, i| {
        try std.testing.expect(p.eql(extended.items[i]));
    }
}
