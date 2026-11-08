//! Incremental bit-reversed coset walker for lazy quotient evaluation.
//!
//! Lazy quotient execution visits every lifting-domain position in natural
//! order and needs the domain point at the bit-reversed position,
//! `domain.at(bitReverseIndex(position, log_size))`. Computing that point
//! directly costs one circle-group addition per set index bit via
//! `CirclePointIndex.toPoint`.
//!
//! This walker replaces the per-row O(log) recomputation with one group
//! addition per row. Consecutive positions `p - 1 -> p` flip the `c` trailing
//! ones of `p - 1` (with `c = ctz(~(p - 1))`) together with bit `c`. In
//! `n`-bit bit-reversed index space the index delta is therefore
//!
//! ```text
//! delta_br(c) = 2^(n - c) + 2^(n - 1 - c) - 2^n   (mod 2^n)
//! ```
//!
//! Domain points satisfy `at(idx) = s * Q(idx mod half)` with
//! `Q(j) = P(initial + j * step)` and `Q` periodic in `half`, so a step is
//! exactly one group add with the precomputed point
//! `delta_pt[c] = P(delta_br(c) * step)`, wrapped by conjugations when a sign
//! branch changes. The walker uses the identical circle group law, so every
//! emitted point is byte-identical to the direct `domain.at(bitReverseIndex)`
//! call it replaces.

const std = @import("std");
const circle = @import("stwo_core").circle;
const core_utils = @import("stwo_core").utils;

const CircleDomain = @import("stwo_core").poly.circle.domain.CircleDomain;
const CirclePointM31 = circle.CirclePointM31;

/// Maximum supported lifting log size (M31 circle order is 2^31).
pub const MAX_LOG_SIZE: u32 = 31;

pub const BitReversedCosetWalk = struct {
    point: CirclePointM31,
    idx: usize,
    negated: bool,
    position: usize,
    log_size: u32,
    mask: usize,
    half: usize,
    delta_indices: [MAX_LOG_SIZE]usize,
    delta_points: [MAX_LOG_SIZE]CirclePointM31,

    /// Initializes the walk at `start`: the first emitted point equals
    /// `domain.at(bitReverseIndex(start, log_size))`.
    pub fn init(domain: CircleDomain, log_size: u32, start: usize) BitReversedCosetWalk {
        std.debug.assert(log_size >= 1 and log_size <= MAX_LOG_SIZE);
        const size = @as(usize, 1) << @intCast(log_size);
        const half = size / 2;
        var self = BitReversedCosetWalk{
            .point = undefined,
            .idx = core_utils.bitReverseIndex(start, log_size),
            .negated = undefined,
            .position = start,
            .log_size = log_size,
            .mask = size - 1,
            .half = half,
            .delta_indices = undefined,
            .delta_points = undefined,
        };
        self.negated = self.idx >= half;
        self.point = domain.at(self.idx);
        const step = domain.half_coset.step_size;
        for (0..log_size) |c| {
            const hi = @as(usize, 1) << @intCast(log_size - c);
            const lo = @as(usize, 1) << @intCast(log_size - 1 - c);
            const delta = (hi +% lo -% size) & self.mask;
            self.delta_indices[c] = delta;
            self.delta_points[c] = step.mul(delta).toPoint();
        }
        return self;
    }

    /// Returns the current point and advances to the next natural position.
    /// Advancing past the end of the domain leaves the walk unmodified.
    pub inline fn next(self: *BitReversedCosetWalk) CirclePointM31 {
        const result = self.point;
        self.advance();
        return result;
    }

    /// Advances to the next natural position without returning a point.
    pub inline fn advance(self: *BitReversedCosetWalk) void {
        const c: usize = @ctz(~self.position);
        self.position += 1;
        if (c >= self.log_size) return;
        var q = self.point;
        if (self.negated) q = q.conjugate();
        q = q.add(self.delta_points[c]);
        self.idx = (self.idx +% self.delta_indices[c]) & self.mask;
        self.negated = self.idx >= self.half;
        self.point = if (self.negated) q.conjugate() else q;
    }
};

test "bit-reversed walk matches direct domain.at over full domains" {
    const canonic = @import("stwo_core").poly.circle.canonic;
    for ([_]u32{ 1, 2, 3, 5, 11, 15 }) |log_size| {
        const domain = canonic.CanonicCoset.new(log_size).circleDomain();
        const size = @as(usize, 1) << @intCast(log_size);
        var walk = BitReversedCosetWalk.init(domain, log_size, 0);
        for (0..size) |position| {
            const expected = domain.at(core_utils.bitReverseIndex(position, log_size));
            const actual = walk.next();
            try std.testing.expect(expected.x.eql(actual.x));
            try std.testing.expect(expected.y.eql(actual.y));
        }
    }
}

test "bit-reversed walk matches direct domain.at from arbitrary starts" {
    const canonic = @import("stwo_core").poly.circle.canonic;
    for ([_]u32{ 4, 11, 15 }) |log_size| {
        const domain = canonic.CanonicCoset.new(log_size).circleDomain();
        const size = @as(usize, 1) << @intCast(log_size);
        for ([_]usize{ 1, 7, 2731, size / 2 - 1, size / 2, size - 3 }) |start| {
            if (start >= size) continue;
            var walk = BitReversedCosetWalk.init(domain, log_size, start);
            for (start..size) |position| {
                const expected = domain.at(core_utils.bitReverseIndex(position, log_size));
                const actual = walk.next();
                try std.testing.expect(expected.x.eql(actual.x));
                try std.testing.expect(expected.y.eql(actual.y));
            }
        }
    }
}
