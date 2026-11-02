//! Packed strict local fractions. A bounded group is one inverse; every role
//! has one joint prefix and one separately closed physical local claim.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const T = @import("truth_fractions.zig");
const Frame = @import("truth_frame.zig");
const Meta = @import("truth_metadata.zig");
const Classic = @import("classic_witness.zig");
fn scale(comptime F: type, value: E.SecureFor(F), weight: anytype) E.SecureFor(F) {
    return if (@TypeOf(weight) == M) value.mulM31(weight) else E.mulBaseFor(F, value, weight);
}
/// One rational numerator authority for native generation and AIR emission.
/// Cross-products are reused; public/base weights never become full secure
/// multiplications merely because the denominator is an extension value.
fn products(comptime F: type, d: [3]E.SecureFor(F), w: anytype, width: usize) struct { d: E.SecureFor(F), n: E.SecureFor(F) } {
    const Secure = E.SecureFor(F);
    return switch (width) {
        1 => .{ .d = d[0], .n = if (@TypeOf(w[0]) == M) Secure.fromBase(w[0]) else E.liftFor(F, w[0]) },
        2 => .{ .d = d[0].mul(d[1]), .n = scale(F, d[1], w[0]).add(scale(F, d[0], w[1])) },
        3 => blk: {
            const p01 = d[0].mul(d[1]);
            const p02 = d[0].mul(d[2]);
            const p12 = d[1].mul(d[2]);
            break :blk .{ .d = p01.mul(d[2]), .n = scale(F, p12, w[0]).add(scale(F, p02, w[1])).add(scale(F, p01, w[2])) };
        },
        else => unreachable,
    };
}
pub fn packing(role: Frame.Role) usize {
    return switch (role) {
        .keccak => 3,
        .product, .linear => 2,
        else => 1,
    };
}
pub fn inverseCount(instance: Frame.Instance) usize {
    return (@as(usize, instance.queries) + packing(instance.role) - 1) / packing(instance.role);
}
pub fn columns(instance: Frame.Instance) usize {
    return 8 * (inverseCount(instance) + 1);
}
pub fn residualCount(instance: Frame.Instance) usize {
    return inverseCount(instance) + 2;
}
pub fn SinkFor(comptime F: type) type {
    return struct {
        const Self = @This();
        const S = E.SecureFor(F);
        challenges: *const T.ChallengesFor(O),
        current: []const F,
        out: *E.SinkFor(F),
        width: usize,
        d: [3]S = @splat(S.one()),
        w: [3]F = @splat(F.zero()),
        fill: usize = 0,
        batches: usize = 0,
        queries: usize = 0,
        contribution: S = S.zero(),
        invalid: bool = false,
        fn flush(self: *Self) void {
            const inverse = E.secureForField(O, F, self.current, 8 * self.batches);
            const value = products(F, self.d, self.w, self.width);
            self.out.emit(inverse.mul(value.d).sub(S.one()));
            self.contribution = self.contribution.add(inverse.mul(value.n));
            self.batches += 1;
            self.fill = 0;
            self.d = @splat(S.one());
            self.w = @splat(F.zero());
        }
        pub fn emit(self: *Self, relation: T.Relation, tuple: anytype, weight: F) void {
            if (8 * (self.batches + 1) >= self.current.len) {
                self.invalid = true;
                return;
            }
            self.d[self.fill] = self.challenges.denominatorFor(F, relation, tuple);
            self.w[self.fill] = weight;
            self.fill += 1;
            self.queries += 1;
            if (self.fill == self.width) self.flush();
        }
        pub fn finish(self: *Self, instance: Frame.Instance, previous: []const F, first: F, last: F, claim: O) !void {
            if (self.fill != 0) self.flush();
            if (self.invalid or self.queries != instance.queries or self.batches != inverseCount(instance) or self.current.len != columns(instance) or previous.len != self.current.len) return error.InvalidTruthClassicQueries;
            const sum = E.secureForField(O, F, self.current, 8 * self.batches);
            const prior = E.secureForField(O, F, previous, 8 * self.batches);
            self.out.emit(sum.sub(prior).add(E.mulBaseFor(F, E.splatFor(F, claim), first)).sub(self.contribution));
            self.out.emit(E.mulBaseFor(F, sum, last));
        }
    };
}
const Fill = struct {
    const Self = @This();
    challenges: *const T.ChallengesFor(O),
    d: []O,
    n: []Classic.Numerator,
    width: usize,
    ds: [3]O = @splat(O.one()),
    ws: [3]M = @splat(M.zero()),
    fill: usize = 0,
    count: usize = 0,
    queries: usize = 0,
    invalid: bool = false,
    fn flush(self: *Self) void {
        if (self.count >= self.d.len) {
            self.invalid = true;
            return;
        }
        const value = products(O, self.ds, self.ws, self.width);
        self.d[self.count] = value.d;
        self.n[self.count] = .{ .secure = value.n };
        self.count += 1;
        self.fill = 0;
        self.ds = @splat(O.one());
        self.ws = @splat(M.zero());
    }
    pub fn emitBase(self: *Self, relation: T.Relation, tuple: anytype, weight: M) void {
        self.ds[self.fill] = self.challenges.denominatorBase(relation, tuple);
        self.ws[self.fill] = weight;
        self.fill += 1;
        self.queries += 1;
        if (self.fill == self.width) self.flush();
    }
};
const Provider = struct {
    /// Validated metadata and challenge inputs are immutable; fill allocates nothing.
    pub const PARALLEL_SAFE = true;
    metadata: *const Meta.Provider,
    challenges: *const T.ChallengesFor(O),
    instance: Frame.Instance,
    pub fn fill(self: @This(), logical: usize, d: []O, n: []Classic.Numerator) !void {
        var sink = Fill{ .challenges = self.challenges, .d = d, .n = n, .width = packing(self.instance.role) };
        try self.metadata.emit(self.instance, logical, &sink);
        if (sink.fill != 0) sink.flush();
        if (sink.invalid or sink.count != d.len or sink.queries != self.instance.queries) return error.InvalidTruthClassicQueries;
    }
};
pub fn generate(a: std.mem.Allocator, metadata: *const Meta.Provider, instance: Frame.Instance, challenges: *const T.ChallengesFor(O), budget: usize) !Classic.Witness {
    return Classic.Witness.initTruth(a, instance.row_log, &.{.{ .inverses = @intCast(inverseCount(instance)) }}, Provider{ .metadata = metadata, .challenges = challenges, .instance = instance }, budget);
}
