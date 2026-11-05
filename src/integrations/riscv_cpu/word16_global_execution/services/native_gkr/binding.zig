//! One late binding pair for every native component, shared by all its kinds.
//! The row suffix is common even when local/global lane heights differ.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("roster.zig");
const MP = @import("../../../logup_gkr/mle_point.zig");
pub const MAX_INSTANCES = 128;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;

pub fn ChallengesFor(comptime C: type) type {
    return struct { gamma: C, rho: [MAX_INSTANCES]C };
}
pub const Challenges = ChallengesFor(O);

pub fn boundaryFor(comptime C: type, roster: *const R.Roster, component: usize, claims: []const []const C, challenges: *const ChallengesFor(C)) !C {
    if (roster.instances.len > MAX_INSTANCES or component >= roster.components.len or claims.len != roster.instances.len) return error.NativeGkrBindingShape;
    var target = C.zero();
    for (roster.instances, claims, 0..) |instance, pair, group| {
        if (pair.len != 2) return error.NativeGkrBindingShape;
        if (instance.component == component) target = target.add(challenges.rho[group].mul(pair[0].add(challenges.gamma.mul(pair[1]))));
    }
    return target;
}

/// Boolean MSB-first weights, including padding. Expansion shares prefixes so
/// circuit construction and host work are linear in the lane count.
pub fn eqTableFor(comptime C: type, allocator: std.mem.Allocator, point: []const C) ![]C {
    if (point.len > R.MAX_LANE_LOG) return error.NativeGkrBindingShape;
    const out = try allocator.alloc(C, @as(usize, 1) << @intCast(point.len));
    out[0] = C.one();
    var length: usize = 1;
    for (point) |coordinate| {
        var i = length;
        while (i != 0) {
            i -= 1;
            const value = out[i];
            out[2 * i + 1] = value.mul(coordinate);
            out[2 * i] = value.mul(C.one().sub(coordinate));
        }
        length *= 2;
    }
    return out;
}

pub fn ParametersFor(comptime C: type) type {
    return struct {
        allocator: std.mem.Allocator,
        point: MP.MleEvalPointFor(C),
        weights: [R.KINDS][]C = @splat(&.{}),
        target_per_row: C,
        pub fn deinit(self: *@This()) void {
            for (self.weights) |weights| if (weights.len != 0) self.allocator.free(weights);
            self.* = undefined;
        }
    };
}

pub fn parametersFor(comptime C: type, allocator: std.mem.Allocator, roster: *const R.Roster, component: usize, point: []const C, claims: []const []const C, challenges: *const ChallengesFor(C)) !ParametersFor(C) {
    try roster.validateBounded(MAX_INSTANCES);
    if (component >= roster.components.len or !roster.components[component].present()) return error.NativeGkrBindingShape;
    const row_log = roster.components[component].row_log;
    if (point.len < row_log or point.len != roster.layers()) return error.NativeGkrBindingShape;
    var result = ParametersFor(C){ .allocator = allocator, .point = try MP.MleEvalPointFor(C).init(point[point.len - row_log ..]), .target_per_row = undefined };
    errdefer result.deinit();
    for (roster.instances, 0..) |instance, group| {
        if (instance.component != component) continue;
        const kind = @intFromEnum(instance.kind);
        if (result.weights[kind].len != 0) return error.NativeGkrBindingShape;
        result.weights[kind] = try eqTableFor(C, allocator, point[point.len - instance.variables() .. point.len - row_log]);
        for (result.weights[kind]) |*weight| weight.* = weight.mul(challenges.rho[group]);
    }
    const row_count = M.fromCanonical(@as(u32, 1) << @intCast(row_log));
    result.target_per_row = (try boundaryFor(C, roster, component, claims, challenges)).mul(C.fromBase(try row_count.inv()));
    return result;
}

test "native v2 shared row binding joins different kind lane suffixes" {
    const allocator = std.testing.allocator;
    const specs = [_]R.ComponentSpec{.{ .origin = .{ 0, 13 }, .row_log = 2, .terms = .{ 3, 1, 2, 0 } }};
    var roster = try R.deriveBounded(allocator, &specs, MAX_INSTANCES);
    defer roster.deinit();
    const o = struct { fn scalar(value: u32) O { return O.fromBase(M.fromCanonical(value)); } }.scalar;
    const point = [_]O{ o(2), o(3), o(5), o(7) };
    const local_claim = [_]O{ o(11), o(13) };
    const ram_claim = [_]O{ o(17), o(19) };
    const kio_claim = [_]O{ o(23), o(29) };
    const claims = [_][]const O{ &local_claim, &ram_claim, &kio_claim };
    var challenges = Challenges{ .gamma = o(31), .rho = @splat(O.zero()) };
    challenges.rho[0] = o(37); challenges.rho[1] = o(41); challenges.rho[2] = o(43);
    var parameters = try parametersFor(O, allocator, &roster, 0, &point, &claims, &challenges);
    defer parameters.deinit();
    try std.testing.expectEqualSlices(O, point[2..], parameters.point.slice());
    try std.testing.expectEqual(@as(usize, 4), parameters.weights[0].len);
    try std.testing.expectEqual(@as(usize, 1), parameters.weights[1].len);
    try std.testing.expectEqual(@as(usize, 2), parameters.weights[2].len);
    for (parameters.weights[0..3], challenges.rho[0..3]) |weights, rho| {
        var sum = O.zero(); for (weights) |weight| sum = sum.add(weight);
        try std.testing.expect(sum.eql(rho));
    }
    const expected = try boundaryFor(O, &roster, 0, &claims, &challenges);
    try std.testing.expect(parameters.target_per_row.mulM31(M.fromCanonical(4)).eql(expected));
    var degenerate = point; degenerate[3] = O.one();
    try std.testing.expectError(error.DegenerateEvalPoint, parametersFor(O, allocator, &roster, 0, &degenerate, &claims, &challenges));
}
