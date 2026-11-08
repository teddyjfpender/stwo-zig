//! CPU leaf's original MAIN/local-binding/global equation adapter.
//! No acceptance or independent constraint implementation lives here. Public
//! fields, terminal artifact, challenges and claims must all be authenticated
//! by the caller's complete GKR+PCS transcript and public output frame.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
pub const Authority = @import("../../word16_global_execution/services/gkr_local/constraint_authority.zig");
pub const Frame = Authority.Source.Frame;
pub const Slot = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig").Slot;

pub fn LocalFor(comptime F: type) type {
    return struct {
        point: Authority.MlePoint.MleEvalPointFor(F),
        lane_weights: []const F,
        challenges: Authority.Source.Challenges.For(F),
        eta: F,
        target_per_row: F,
    };
}
/// Derive succinct binding data from the checked GKR artifact, never from a
/// producer-supplied marginal or eta override. Small instances use its suffix.
pub fn localFromArtifact(comptime F: type, a: std.mem.Allocator, instance: Frame.Instance, index: usize, artifact: anytype, challenges: Authority.Source.Challenges.For(F), eta: F) !LocalFor(F) {
    const variables = try instance.variables();
    if (index >= artifact.n_variables_by_instance.len or index >= artifact.claims_to_verify_by_instance.len or artifact.n_variables_by_instance[index] != variables or artifact.ood_point.len < variables) return error.LocalGkrPointGeometryMismatch;
    const claims = artifact.claims_to_verify_by_instance[index];
    if (claims.len != 2) return error.LocalGkrProjectionShape;
    const suffix = artifact.ood_point[artifact.ood_point.len - variables ..];
    const lane_point = suffix[instance.row_log..];
    const lanes = @as(usize, 1) << @intCast(try instance.laneLog());
    const weights = try a.alloc(F, lanes);
    for (weights, 0..) |*weight, lane| {
        weight.* = F.one();
        for (lane_point, 0..) |coordinate, bit| {
            const one = ((lane >> @intCast(lane_point.len - 1 - bit)) & 1) != 0;
            weight.* = weight.mul(if (one) coordinate else F.one().sub(coordinate));
        }
    }
    const divisor = core.fields.m31.M31.fromCanonical(@intCast(try instance.rows()));
    const rows_inverse = try divisor.inv();
    return .{ .point = try Authority.MlePoint.MleEvalPointFor(F).init(suffix[0..instance.row_log]), .lane_weights = weights, .challenges = challenges, .eta = eta, .target_per_row = claims[0].add(eta.mul(claims[1])).mul(F.fromBase(rows_inverse)) };
}
pub fn PublicFor(comptime F: type) type {
    return struct {
        main: Authority.PublicFor(E.ConstFor(F)),
        source: [Authority.Source.Public.count]F,
        shared: Authority.SharedFor(E.ConstFor(F)),
        claims: Authority.Global.ClaimsFor(E.ConstFor(F)),
        local: ?LocalFor(F),
    };
}
fn sample(comptime F: type, sampled: []const []const []const F, tree: usize, column: usize, index: usize, count: usize) !F {
    if (tree >= sampled.len or column >= sampled[tree].len or sampled[tree][column].len != count or index >= count) return error.InvalidRv64MaskShape;
    return sampled[tree][column][index];
}
/// Appends one role's scaled residuals in the EXACT native order: MAIN,
/// three terminal binding constraints, then every global physical relation.
pub fn evaluateRole(comptime F: type, a: std.mem.Allocator, descriptor: Authority.Source.Descriptor, slot: Slot, public: PublicFor(F), point: core.circle.CirclePoint(F), global_log: u32, sampled: []const []const []const F, accumulator: anytype) !usize {
    if (!std.meta.eql(descriptor.origin, slot.origin)) return error.LocalGkrRoleMismatch;
    const geometry = try Authority.shape(descriptor);
    const local = Authority.hasLocal(descriptor);
    if (local != (public.local != null) or local != (slot.binding_index != null)) return error.LocalGkrProjectionShape;
    const fixed = try a.alloc(F, geometry.fixed);
    defer a.free(fixed);
    const main = try a.alloc(F, geometry.main);
    defer a.free(main);
    const previous = try a.alloc(F, geometry.main);
    defer a.free(previous);
    for (fixed, 0..) |*v, c| v.* = try sample(F, sampled, 0, slot.fixed_offset + c, 0, 1);
    for (main, previous, 0..) |*v, *p, c| {
        const prior = Authority.previousMain(descriptor, c);
        v.* = try sample(F, sampled, 1, slot.main_offset + c, 0, if (prior) 2 else 1);
        p.* = if (prior) try sample(F, sampled, 1, slot.main_offset + c, 1, 2) else F.zero();
    }
    var sink = E.SinkFor(F){ .accumulator = accumulator, .scale = try A.geometry.denominatorInverseFor(F, point, global_log, slot.log) };
    try Authority.emitMain(descriptor, F, public.main, fixed, main, previous, &sink);
    if (public.local) |binding| {
        if (binding.point.n != slot.log) return error.LocalGkrPointGeometryMismatch;
        var projection = Authority.Binding.ProjectionFor(F){ .challenges = &binding.challenges, .lane_weights = binding.lane_weights, .terms = try descriptor.terms() };
        try descriptor.emit(F, fixed, main, previous, &public.source, &projection);
        try projection.finish();
        var eq: [8]F = undefined;
        var eq_next: [8]F = undefined;
        var prefix: [8]F = undefined;
        var prefix_previous: [8]F = undefined;
        for (0..8) |c| {
            eq[c] = try sample(F, sampled, 2, slot.inter_offset + c, 0, 2);
            eq_next[c] = try sample(F, sampled, 2, slot.inter_offset + c, 1, 2);
            prefix[c] = try sample(F, sampled, 2, slot.inter_offset + 8 + c, 0, 2);
            prefix_previous[c] = try sample(F, sampled, 2, slot.inter_offset + 8 + c, 1, 2);
        }
        const p = try A.geometry.localPointFor(F, point, global_log, slot.log);
        const anchors = try Authority.MlePoint.evalAnchorsFor(F, slot.log, p);
        Authority.Binding.emitFor(F, .{ .eq = E.secureFromCoordinatesForField(F, F, eq), .eq_next2 = E.secureFromCoordinatesForField(F, F, eq_next), .prefix = E.secureFromCoordinatesForField(F, F, prefix), .prefix_previous = E.secureFromCoordinatesForField(F, F, prefix_previous) }, .{ .first = anchors[0], .second = anchors[1], .carry = try Authority.MlePoint.evalCarryQuotientFor(F, &binding.point, p), .eq0 = binding.point.eq0, .eq1 = binding.point.eq1 }, projection.combine(binding.eta), binding.target_per_row, &sink);
    }
    const global = Authority.Global.layout(slot.origin);
    const current = try a.alloc(F, global.width());
    defer a.free(current);
    const prior = try a.alloc(F, global.width());
    defer a.free(prior);
    const global_offset: usize = slot.inter_offset + if (local) @as(usize, 16) else 0;
    for (current, prior, 0..) |*v, *p, c| {
        const shifted = global.previous(c);
        v.* = try sample(F, sampled, 2, global_offset + c, 0, if (shifted) 2 else 1);
        p.* = if (shifted) try sample(F, sampled, 2, global_offset + c, 1, 2) else F.zero();
    }
    try Authority.emitGlobal(descriptor, F, fixed, main, &public.source, public.shared, public.claims, current, prior, &sink);
    const expected = geometry.constraints + (if (local) Authority.Binding.CONSTRAINTS else @as(usize, 0)) + global.constraints();
    if (sink.count != expected) return error.LocalGkrProjectionShape;
    return sink.count;
}
