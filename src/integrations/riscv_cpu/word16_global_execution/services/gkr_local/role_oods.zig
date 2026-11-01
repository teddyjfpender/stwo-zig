//! Same original MAIN -> local terminal residual order as the packed evaluator.
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const MP = @import("../../../logup_gkr/mle_point.zig");
const B = @import("binding.zig");
pub fn evaluate(self: anytype, point: Point, mask: *const Air.MaskValues, acc: *Acc, global_log: u32) !void {
    try self.validate();
    const Component = @typeInfo(@TypeOf(self)).pointer.child;
    const shape = self.mainShape();
    const offsets = self.columnOffsets();
    const samples = E.lane.NativeMasksForField(O){ .values = mask };
    var fixed: [Component.MAX_FIXED]O = undefined;
    var main: [Component.MAX_MAIN]O = undefined;
    var previous: [Component.MAX_MAIN]O = @splat(O.zero());
    for (fixed[0..shape.fixed], 0..) |*v, c| v.* = try E.lane.sample(O, samples, 0, offsets[0] + c, 0, 1);
    for (main[0..shape.main], 0..) |*v, c| {
        const prior = self.previousMain(c);
        v.* = try E.lane.sample(O, samples, 1, offsets[1] + c, 0, if (prior) 2 else 1);
        if (prior) previous[c] = try E.lane.sample(O, samples, 1, offsets[1] + c, 1, 2);
    }
    var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, self.data.instance.row_log) };
    try self.emitMainFor(O, fixed[0..shape.fixed], main[0..shape.main], previous[0..shape.main], &sink);
    var projection = B.ProjectionFor(O){ .challenges = &self.data.challenges, .lane_weights = self.data.lane_weights[0..self.data.lane_count], .terms = self.data.instance.terms };
    self.emitLocalFor(O, fixed[0..shape.fixed], main[0..shape.main], &projection);
    try projection.finish();
    var current: [16]O = undefined;
    var shifted: [16]O = undefined;
    for (&current, &shifted, 0..) |*v, *s, c| {
        v.* = try E.lane.sample(O, samples, 2, self.inter_offset + c, 0, 2);
        s.* = try E.lane.sample(O, samples, 2, self.inter_offset + c, 1, 2);
    }
    const local = try A.geometry.localPointFor(O, point, global_log, self.data.instance.row_log);
    const anchors = try MP.evalAnchorsFor(O, self.data.instance.row_log, local);
    B.emitFor(O, .{
        .eq = E.secureFromCoordinatesForField(O, O, current[0..8].*),
        .eq_next2 = E.secureFromCoordinatesForField(O, O, shifted[0..8].*),
        .prefix = E.secureFromCoordinatesForField(O, O, current[8..16].*),
        .prefix_previous = E.secureFromCoordinatesForField(O, O, shifted[8..16].*),
    }, .{ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(O, &self.data.point, local), .eq0 = self.data.point.eq0, .eq1 = self.data.point.eq1 }, projection.combine(self.data.eta), self.data.target_per_row, &sink);
    if (sink.count != self.nConstraints()) return error.LocalGkrProjectionShape;
}
