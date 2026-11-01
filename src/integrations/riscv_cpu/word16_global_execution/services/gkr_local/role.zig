//! One MAIN span: original arithmetic + local GKR terminal binding. Global
//! RAM/KIO/Wire must join this same role before execution acceptance. This
//! component alone is an authenticated local fragment, never execution proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const Main = A.main_only.authority;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const MP = @import("../../../logup_gkr/mle_point.zig");
const Frame = @import("frame.zig");
const B = @import("binding.zig");
const Fns = @import("fractions.zig");
const Ch = @import("challenges.zig").For(O);
pub const Data = struct {
    instance: Frame.Instance,
    point: MP.MleEvalPointFor(O),
    lane_weights: [128]O,
    lane_count: usize,
    challenges: Ch,
    eta: O,
    target_per_row: O,
    pub fn init(instance: Frame.Instance, pending: *const @import("child.zig").Pending, index: usize) !Data {
        if (index >= pending.artifact.claims_to_verify_by_instance.len) return error.LocalGkrProjectionShape;
        const claims = pending.artifact.claims_to_verify_by_instance[index];
        if (claims.len != 2) return error.LocalGkrProjectionShape;
        const split = try Frame.splitPoint(instance, pending.artifact.ood_point, pending.artifact.n_variables_by_instance[index]);
        const lanes: usize = @as(usize, 1) << @intCast(try instance.laneLog());
        var planes: [8 * 128]M = undefined;
        try @import("witness.zig").eqInto(planes[0 .. 8 * lanes], lanes, split.lanes);
        var weights: [128]O = undefined;
        for (weights[0..lanes], 0..) |*v, i| {
            var c: [8]M = undefined;
            for (&c, 0..) |*x, k| x.* = planes[k * lanes + i];
            v.* = O.fromM31Array(c);
        }
        return .{ .instance = instance, .point = try MP.MleEvalPointFor(O).init(split.rows), .lane_weights = weights, .lane_count = lanes, .challenges = pending.challenges, .eta = pending.eta, .target_per_row = claims[0].add(pending.eta.mul(claims[1])).mulM31(try M.fromCanonical(@intCast(try instance.rows())).inv()) };
    }
};
pub fn emitLocalFor(comptime F: type, role: Main.Role, fixed: []const F, main: []const F, epoch: F, sink: anytype) void {
    switch (role) {
        .cpu => Fns.cpuFor(F, fixed, main, epoch, sink),
        .alu => Fns.aluFor(F, main, sink),
        .binary => Fns.binaryFor(F, main, sink),
        .shift => Fns.shiftFor(F, main, sink),
        .ls => Fns.lsFor(F, main, sink),
        .jalr => Fns.jalrFor(F, main, sink),
        .mul => Fns.multiplicationFor(F, main[0..A.arithmetic.multiplication.layout.MAIN], sink),
        .div => Fns.divisionFor(F, main, sink),
    }
}
pub const Component = struct {
    main: A.main_only.component.Component,
    data: Data,
    inter_offset: usize,
    epoch: u16,
    pub fn nConstraints(self: *const @This()) usize {
        return self.main.nConstraints() + B.CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.main.log_size + 1;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const @This(), i: usize) !u8 {
        if (i >= self.nConstraints()) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn validate(self: *const @This()) !void {
        try self.main.validate();
        if (self.data.instance.row_log != self.main.log_size or self.data.point.n != self.main.log_size or self.data.instance.origin != .core) return error.LocalGkrRoleMismatch;
        const expected: Main.Role = switch (self.data.instance.origin.core) {
            .cpu => .cpu,
            .alu, .alu_tail => .alu,
            .binary, .binary_tail => .binary,
            .shift, .shift_tail => .shift,
            .ls, .ls_tail => .ls,
            .jalr => .jalr,
            .multiplication => .mul,
            .division => .div,
            else => return error.LocalGkrRoleMismatch,
        };
        if (expected != self.main.role() or self.data.instance.main_offset != self.main.offsets[1] or self.data.instance.fixed_offset != self.main.offsets[0] or self.data.instance.terms != @import("roster.zig").terms(self.data.instance.origin.core)) return error.LocalGkrRoleMismatch;
        if (self.data.lane_count != @as(usize, 1) << @intCast(try self.data.instance.laneLog())) return error.LocalGkrRoleMismatch;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        try self.validate();
        var bounds = try self.main.traceLogDegreeBounds(a);
        errdefer bounds.deinitDeep(a);
        const inter = try a.alloc(u32, 16);
        @memset(inter, self.main.log_size);
        a.free(bounds.items[2]);
        bounds.items[2] = inter;
        return bounds;
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        return self.main.preprocessedColumnIndices(a);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        try self.validate();
        var masks = try self.main.maskPoints(a, point, global_log);
        errdefer masks.deinitDeep(a);
        const inter = try a.alloc([]Point, 16);
        var done: usize = 0;
        errdefer {
            for (inter[0..done]) |v| a.free(v);
            a.free(inter);
        }
        const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step.double();
        const next2 = point.add(.{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) });
        for (inter, 0..) |*v, i| {
            v.* = try a.dupe(Point, &.{ point, if (i < 8) next2 else A.geometry.previousPointFor(O, point, global_log) });
            done += 1;
        }
        a.free(masks.items[2]);
        masks.items[2] = inter;
        return masks;
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc, global_log: u32) !void {
        try self.validate();
        try self.main.evaluateConstraintQuotientsAtPoint(point, mask, acc, global_log);
        const shape = Main.shape(self.main.role());
        const samples = E.lane.NativeMasksForField(O){ .values = mask };
        var fixed: [3]O = undefined;
        var main: [128]O = undefined;
        for (fixed[0..shape.fixed], 0..) |*v, c| v.* = try E.lane.sample(O, samples, 0, self.main.offsets[0] + c, 0, 1);
        for (main[0..shape.main], 0..) |*v, c| v.* = try E.lane.sample(O, samples, 1, self.main.offsets[1] + c, 0, if (Main.previousMain(self.main.role(), c)) 2 else 1);
        var projection = B.ProjectionFor(O){ .challenges = &self.data.challenges, .lane_weights = self.data.lane_weights[0..self.data.lane_count], .terms = self.data.instance.terms };
        emitLocalFor(O, self.main.role(), fixed[0..shape.fixed], main[0..shape.main], O.fromBase(M.fromCanonical(self.epoch)), &projection);
        try projection.finish();
        var current: [16]O = undefined;
        var shifted: [16]O = undefined;
        for (&current, &shifted, 0..) |*v, *s, c| {
            v.* = try E.lane.sample(O, samples, 2, self.inter_offset + c, 0, 2);
            s.* = try E.lane.sample(O, samples, 2, self.inter_offset + c, 1, 2);
        }
        const local = try A.geometry.localPointFor(O, point, global_log, self.main.log_size);
        const anchors = try MP.evalAnchorsFor(O, self.main.log_size, local);
        var sink = E.SinkFor(O){ .accumulator = acc, .scale = try A.geometry.denominatorInverseFor(O, point, global_log, self.main.log_size) };
        // Actual values are secure polynomials reconstructed from8 committed
        // base coordinates, not base-field values reinterpreted as secure.
        const eq = E.secureFromCoordinatesForField(O, O, current[0..8].*);
        const next = E.secureFromCoordinatesForField(O, O, shifted[0..8].*);
        const prefix = E.secureFromCoordinatesForField(O, O, current[8..16].*);
        const prior = E.secureFromCoordinatesForField(O, O, shifted[8..16].*);
        B.emitFor(O, .{ .eq = eq, .eq_next2 = next, .prefix = prefix, .prefix_previous = prior }, .{ .first = anchors[0], .second = anchors[1], .carry = try MP.evalCarryQuotientFor(O, &self.data.point, local), .eq0 = self.data.point.eq0, .eq1 = self.data.point.eq1 }, projection.combine(self.data.eta), self.data.target_per_row, &sink);
        if (sink.count != B.CONSTRAINTS) return error.LocalGkrProjectionShape;
    }
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator).asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) P.ComponentProver {
        return core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator).asProverComponent(self);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
        return @import("role_domain.zig").evaluate(self, trace, acc, null);
    }
};
