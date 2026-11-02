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
pub const MAX_DEGREE: u8 = 3;
pub fn mainRole(role: @import("../../../word16_execution/geometry.zig").Role) !Main.Role {
    return switch (role) {
        .cpu => .cpu,
        .alu, .alu_tail => .alu,
        .binary, .binary_tail => .binary,
        .shift, .shift_tail => .shift,
        .ls, .ls_tail => .ls,
        .jalr => .jalr,
        .multiplication => .mul,
        .division => .div,
        else => error.LocalGkrRoleMismatch,
    };
}
pub fn constraintCount(role: Main.Role, origin: Frame.Origin) usize {
    return Main.shape(role).constraints + B.CONSTRAINTS + @import("global_cpu.zig").layout(origin).constraints();
}
pub const Data = struct {
    cpu_u8_pairs: bool = false,
    instance: Frame.Instance,
    point: MP.MleEvalPointFor(O),
    lane_weights: [Frame.MAX_LOCAL_TERMS]O,
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
        var planes: [8 * Frame.MAX_LOCAL_TERMS]M = undefined;
        try @import("witness.zig").eqInto(planes[0 .. 8 * lanes], lanes, split.lanes);
        var weights: [Frame.MAX_LOCAL_TERMS]O = undefined;
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
    pub const MAX_FIXED = 3;
    pub const MAX_MAIN = 128;
    pub const MAX_INTER = 32;
    pub fn mainShape(self: *const @This()) Main.Shape {
        return Main.shape(self.main.role());
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return .{ self.main.offsets[0], self.main.offsets[1] };
    }
    pub fn previousMain(self: *const @This(), column: usize) bool {
        return Main.previousMain(self.main.role(), column);
    }
    pub fn emitMainFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        return Main.emitFor(F, self.main.public, fixed, main, previous, sink);
    }
    pub fn emitLocalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
        if (self.main.role() == .cpu) return Fns.cpuModeFor(F, fixed, main, E.scalarFor(F, self.epoch), self.data.cpu_u8_pairs, sink);
        @import("role.zig").emitLocalFor(F, self.main.role(), fixed, main, E.scalarFor(F, self.epoch), sink);
    }
    main: A.main_only.component.Component,
    data: Data,
    inter_offset: usize,
    epoch: u16,
    global: ?struct { shared: @import("manifest.zig").Shared, claims: @import("global_cpu.zig").ClaimsFor(O) } = null,
    pub fn interWidth(self: *const @This()) usize {
        return 16 + @import("global_cpu.zig").layout(self.data.instance.origin).width();
    }
    pub fn previousInter(self: *const @This(), c: usize) bool {
        return c >= 16 and @import("global_cpu.zig").layout(self.data.instance.origin).previous(c - 16);
    }
    pub fn emitGlobalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        const g = self.global orelse {
            if (current.len != 16 or previous.len != 16) return error.MissingWideGlobalRole;
            return;
        };
        try @import("global_cpu.zig").emitFor(F, self.data.instance.origin, g.shared, g.claims, fixed, main, current[16..], previous[16..], sink);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return constraintCount(self.main.role(), self.data.instance.origin);
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.main.log_size + 1;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const @This(), i: usize) !u8 {
        if (i >= self.nConstraints()) return error.InvalidConstraintIndex;
        return MAX_DEGREE;
    }
    pub fn validate(self: *const @This()) !void {
        try self.main.validate();
        if (self.main.role() == .cpu and self.main.log_size > 22) return error.UnqualifiedWideClockGkr;
        const globals = @import("global_cpu.zig");
        const global_width = globals.layout(self.data.instance.origin).width();
        if ((global_width != 0) != (self.global != null)) return error.MissingWideGlobalRole;
        if (self.global) |g| try globals.validateClaims(self.data.instance.origin, g.claims);

        if (self.data.instance.row_log != self.main.log_size or self.data.point.n != self.main.log_size or self.data.instance.origin != .core) return error.LocalGkrRoleMismatch;
        const expected = try mainRole(self.data.instance.origin.core);
        if (expected != self.main.role() or self.data.instance.main_offset != self.main.offsets[1] or self.data.instance.fixed_offset != self.main.offsets[0] or self.data.instance.terms != (if (self.main.role() == .cpu and self.data.cpu_u8_pairs) @as(u32, 14) else @import("roster.zig").terms(self.data.instance.origin.core))) return error.LocalGkrRoleMismatch;
        if (self.data.lane_count != @as(usize, 1) << @intCast(try self.data.instance.laneLog())) return error.LocalGkrRoleMismatch;
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        return @import("role_geometry.zig").bounds(self, a);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        return @import("role_geometry.zig").indices(self, a);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
        return @import("role_geometry.zig").masks(self, a, point, global_log);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc, global_log: u32) !void {
        return @import("role_oods.zig").evaluate(self, point, mask, acc, global_log);
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
