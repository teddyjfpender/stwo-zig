//! OP-only authenticated640-byte bridge MAIN: original RAM arithmetic, local GKR
//! OWNER/ranges, and explicit OM31 global RAM/KIO/Wire. Argument geometry is
//! receiver-derived from admitted family, call span and layout, never a flag.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const S = A.crypto.secp256k1.word16_bridge;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Geo = @import("role_geometry.zig");
const Global = @import("global_cpu.zig");
const Manifest = @import("manifest.zig");
const Projection = @import("op_tower_projection.zig");
pub fn mainShapeFor() A.main_only.authority.Shape {
    return Projection.MAIN_SHAPE;
}
pub fn constraintCount() usize {
    return mainShapeFor().constraints + @import("binding.zig").CONSTRAINTS + Global.layout(.{ .tower = {} }).constraints();
}
pub const MAX_DEGREE: u8 = 3;
pub const Component = struct {
    pub const MAX_FIXED = 8;
    pub const MAX_MAIN = 134;
    pub const MAX_INTER = 72;
    data: @import("role.zig").Data,
    span: E.CallSpanFor(O),
    offsets: [2]usize,
    inter_offset: usize,
    shared: Manifest.Shared,
    claims: Global.ClaimsFor(O),
    pub fn mainShape(_: *const @This()) A.main_only.authority.Shape {
        return mainShapeFor();
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return self.offsets;
    }
    pub fn interWidth(self: *const @This()) usize {
        return 16 + Global.layout(self.data.instance.origin).width();
    }
    pub fn previousMain(_: *const @This(), c: usize) bool {
        return S.layout.previousMainFor(.bridge, c);
    }
    pub fn previousInter(self: *const @This(), c: usize) bool {
        return c >= 16 and Global.layout(self.data.instance.origin).previous(c - 16);
    }
    pub fn nConstraints(_: *const @This()) usize {
        return constraintCount();
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.data.instance.row_log + 1;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const @This(), index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return MAX_DEGREE;
    }
    pub fn validate(self: *const @This()) !void {
        if (self.data.instance.origin != .tower or self.data.point.n != self.data.instance.row_log or self.offsets[0] != self.data.instance.fixed_offset or self.offsets[1] != self.data.instance.main_offset) return error.LocalGkrRoleMismatch;
        const log = self.data.instance.row_log;
        const terms: usize = Projection.LOCAL_TERMS;
        if (self.data.instance.terms != terms or self.data.lane_count != @as(usize, 1) << @intCast(try self.data.instance.laneLog())) return error.LocalGkrRoleMismatch;
        _ = try S.types.validateGeometry(Projection.KIND, self.span.calls, self.span.first_id, log);
        try Global.validateClaims(self.data.instance.origin, self.claims);
    }
    pub fn emitMainFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        Projection.emitMainFor(F, fixed, main, previous, self.span, sink);
    }
    pub fn emitLocalFor(_: *const @This(), comptime F: type, fixed: []const F, main: []const F, projection: anytype) void {
        Projection.emitLocalFor(F, fixed, main, projection);
    }
    pub fn emitGlobalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        try Global.emitFor(F, self.data.instance.origin, self.shared, self.claims, fixed, main, current[16..], previous[16..], sink);
    }
    pub fn traceLogDegreeBounds(self: *const @This(), a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
        return Geo.bounds(self, a);
    }
    pub fn maskPoints(self: *const @This(), a: std.mem.Allocator, point: Point, global: u32) !Air.MaskPoints {
        return Geo.masks(self, a, point, global);
    }
    pub fn preprocessedColumnIndices(self: *const @This(), a: std.mem.Allocator) ![]usize {
        return Geo.indices(self, a);
    }
    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const Air.MaskValues, acc: *Acc, global: u32) !void {
        return @import("role_oods.zig").evaluate(self, point, mask, acc, global);
    }
    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const P.Trace, acc: *D.DomainEvaluationAccumulator) !void {
        return @import("role_domain.zig").evaluate(self, trace, acc, null);
    }
    const Adapter = core.air.derive.ForField(O).ComponentAdapter(@This(), P.ComponentProver, P.Trace, D.DomainEvaluationAccumulator);
    pub fn asVerifierComponent(self: *const @This()) Air.Component {
        return Adapter.asVerifierComponent(self);
    }
    pub fn asProverComponent(self: *const @This()) P.ComponentProver {
        return Adapter.asProverComponent(self);
    }
};
