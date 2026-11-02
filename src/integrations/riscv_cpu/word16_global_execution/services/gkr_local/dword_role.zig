//! LS-D64 MAIN39, local7 GKR binding and pure RAM14 share one physical role.
//! Head/tail use identical equations; complete execution admission is external.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const B = A.memory.load_store_dword;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Geo = @import("role_geometry.zig");
const Global = @import("global_cpu.zig");
const Projection = @import("dword_projection.zig");
pub const MAX_DEGREE: u8 = 3;
pub fn mainShapeFor(_: u1) A.main_only.authority.Shape {
    return Projection.MAIN_SHAPE;
}
pub fn constraintCount(_: u1) usize {
    return Projection.MAIN_CONSTRAINTS + @import("binding.zig").CONSTRAINTS + 3;
}
pub const Data = struct {
    instance: @import("frame.zig").Instance,
    point: @import("../../../logup_gkr/mle_point.zig").MleEvalPointFor(O),
    lane_weights: [8]O,
    lane_count: usize,
    challenges: @import("challenges.zig").For(O),
    eta: O,
    target_per_row: O,
    pub fn init(instance: @import("frame.zig").Instance, pending: *const @import("child.zig").Pending, index: usize) !Data {
        if (instance.origin != .dword or instance.terms != Projection.LOCAL_TERMS) return error.LocalGkrRoleMismatch;
        const common = try @import("role.zig").Data.init(instance, pending, index);
        if (common.lane_count != 8) return error.LocalGkrRoleMismatch;
        return .{ .instance = instance, .point = common.point, .lane_weights = common.lane_weights[0..8].*, .lane_count = 8, .challenges = common.challenges, .eta = common.eta, .target_per_row = common.target_per_row };
    }
};
pub const Component = struct {
    pub const MAX_FIXED = 3;
    pub const MAX_MAIN = B.layout.MAIN;
    pub const MAX_INTER = 32; //16 binding +16 pure RAM
    data: Data,
    rows: u32,
    offsets: [2]usize = .{ 0, 0 },
    inter_offset: usize = 0,
    shared: @import("manifest.zig").Shared,
    claims: Global.ClaimsFor(O),
    pub fn mainShape(self: *const @This()) A.main_only.authority.Shape {
        return mainShapeFor(self.data.instance.origin.dword);
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return self.offsets;
    }
    pub fn interWidth(self: *const @This()) usize {
        _ = self;
        return 32;
    }
    pub fn previousMain(self: *const @This(), c: usize) bool {
        _ = self;
        return B.layout.previousMain(c);
    }
    pub fn previousInter(self: *const @This(), c: usize) bool {
        _ = self;
        return c >= 24 and c < 32;
    }
    pub fn nConstraints(self: *const @This()) usize {
        return constraintCount(self.data.instance.origin.dword);
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
        const instance = self.data.instance;
        if (instance.origin != .dword or self.data.point.n != instance.row_log or self.offsets[0] != instance.fixed_offset or self.offsets[1] != instance.main_offset or instance.terms != Projection.LOCAL_TERMS) return error.LocalGkrRoleMismatch;
        const n = try instance.rows();
        if (self.rows >= n or self.data.lane_count != 8) return error.LocalGkrRoleMismatch;
        if (!self.claims.kio.isZero() or !self.claims.wire.isZero()) return error.NonzeroAbsentGlobalGkrClaim;
        for (self.claims.ram.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.NoncanonicalGlobalGkrCoordinate;
    }
    pub fn emitMainFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        try Projection.emitMainFor(F, fixed, main, previous, self.rows, self.rows != 0, sink);
    }
    pub fn emitLocalFor(_: *const @This(), comptime F: type, fixed: []const F, main: []const F, projection: anytype) void {
        _ = fixed;
        Projection.emitLocalFor(F, main, projection);
    }
    pub fn emitGlobalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        if (current.len != 32 or previous.len != 32) return error.InvalidWideGlobalShape;
        var queries = Global.QuerySinkFor(F, @TypeOf(self.shared)){ .shared = &self.shared };
        Projection.emitGlobalFor(F, main, &queries);
        if (queries.ram_count != 2 or queries.other_count != 0) return error.InvalidWideGlobalShape;
        try A.main_only.global_classic.linearPairsFor(F, queries.ram[0..2], queries.ram_weights[0..2], current[16..32], previous[16..32], fixed[1], fixed[2], self.claims.ram, sink);
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
