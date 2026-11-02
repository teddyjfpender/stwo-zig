//! Bulk MAIN, authenticated local terminal binding and global RAM share one
//! physical role. Production v3 admission remains closed until CPU integration.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const B = A.crypto.bulk_memory;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Geo = @import("role_geometry.zig");
const Global = @import("global_cpu.zig");
const Projection = @import("bulk_projection.zig");
pub const MAX_DEGREE: u8 = 3;
pub fn mainShapeFor(kind: B.layout.Kind) A.main_only.authority.Shape {
    return .{ .fixed = B.layout.fixedWidth(kind), .main = B.layout.main(kind), .constraints = B.layout.constraints(kind) - B.layout.slots(kind) - 6 };
}
pub fn constraintCount(kind: B.layout.Kind) usize {
    return mainShapeFor(kind).constraints + @import("binding.zig").CONSTRAINTS + Global.layout(.{ .bulk = kind }).constraints();
}
pub const Component = struct {
    pub const MAX_FIXED = B.layout.JTAB_FIXED;
    pub const MAX_MAIN = B.layout.MAX_MAIN;
    pub const MAX_INTER = 96; //16binding +9 RAM inverse groups +1prefix, each8coords
    data: @import("role.zig").Data,
    rows: u32,
    offsets: [2]usize = .{ 0, 0 },
    inter_offset: usize = 0,
    shared: @import("manifest.zig").Shared,
    claims: Global.ClaimsFor(O),
    pub fn mainShape(self: *const @This()) A.main_only.authority.Shape {
        return mainShapeFor(self.data.instance.origin.bulk);
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return self.offsets;
    }
    pub fn interWidth(self: *const @This()) usize {
        return 16 + Global.layout(self.data.instance.origin).width();
    }
    pub fn previousMain(self: *const @This(), c: usize) bool {
        return B.layout.previousMainFor(self.data.instance.origin.bulk, c);
    }
    pub fn previousInter(self: *const @This(), c: usize) bool {
        return c >= 16 and Global.layout(self.data.instance.origin).previous(c - 16);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return constraintCount(self.data.instance.origin.bulk);
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
        if (instance.origin != .bulk or self.data.point.n != instance.row_log or self.offsets[0] != instance.fixed_offset or self.offsets[1] != instance.main_offset or instance.terms != Projection.localTerms(instance.origin.bulk)) return error.LocalGkrRoleMismatch;
        _ = try instance.variables();
        if (self.data.lane_count != @as(usize, 1) << @intCast(try instance.laneLog())) return error.LocalGkrRoleMismatch;
        _ = try B.types.validateGeometry(instance.origin.bulk, self.rows, instance.row_log);
        if (instance.origin.bulk == .jtab and instance.row_log != B.types.TABLE_LOG) return error.InvalidBulkMemoryGeometry;
        try Global.validateClaims(instance.origin, self.claims);
    }
    pub fn emitMainFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        switch (self.data.instance.origin.bulk) {
            inline else => |kind| B.equations.emitMainFor(F, kind, fixed, main, previous, self.rows, sink),
        }
    }
    pub fn emitLocalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, projection: anytype) void {
        switch (self.data.instance.origin.bulk) {
            inline else => |kind| Projection.emitLocalFor(F, kind, fixed, main, projection),
        }
    }
    pub fn emitGlobalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, current: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        if (Global.layout(self.data.instance.origin).width() != 0) try Global.emitFor(F, self.data.instance.origin, self.shared, self.claims, fixed, main, current[16..], previous[16..], sink);
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
