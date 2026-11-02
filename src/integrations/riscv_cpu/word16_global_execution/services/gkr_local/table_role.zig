//! Original ROM guard and authenticated table/public-REG local terminals.
//! Fixed polynomials are receiver-owned setup authority. Public register words
//! stay native statement data and are lifted through the shared literal/tuple
//! emitter, so packed evaluation never reinterprets a secure OODS value as M31.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
const P = engine.air.component_prover.ForField(O);
const D = engine.air.accumulation.ForField(O);
const Main = A.main_only.authority;
const B = @import("binding.zig");
const Fns = @import("fractions.zig");
pub const Kind = enum { rom, boundary, range16, range8, and_table, shift_table, selection };
pub const Boundary = struct { value: A.word16_cpu.public.Public, cpu_log: u32 };
pub fn kindForRole(role: @import("../../../word16_execution/geometry.zig").Role) !Kind {
    return std.meta.stringToEnum(Kind, @tagName(role)) orelse error.LocalGkrRoleMismatch;
}
pub fn mainShapeFor(kind: Kind) Main.Shape {
    return switch (kind) {
        .rom => .{ .fixed = 32, .main = 1, .constraints = 1, .max_degree = 2 },
        .boundary => .{ .fixed = 34, .main = 0, .constraints = 0 },
        .range16, .range8 => .{ .fixed = 3, .main = 1, .constraints = 0 },
        .and_table => .{ .fixed = 5, .main = 1, .constraints = 0 },
        .shift_table => .{ .fixed = 18, .main = 16, .constraints = 0 },
        .selection => .{ .fixed = 6, .main = 2, .constraints = 0 },
    };
}
pub fn mainShapeForMode(kind: Kind, pairs: bool) Main.Shape {
    var shape = mainShapeFor(kind);
    if (kind == .and_table and pairs) shape.main = 2;
    return shape;
}
pub fn constraintCount(kind: Kind) usize {
    return mainShapeFor(kind).constraints + B.CONSTRAINTS;
}
pub fn emitMainFor(kind: Kind, comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
    const shape = mainShapeFor(kind);
    if (fixed.len != shape.fixed or main.len != shape.main or previous.len != shape.main) return error.InvalidLocalGkrTableShape;
    if (kind == .rom) sink.emit(main[0].mul(F.one().sub(fixed[A.word16_execution.layout.rom.valid])));
}
pub fn emitLocalFor(kind: Kind, boundary_public: ?Boundary, comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
    switch (kind) {
        .rom => Fns.romFor(F, fixed, main, sink),
        .range16 => Fns.scalarTableFor(F, .range16, fixed, main, sink),
        .range8 => Fns.scalarTableFor(F, .range8, fixed, main, sink),
        .and_table => Fns.andTableFor(F, fixed, main, sink),
        .shift_table => Fns.shiftTableFor(F, fixed, main, sink),
        .selection => Fns.selectionTableFor(F, fixed, main, sink),
        .boundary => {
            const boundary = A.word16_cpu.boundary;
            const public = boundary_public.?.value;
            sink.emit(.register, boundary.tupleFor(F, fixed, public, false), F.one().neg());
            sink.emit(.register, boundary.tupleFor(F, fixed, public, true), F.one());
        },
    }
}
pub const MAX_DEGREE: u8 = 3;
pub const Component = struct {
    pub const MAX_FIXED = 34;
    pub const MAX_MAIN = 16;
    kind: Kind,
    data: @import("role.zig").Data,
    inter_offset: usize,
    boundary: ?Boundary = null,
    pub fn mainShape(self: *const @This()) Main.Shape {
        var shape = mainShapeFor(self.kind);
        if (self.kind == .and_table and self.data.cpu_u8_pairs) shape.main = 2;
        return shape;
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return .{ self.data.instance.fixed_offset, self.data.instance.main_offset };
    }
    pub fn previousMain(_: *const @This(), _: usize) bool {
        return false;
    }
    pub fn emitMainFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        if (self.kind == .and_table and self.data.cpu_u8_pairs) {
            if (fixed.len != 5 or main.len != 2 or previous.len != 2) return error.InvalidLocalGkrTableShape;
            return;
        }
        return @import("table_role.zig").emitMainFor(self.kind, F, fixed, main, previous, sink);
    }
    pub fn emitLocalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
        if (self.kind == .and_table) return Fns.andTableModeFor(F, fixed, main, self.data.cpu_u8_pairs, sink);
        @import("table_role.zig").emitLocalFor(self.kind, self.boundary, F, fixed, main, sink);
    }
    pub fn nConstraints(self: *const @This()) usize {
        return constraintCount(self.kind);
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
        if (instance.origin != .core) return error.LocalGkrRoleMismatch;
        const expected = try kindForRole(instance.origin.core);
        if (expected != self.kind or instance.terms != (if (self.kind == .and_table and self.data.cpu_u8_pairs) @as(u32, 2) else @import("roster.zig").terms(instance.origin.core)) or self.data.point.n != instance.row_log or self.data.lane_count != @as(usize, 1) << @intCast(try instance.laneLog())) return error.LocalGkrRoleMismatch;
        if ((self.kind == .boundary) != (self.boundary != null)) return error.InvalidLocalGkrPublicBoundary;
        if (self.boundary) |p| try p.value.validate(p.cpu_log);
        switch (self.kind) {
            .rom => {},
            .boundary => if (instance.row_log != 5) return error.InvalidLocalGkrTableGeometry,
            .range8 => if (instance.row_log != 8) return error.InvalidLocalGkrTableGeometry,
            else => if (instance.row_log != 16) return error.InvalidLocalGkrTableGeometry,
        }
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
