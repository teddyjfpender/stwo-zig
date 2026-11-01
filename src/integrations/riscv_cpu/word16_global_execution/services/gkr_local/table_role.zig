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
pub const Component = struct {
    pub const MAX_FIXED = 34;
    pub const MAX_MAIN = 16;
    kind: Kind,
    data: @import("role.zig").Data,
    inter_offset: usize,
    boundary: ?Boundary = null,
    pub fn mainShape(self: *const @This()) Main.Shape {
        return switch (self.kind) {
            .rom => .{ .fixed = 32, .main = 1, .constraints = 1, .max_degree = 2 },
            .boundary => .{ .fixed = 34, .main = 0, .constraints = 0 },
            .range16, .range8 => .{ .fixed = 3, .main = 1, .constraints = 0 },
            .and_table => .{ .fixed = 5, .main = 1, .constraints = 0 },
            .shift_table => .{ .fixed = 18, .main = 16, .constraints = 0 },
            .selection => .{ .fixed = 6, .main = 2, .constraints = 0 },
        };
    }
    pub fn columnOffsets(self: *const @This()) [2]usize {
        return .{ self.data.instance.fixed_offset, self.data.instance.main_offset };
    }
    pub fn previousMain(_: *const @This(), _: usize) bool {
        return false;
    }
    pub fn emitMainFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, previous: []const F, sink: *E.SinkFor(F)) !void {
        const shape = self.mainShape();
        if (fixed.len != shape.fixed or main.len != shape.main or previous.len != shape.main) return error.InvalidLocalGkrTableShape;
        if (self.kind == .rom) sink.emit(main[0].mul(F.one().sub(fixed[A.word16_execution.layout.rom.valid])));
    }
    pub fn emitLocalFor(self: *const @This(), comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
        switch (self.kind) {
            .rom => Fns.romFor(F, fixed, main, sink),
            .range16 => Fns.scalarTableFor(F, .range16, fixed, main, sink),
            .range8 => Fns.scalarTableFor(F, .range8, fixed, main, sink),
            .and_table => Fns.andTableFor(F, fixed, main, sink),
            .shift_table => Fns.shiftTableFor(F, fixed, main, sink),
            .selection => Fns.selectionTableFor(F, fixed, main, sink),
            .boundary => {
                const boundary = A.word16_cpu.boundary;
                const public = self.boundary.?.value;
                sink.emit(.register, boundary.tupleFor(F, fixed, public, false), F.one().neg());
                sink.emit(.register, boundary.tupleFor(F, fixed, public, true), F.one());
            },
        }
    }
    pub fn nConstraints(self: *const @This()) usize {
        return self.mainShape().constraints + B.CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.data.instance.row_log + 1;
    }
    pub fn compositionLogSplit(_: *const @This()) u32 {
        return 1;
    }
    pub fn constraintDegreeBound(self: *const @This(), index: usize) !u8 {
        if (index >= self.nConstraints()) return error.InvalidConstraintIndex;
        return 3;
    }
    pub fn validate(self: *const @This()) !void {
        const instance = self.data.instance;
        if (instance.origin != .core) return error.LocalGkrRoleMismatch;
        const expected: Kind = switch (instance.origin.core) {
            .rom => .rom,
            .boundary => .boundary,
            .range16 => .range16,
            .range8 => .range8,
            .and_table => .and_table,
            .shift_table => .shift_table,
            .selection => .selection,
            else => return error.LocalGkrRoleMismatch,
        };
        _ = try instance.variables();
        if (expected != self.kind or instance.terms != @import("roster.zig").terms(instance.origin.core) or self.data.point.n != instance.row_log or self.data.lane_count != @as(usize, 1) << @intCast(try instance.laneLog())) return error.LocalGkrRoleMismatch;
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
